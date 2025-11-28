/*
 * Copyright 2020 - 2025 Anton Tananaev (anton@traccar.org)
 * Copyright 2017 Ivan Muratov (binakot@gmail.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.traccar.protocol;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import org.traccar.BaseProtocolDecoder;
import org.traccar.session.DeviceSession;
import org.traccar.NetworkMessage;
import org.traccar.Protocol;
import org.traccar.helper.Checksum;
import org.traccar.model.Position;

import java.net.SocketAddress;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

public class ArnaviBinaryProtocolDecoder extends BaseProtocolDecoder {

    private static final byte HEADER_START_SIGN = (byte) 0xff;
    private static final byte HEADER_VERSION_1 = 0x22;
    private static final byte HEADER_VERSION_2 = 0x23;

    private static final byte RECORD_PING = 0x00;
    private static final byte RECORD_DATA = 0x01;
    private static final byte RECORD_TEXT = 0x03;
    private static final byte RECORD_FILE = 0x04;
    private static final byte RECORD_BINARY = 0x06;

    // Tag definitions from official protocol sheet
    private static final byte TAG_VOLTAGE = 1;
    private static final byte TAG_LATITUDE = 3;
    private static final byte TAG_LONGITUDE = 4;
    private static final byte TAG_COORD_PARAMS = 5;
    private static final byte TAG_INPUT = 6;
    private static final byte TAG_CAN_FUEL_LEVEL = 55;   // % * 10
    private static final byte TAG_CAN_FUEL_LITERS = 56;  // L * 10
    private static final byte TAG_CAN_RPM = 57;          // RPM
    private static final byte TAG_LLS_1 = 71;
    private static final byte TAG_LLS_2 = 72;

    public ArnaviBinaryProtocolDecoder(Protocol protocol) {
        super(protocol);
    }

    private void sendResponse(Channel channel, byte version, int index) {
        if (channel != null) {
            ByteBuf response = Unpooled.buffer();
            response.writeByte(0x7b);
            if (version == HEADER_VERSION_1) {
                response.writeByte(0x00);
                response.writeByte((byte) index);
            } else if (version == HEADER_VERSION_2) {
                response.writeByte(0x04);
                response.writeByte(0x00);
                ByteBuf timeBuf = Unpooled.buffer(4);
                timeBuf.writeIntLE((int) (System.currentTimeMillis() / 1000));
                response.writeByte(Checksum.modulo256(timeBuf.nioBuffer()));
                response.writeBytes(timeBuf);
                timeBuf.release();
            }
            response.writeByte(0x7d);
            channel.writeAndFlush(new NetworkMessage(response, channel.remoteAddress()));
        }
    }

    private Position decodePosition(DeviceSession deviceSession, ByteBuf buf, int length, Date time) {
        final Position position = new Position();
        position.setProtocol(getProtocolName());
        position.setDeviceId(deviceSession.getDeviceId());
        position.setTime(time);

        int readBytes = 0;
        while (readBytes < length && buf.readableBytes() > 0) {
            short tag = buf.readUnsignedByte();
            int tagDataSize = 0;

            switch (tag) {
                case TAG_VOLTAGE: {
                    int batteryVoltage = buf.readUnsignedShortLE();  // mV
                    int externalVoltage = buf.readUnsignedShortLE(); // mV

                    position.set(Position.KEY_POWER, externalVoltage / 1000.0);

                    if (batteryVoltage == 0x0000) {
                        position.set("batteryNotConnected", true);
                    } else if (batteryVoltage == 0xFFFF) {
                        position.set("batteryError", true);
                    } else {
                        position.set(Position.KEY_BATTERY, batteryVoltage / 1000.0);
                    }
                    tagDataSize = 4;
                    break;
                }

                case TAG_LATITUDE:
                    position.setLatitude(buf.readFloatLE());
                    position.setValid(true);
                    tagDataSize = 4;
                    break;

                case TAG_LONGITUDE:
                    position.setLongitude(buf.readFloatLE());
                    position.setValid(true);
                    tagDataSize = 4;
                    break;

                case TAG_COORD_PARAMS:
                    position.setCourse(buf.readUnsignedByte() * 2);
                    position.setAltitude(buf.readUnsignedByte() * 10);
                    byte satellites = buf.readByte();
                    position.set(Position.KEY_SATELLITES, (satellites & 0x0F) + ((satellites >> 4) & 0x0F));
                    position.setSpeed(buf.readUnsignedByte());
                    tagDataSize = 4;
                    break;

                case TAG_INPUT: {
                    if (buf.readableBytes() < 3) {
                        tagDataSize = buf.readableBytes();
                        buf.skipBytes(tagDataSize);
                        break;
                    }
                    int mode = buf.readUnsignedByte();
                    int inputNumber = buf.readUnsignedByte();
                    int value = buf.readUnsignedShortLE();

                    switch (mode) {
                        case 0x01: {
                            // Побитовое отображение (bit 0 to bit 15)
                            for (int bit = 0; bit < 16; bit++) {
                                position.set("pin_bit" + bit, (value & (1 << bit)) != 0);
                            }
                            // Виртуальные датчики для удобства и совместимости
                            position.set("ignition", (value & 0x01) != 0);
                            position.set("callButton", (value & 0x02) != 0);
                            break;
                        }
                        case 0x06:
                            position.set("input" + inputNumber + "_pulses", value);
                            break;
                        case 0x07:
                            position.set("input" + inputNumber + "_frequency", value);
                            break;
                        case 0x08:
                            position.set("input" + inputNumber + "_analog", value);
                            break;
                        default:
                            position.set("input" + inputNumber + "_unknownMode" + mode, value);
                            break;
                    }
                    tagDataSize = 4;
                    break;
                }

                case TAG_LLS_1:
                case TAG_LLS_2: {
                    String sensorName = (tag == TAG_LLS_1) ? "lls1" : "lls2";
                    int levelRaw = buf.readUnsignedShortLE();
                    short tempRaw = buf.readShortLE();
                    position.set(sensorName + "_level", levelRaw / 10.0);
                    position.set(sensorName + "_temp", tempRaw / 10.0);
                    tagDataSize = 4;
                    break;
                }

                // CAN data — 2 bytes each
                case TAG_CAN_FUEL_LEVEL: {
                    int value = buf.readUnsignedShortLE(); // % * 10
                    position.set("can_fuel_level", value / 10.0);
                    tagDataSize = 2;
                    break;
                }

                case TAG_CAN_FUEL_LITERS: {
                    int value = buf.readUnsignedShortLE(); // liters * 10
                    position.set("can_fuel_liters", value / 10.0);
                    tagDataSize = 2;
                    break;
                }

                case TAG_CAN_RPM: {
                    int rpm = buf.readUnsignedShortLE(); // RPM
                    position.set("can_rpm", rpm);
                    tagDataSize = 2;
                    break;
                }

                default:
                    // Skip 4 bytes for unknown tags (common case)
                    tagDataSize = Math.min(4, buf.readableBytes());
                    buf.skipBytes(tagDataSize);
                    break;
            }

            readBytes += 1 + tagDataSize;
        }

        return position;
    }

    @Override
    protected Object decode(Channel channel, SocketAddress remoteAddress, Object msg) throws Exception {
        ByteBuf buf = (ByteBuf) msg;

        byte startSign = buf.readByte();

        if (startSign == HEADER_START_SIGN) {
            byte version = buf.readByte();
            String imei = String.valueOf(buf.readLongLE());
            DeviceSession deviceSession = getDeviceSession(channel, remoteAddress, imei);

            if (deviceSession != null) {
                sendResponse(channel, version, 0);
            }
            return null;
        }

        DeviceSession deviceSession = getDeviceSession(channel, remoteAddress);
        if (deviceSession == null) {
            return null;
        }

        List<Position> positions = new LinkedList<>();
        int index = buf.readUnsignedByte();
        byte recordType = buf.readByte();

        while (buf.readableBytes() > 0) {
            switch (recordType) {
                case RECORD_PING, RECORD_DATA, RECORD_TEXT, RECORD_FILE, RECORD_BINARY -> {
                    int length = buf.readUnsignedShortLE();
                    Date time = new Date(buf.readUnsignedIntLE() * 1000L);

                    if (recordType == RECORD_DATA) {
                        positions.add(decodePosition(deviceSession, buf, length, time));
                    } else {
                        buf.readBytes(length);
                    }

                    buf.readUnsignedByte(); // checksum
                }
                default -> {
                    return null;
                }
            }

            if (buf.readableBytes() > 0) {
                recordType = buf.readByte();
            } else {
                break;
            }
        }

        sendResponse(channel, HEADER_VERSION_1, index);
        return positions;
    }
}
