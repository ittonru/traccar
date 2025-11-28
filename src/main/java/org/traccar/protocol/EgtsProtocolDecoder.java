/*
 * Copyright 2018 - 2025 Anton Tananaev (anton@traccar.org)
 * Modified for enhanced EGTS support
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
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import org.traccar.BaseProtocolDecoder;
import org.traccar.session.DeviceSession;
import org.traccar.NetworkMessage;
import org.traccar.Protocol;
import org.traccar.helper.BitUtil;
import org.traccar.helper.Checksum;
import org.traccar.helper.UnitsConverter;
import org.traccar.model.Position;

import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class EgtsProtocolDecoder extends BaseProtocolDecoder {

    private static final Logger logger = LoggerFactory.getLogger(EgtsProtocolDecoder.class);

    // Кэш для мультиплексирования: objectId -> DeviceSession
    private final Map<Long, DeviceSession> objectSessionMap = new ConcurrentHashMap<>();

    public EgtsProtocolDecoder(Protocol protocol) {
        super(protocol);
    }


    private boolean useObjectIdAsDeviceId = true;

    public static final int PT_RESPONSE = 0;
    public static final int PT_APPDATA = 1;
    public static final int PT_SIGNED_APPDATA = 2;

    public static final int SERVICE_AUTH = 1;
    public static final int SERVICE_TELEDATA = 2;
    public static final int SERVICE_COMMANDS = 4;
    public static final int SERVICE_FIRMWARE = 9;
    public static final int SERVICE_ECALL = 10;

    public static final int MSG_RECORD_RESPONSE = 0;
    public static final int MSG_TERM_IDENTITY = 1;
    public static final int MSG_MODULE_DATA = 2;
    public static final int MSG_VEHICLE_DATA = 3;
    public static final int MSG_AUTH_PARAMS = 4;
    public static final int MSG_AUTH_INFO = 5;
    public static final int MSG_SERVICE_INFO = 6;
    public static final int MSG_RESULT_CODE = 7;
    public static final int MSG_POS_DATA = 16;
    public static final int MSG_EXT_POS_DATA = 17;
    public static final int MSG_AD_SENSORS_DATA = 18;
    public static final int MSG_COUNTERS_DATA = 19;
    public static final int MSG_STATE_DATA = 20;
    public static final int MSG_LOOPIN_DATA = 22;
    public static final int MSG_ABS_DIG_SENS_DATA = 23;
    public static final int MSG_ABS_AN_SENS_DATA = 24;
    public static final int MSG_ABS_CNTR_DATA = 25;
    public static final int MSG_ABS_LOOPIN_DATA = 26;
    public static final int MSG_LIQUID_LEVEL_SENSOR = 27;
    public static final int MSG_PASSENGERS_COUNTERS = 28;

    private int packetId;

    private void sendResponse(Channel channel, int packetType, int index, int serviceType, int type, ByteBuf content) {
        if (channel != null) {
            ByteBuf data = Unpooled.buffer();
            data.writeByte(type);
            data.writeShortLE(content.readableBytes());
            data.writeBytes(content);
            content.release();

            ByteBuf record = Unpooled.buffer();
            if (packetType == PT_RESPONSE) {
                record.writeShortLE(index);
                record.writeByte(0); // success
            }
            record.writeShortLE(data.readableBytes());
            record.writeShortLE(0);
            record.writeByte(0);
            record.writeByte(serviceType);
            record.writeByte(serviceType);
            record.writeBytes(data);
            data.release();
            int recordChecksum = Checksum.crc16(Checksum.CRC16_CCITT_FALSE, record.nioBuffer());

            ByteBuf response = Unpooled.buffer();
            response.writeByte(1); // protocol version
            response.writeByte(0); // security key id
            response.writeByte(0); // flags
            response.writeByte(11); // header length
            response.writeByte(0); // encoding
            response.writeShortLE(record.readableBytes());
            response.writeShortLE(packetId++);
            response.writeByte(packetType);
            response.writeByte(Checksum.crc8(Checksum.CRC8_EGTS, response.nioBuffer()));
            response.writeBytes(record);
            record.release();
            response.writeShortLE(recordChecksum);

            channel.writeAndFlush(new NetworkMessage(response, channel.remoteAddress()));
        }
    }

    @Override
    protected Object decode(Channel channel, SocketAddress remoteAddress, Object msg) throws Exception {
        ByteBuf buf = (ByteBuf) msg;
        List<Position> positions = new LinkedList<>();

        short headerLength = buf.getUnsignedByte(buf.readerIndex() + 3);
        int index = buf.getUnsignedShort(buf.readerIndex() + 5 + 2);
        short packetType = buf.getUnsignedByte(buf.readerIndex() + 5 + 2 + 2);
        buf.skipBytes(headerLength);

        if (packetType == PT_RESPONSE) {
            return null;
        }

        long objectId = 0L;

        while (buf.readableBytes() > 2) {
            int length = buf.readUnsignedShortLE();
            int recordIndex = buf.readUnsignedShortLE();
            int recordFlags = buf.readUnsignedByte();

            long currentObjectId = objectId;
            if (BitUtil.check(recordFlags, 0)) {
                currentObjectId = buf.readUnsignedIntLE();
            }
            if (BitUtil.check(recordFlags, 1)) {
                buf.readUnsignedIntLE(); // event id
            }
            if (BitUtil.check(recordFlags, 2)) {
                buf.readUnsignedIntLE(); // time
            }

            int serviceType = buf.readUnsignedByte();
            buf.readUnsignedByte(); // recipient

            int recordEnd = buf.readerIndex() + length;
            Position position = null;

            while (buf.readerIndex() < recordEnd) {
                int type = buf.readUnsignedByte();
                int subRecordLength = buf.readUnsignedShortLE();
                int subRecordEnd = buf.readerIndex() + subRecordLength;

                switch (type) {
                    case MSG_TERM_IDENTITY:
                        useObjectIdAsDeviceId = false;
                        buf.readUnsignedIntLE(); // object id
                        int flags = buf.readUnsignedByte();

                        if (BitUtil.check(flags, 0)) buf.readUnsignedShortLE();
                        if (BitUtil.check(flags, 1)) getDeviceSession(channel, remoteAddress,
                                buf.readSlice(15).toString(StandardCharsets.US_ASCII).trim());
                        if (BitUtil.check(flags, 2)) getDeviceSession(channel, remoteAddress,
                                buf.readSlice(16).toString(StandardCharsets.US_ASCII).trim());
                        if (BitUtil.check(flags, 3)) buf.skipBytes(3);
                        if (BitUtil.check(flags, 5)) buf.skipBytes(3);
                        if (BitUtil.check(flags, 6)) buf.readUnsignedShortLE();
                        if (BitUtil.check(flags, 7)) getDeviceSession(channel, remoteAddress,
                                buf.readSlice(15).toString(StandardCharsets.US_ASCII).trim());

                        ByteBuf response = Unpooled.buffer();
                        response.writeByte(0);
                        sendResponse(channel, PT_APPDATA, 0, serviceType, MSG_RESULT_CODE, response);
                        break;

                    case MSG_POS_DATA:
                        position = new Position(getProtocolName());
                        Date eventTime = new Date((buf.readUnsignedIntLE() + 1262304000L) * 1000);
                        position.setTime(eventTime);

                        double lat = buf.readUnsignedIntLE() * 90.0 / 0xFFFFFFFFL;
                        double lon = buf.readUnsignedIntLE() * 180.0 / 0xFFFFFFFFL;

                        int posFlags = buf.readUnsignedByte();
                        position.setValid(BitUtil.check(posFlags, 0));
                        if (BitUtil.check(posFlags, 5)) lat = -lat;
                        if (BitUtil.check(posFlags, 6)) lon = -lon;
                        position.setLatitude(lat);
                        position.setLongitude(lon);

                        int speedRaw = buf.readUnsignedShortLE();
                        double speedKph = BitUtil.to(speedRaw, 14) * 0.1;
                        position.setSpeed(UnitsConverter.knotsFromKph(speedKph));
                        int course = buf.readUnsignedByte();
                        if (BitUtil.check(speedRaw, 15)) course += 0x100;
                        position.setCourse(course);

                        position.set(Position.KEY_ODOMETER, buf.readUnsignedMediumLE() * 100);
                        position.set(Position.KEY_INPUT, buf.readUnsignedByte());
                        position.set(Position.KEY_EVENT, buf.readUnsignedByte());

                        if (BitUtil.check(posFlags, 7)) {
                            position.setAltitude(buf.readMediumLE());
                        }
                        break;

                    case MSG_EXT_POS_DATA:
                        int extFlags = buf.readUnsignedByte();
                        if (BitUtil.check(extFlags, 0)) position.set(Position.KEY_VDOP, buf.readUnsignedShortLE());
                        if (BitUtil.check(extFlags, 1)) position.set(Position.KEY_HDOP, buf.readUnsignedShortLE());
                        if (BitUtil.check(extFlags, 2)) position.set(Position.KEY_PDOP, buf.readUnsignedShortLE());
                        if (BitUtil.check(extFlags, 3)) position.set(Position.KEY_SATELLITES, buf.readUnsignedByte());
                        break;

                    case MSG_STATE_DATA:
                        int stateFlags = buf.readUnsignedByte();
                        if (position != null) {
                            if (BitUtil.check(stateFlags, 0)) position.set(Position.KEY_BATTERY, buf.readUnsignedByte());
                            if (BitUtil.check(stateFlags, 1)) position.set(Position.KEY_INPUT, buf.readUnsignedByte());
                            if (BitUtil.check(stateFlags, 2)) position.set(Position.KEY_OUTPUT, buf.readUnsignedByte());
                            if (BitUtil.check(stateFlags, 3)) position.set("adc1", buf.readUnsignedShortLE());
                            if (BitUtil.check(stateFlags, 4)) position.set("adc2", buf.readUnsignedShortLE());
                        } else {
                            // Skip data if no position
                            int skipped = 0;
                            if (BitUtil.check(stateFlags, 0)) skipped += 1;
                            if (BitUtil.check(stateFlags, 1)) skipped += 1;
                            if (BitUtil.check(stateFlags, 2)) skipped += 1;
                            if (BitUtil.check(stateFlags, 3)) skipped += 2;
                            if (BitUtil.check(stateFlags, 4)) skipped += 2;
                            buf.skipBytes(skipped);
                        }
                        break;

                    case MSG_AD_SENSORS_DATA:
                        int inputMask = buf.readUnsignedByte();
                        if (position != null) {
                            position.set(Position.KEY_OUTPUT, buf.readUnsignedByte());
                        } else {
                            buf.skipBytes(1);
                        }
                        int adcMask = buf.readUnsignedByte();

                        // Обработка дискретных входов (до 8 шт)
                        for (int i = 0; i < 8; i++) {
                            if (BitUtil.check(inputMask, i)) {
                                int inputValue = buf.readUnsignedByte();
                                if (position != null) {
                                    position.set("io" + (i + 1), inputValue != 0);
                                }
                            }
                        }

                        // Обработка аналоговых датчиков (ADC)
                        for (int i = 0; i < 8; i++) {
                            if (BitUtil.check(adcMask, i)) {
                                if (position != null) {
                                    position.set(Position.PREFIX_ADC + (i + 1), buf.readUnsignedMediumLE());
                                } else {
                                    buf.skipBytes(3);
                                }
                            }
                        }
                        break;

                    case MSG_VEHICLE_DATA:
                        int vFlags = buf.readUnsignedByte();
                        if (BitUtil.check(vFlags, 0)) buf.skipBytes(2); // speed
                        if (BitUtil.check(vFlags, 1)) { // voltage
                            if (position != null) {
                                position.set(Position.KEY_POWER, buf.readUnsignedShortLE() * 0.1);
                            } else {
                                buf.skipBytes(2);
                            }
                        }
                        if (BitUtil.check(vFlags, 2)) { // odometer
                            if (position != null) {
                                position.set(Position.KEY_ODOMETER, buf.readUnsignedIntLE());
                            } else {
                                buf.skipBytes(4);
                            }
                        }
                        break;

                    case MSG_ABS_DIG_SENS_DATA:
                        int digCount = buf.readUnsignedByte();
                        for (int i = 0; i < digCount && buf.readerIndex() < subRecordEnd; i++) {
                            int sensorId = buf.readUnsignedShortLE();
                            int value = buf.readUnsignedByte();
                            if (position != null) {
                                position.set("can.digital." + sensorId, value != 0);
                            }
                        }
                        break;

                    case MSG_ABS_AN_SENS_DATA:
                        int anCount = buf.readUnsignedByte();
                        for (int i = 0; i < anCount && buf.readerIndex() < subRecordEnd; i++) {
                            int sensorId = buf.readUnsignedShortLE();
                            long value = buf.readUnsignedIntLE();
                            if (position != null) {
                                position.set("can.analog." + sensorId, value);
                            }
                        }
                        break;

                    case MSG_ABS_CNTR_DATA:
                        int cntrCount = buf.readUnsignedByte();
                        for (int i = 0; i < cntrCount && buf.readerIndex() < subRecordEnd; i++) {
                            int sensorId = buf.readUnsignedShortLE();
                            long value = buf.readLongLE();
                            if (position != null) {
                                position.set("can.counter." + sensorId, value);
                            }
                        }
                        break;

                    case MSG_LIQUID_LEVEL_SENSOR:
                        int liquidFlags = buf.readUnsignedByte();
                        int address = buf.readUnsignedShortLE();
                        String key = "liquid." + String.format("%04d", address);
                        if (BitUtil.check(liquidFlags, 3)) {
                            if (position != null) {
                                position.set(key + "Raw", ByteBufUtil.hexDump(buf.readSlice(subRecordEnd - buf.readerIndex())));
                            } else {
                                buf.readerIndex(subRecordEnd);
                            }
                        } else {
                            if (position != null) {
                                position.set(key, buf.readUnsignedIntLE());
                            } else {
                                buf.skipBytes(4);
                            }
                        }
                        break;


                    case MSG_AUTH_PARAMS:
                        int authLength = buf.readUnsignedByte();
                        if (authLength > 0 && authLength <= subRecordEnd - buf.readerIndex()) {
                            String authId = buf.readSlice(authLength).toString(StandardCharsets.US_ASCII).trim();
                            DeviceSession authSession = getDeviceSession(channel, remoteAddress, authId);
                            if (authSession != null && currentObjectId != 0L) {
                                objectSessionMap.put(currentObjectId, authSession);
                            }
                        }
                        break;

                    case MSG_AUTH_INFO:
                        int authResult = buf.readUnsignedByte();
                        if (authResult != 0) {
                            logger.warn("EGTS authentication failed: {}", authResult);
                        }
                        break;

                    case MSG_SERVICE_INFO:
                        int serviceInfoLength = buf.readUnsignedByte();
                        if (position != null && serviceInfoLength > 0) {
                            String serviceInfo = buf.readSlice(Math.min(serviceInfoLength, subRecordEnd - buf.readerIndex()))
                                    .toString(StandardCharsets.US_ASCII).trim();
                            position.set("serviceInfo", serviceInfo);
                        } else {
                            buf.skipBytes(serviceInfoLength);
                        }
                        break;

                    case MSG_LOOPIN_DATA:
                        int loopinMask = buf.readUnsignedByte();
                        for (int i = 0; i < 8; i++) {
                            if (BitUtil.check(loopinMask, i)) {
                                if (position != null) {
                                    position.set("loopin" + (i + 1), buf.readUnsignedShortLE());
                                } else {
                                    buf.skipBytes(2);
                                }
                            }
                        }
                        break;

                    case MSG_ABS_LOOPIN_DATA:
                        int loopCount = buf.readUnsignedByte();
                        for (int i = 0; i < loopCount && buf.readerIndex() < subRecordEnd; i++) {
                            int sensorId = buf.readUnsignedShortLE();
                            int value = buf.readUnsignedShortLE();
                            if (position != null) {
                                position.set("loopin.abs." + sensorId, value);
                            }
                        }
                        break;

                    default:
                        logger.warn("Unknown EGTS subrecord type: {}", type);
                        buf.readerIndex(subRecordEnd);
                        continue;
                }

                buf.readerIndex(subRecordEnd);
            }

            if (position != null && position.getValid()) {
                DeviceSession deviceSession = null;
                if (useObjectIdAsDeviceId && currentObjectId != 0L) {
                    deviceSession = getDeviceSession(channel, remoteAddress, String.valueOf(currentObjectId));
                } else {
                    deviceSession = getDeviceSession(channel, remoteAddress);
                }

                if (deviceSession != null) {
                    position.setDeviceId(deviceSession.getDeviceId());
                    positions.add(position);

                    ByteBuf ack = Unpooled.buffer();
                    ack.writeShortLE(recordIndex);
                    ack.writeByte(0);
                    sendResponse(channel, PT_RESPONSE, index, serviceType, MSG_RECORD_RESPONSE, ack);
                }
            }
        }

        return positions.isEmpty() ? null : positions;
    }
}
