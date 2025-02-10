/*
 * Copyright 2018 - 2020 Anton Tananaev (anton@traccar.org)
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
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class EgtsProtocolDecoder extends BaseProtocolDecoder {

    private static final Logger logger = LoggerFactory.getLogger(EgtsProtocolDecoder.class);

    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

    public EgtsProtocolDecoder(Protocol protocol) {
        super(protocol);
        // Запускаем периодический опрос устройства каждую минуту
        scheduler.scheduleAtFixedRate(this::pollDeviceState, 1, 1, TimeUnit.MINUTES);
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

    /**
     * Отправляет ответ на запрос устройства.
     *
     * @param channel     Канал для отправки ответа.
     * @param packetType  Тип пакета (например, PT_RESPONSE).
     * @param index       Индекс записи.
     * @param serviceType Тип сервиса.
     * @param type        Тип сообщения (например, MSG_RECORD_RESPONSE).
     * @param content     Данные для отправки.
     */
    private void sendResponse(Channel channel, int packetType, int index, int serviceType, int type, ByteBuf content) {
        if (channel != null) {
            // Создаем данные для ответа
            ByteBuf data = Unpooled.buffer();
            data.writeByte(type); // Тип сообщения (например, MSG_RECORD_RESPONSE)
            data.writeShortLE(content.readableBytes()); // Длина данных
            data.writeBytes(content); // Данные
            content.release();

            // Создаем запись (Record)
            ByteBuf record = Unpooled.buffer();
            if (packetType == PT_RESPONSE) {
                record.writeShortLE(index); // Индекс записи
                record.writeByte(0); // Успешное завершение (0x00)
            }
            record.writeShortLE(data.readableBytes()); // Длина данных
            record.writeShortLE(0); // Флаги записи
            record.writeByte(0); // Флаги (возможно, 1 << 6)
            record.writeByte(serviceType); // Тип сервиса
            record.writeByte(serviceType); // Тип сервиса получателя
            record.writeBytes(data); // Данные
            data.release();

            // Расчет контрольной суммы записи (CRC16)
            int recordChecksum = Checksum.crc16(Checksum.CRC16_CCITT_FALSE, record.nioBuffer());

            // Создаем заголовок пакета (Header)
            ByteBuf response = Unpooled.buffer();
            response.writeByte(1); // Версия протокола (0x01)
            response.writeByte(0); // Идентификатор ключа безопасности (0x00)
            response.writeByte(0); // Флаги (0x00)
            response.writeByte(11); // Длина заголовка (0x0B)
            response.writeByte(0); // Кодировка (0x00)
            response.writeShortLE(record.readableBytes()); // Длина пакета
            response.writeShortLE(packetId++); // Идентификатор пакета
            response.writeByte(packetType); // Тип пакета (PT_RESPONSE)
            response.writeByte(Checksum.crc8(Checksum.CRC8_EGTS, response.nioBuffer())); // Контрольная сумма заголовка (CRC8)
            response.writeBytes(record); // Запись
            record.release();
            response.writeShortLE(recordChecksum); // Контрольная сумма записи (CRC16)

            // Отправляем ответ
            channel.writeAndFlush(new NetworkMessage(response, channel.remoteAddress()));
        }
    }

    /**
     * Отправляет команду EGTS_FLEET_GET_STATE для опроса состояния устройства.
     */
    private void pollDeviceState() {
        // Здесь можно добавить логику для отправки команды EGTS_FLEET_GET_STATE
        // Например, если у вас есть канал устройства, вы можете отправить команду через него
        // Пример:
        // if (channel != null) {
        //     ByteBuf command = Unpooled.buffer();
        //     command.writeByte(MSG_STATE_DATA); // Тип сообщения
        //     sendResponse(channel, PT_APPDATA, 0, SERVICE_COMMANDS, MSG_STATE_DATA, command);
         //}
    }

    @Override
    protected Object decode(Channel channel, SocketAddress remoteAddress, Object msg) throws Exception {
        ByteBuf buf = (ByteBuf) msg;
        List<Position> positions = new LinkedList<>();

        // Чтение заголовка пакета
        short headerLength = buf.getUnsignedByte(buf.readerIndex() + 3);
        int packetId = buf.getUnsignedShort(buf.readerIndex() + 5 + 2);
        short packetType = buf.getUnsignedByte(buf.readerIndex() + 5 + 2 + 2);
        buf.skipBytes(headerLength);

        if (packetType == PT_RESPONSE) {
            return null; // Игнорируем ответы
        }

        long objectId = 0L;
        while (buf.readableBytes() > 2) {
            int length = buf.readUnsignedShortLE();
            int recordIndex = buf.readUnsignedShortLE();
            int recordFlags = buf.readUnsignedByte();

            if (BitUtil.check(recordFlags, 0)) {
                objectId = buf.readUnsignedIntLE();
            }

            if (BitUtil.check(recordFlags, 1)) {
                buf.readUnsignedIntLE(); // event id
            }
            if (BitUtil.check(recordFlags, 2)) {
                buf.readUnsignedIntLE(); // time
            }

            int serviceType = buf.readUnsignedByte();
            buf.readUnsignedByte(); // recipient service type

            int recordEnd = buf.readerIndex() + length;

            Position position = new Position(getProtocolName());
            DeviceSession deviceSession = getDeviceSession(channel, remoteAddress);
            if (deviceSession != null) {
                position.setDeviceId(deviceSession.getDeviceId());
            }

            while (buf.readerIndex() < recordEnd) {
                int type = buf.readUnsignedByte();
                int end = buf.readUnsignedShortLE() + buf.readerIndex();

                switch (type) {
                    case MSG_TERM_IDENTITY:
                        // Обработка идентификации устройства
                        useObjectIdAsDeviceId = false;

                        buf.readUnsignedIntLE(); // object id
                        int flags = buf.readUnsignedByte();

                        if (BitUtil.check(flags, 0)) {
                            buf.readUnsignedShortLE(); // home dispatcher identifier
                        }
                        if (BitUtil.check(flags, 1)) {
                            getDeviceSession(
                                    channel, remoteAddress, buf.readSlice(15).toString(StandardCharsets.US_ASCII).trim());
                        }
                        if (BitUtil.check(flags, 2)) {
                            getDeviceSession(
                                    channel, remoteAddress, buf.readSlice(16).toString(StandardCharsets.US_ASCII).trim());
                        }
                        if (BitUtil.check(flags, 3)) {
                            buf.skipBytes(3); // language identifier
                        }
                        if (BitUtil.check(flags, 5)) {
                            buf.skipBytes(3); // network identifier
                        }
                        if (BitUtil.check(flags, 6)) {
                            buf.readUnsignedShortLE(); // buffer size
                        }
                        if (BitUtil.check(flags, 7)) {
                            getDeviceSession(
                                    channel, remoteAddress, buf.readSlice(15).toString(StandardCharsets.US_ASCII).trim());
                        }

                        ByteBuf response = Unpooled.buffer();
                        response.writeByte(0); // success
                        sendResponse(channel, PT_APPDATA, recordIndex, serviceType, MSG_RESULT_CODE, response);
                        break;

                    case MSG_POS_DATA:
                        // Обработка координат
                        position.setTime(new Date((buf.readUnsignedIntLE() + 1262304000) * 1000)); // since 2010-01-01
                        position.setLatitude(buf.readUnsignedIntLE() * 90.0 / 0xFFFFFFFFL);
                        position.setLongitude(buf.readUnsignedIntLE() * 180.0 / 0xFFFFFFFFL);

                        int posFlags = buf.readUnsignedByte();
                        position.setValid(BitUtil.check(posFlags, 0));
                        if (BitUtil.check(posFlags, 5)) {
                            position.setLatitude(-position.getLatitude());
                        }
                        if (BitUtil.check(posFlags, 6)) {
                            position.setLongitude(-position.getLongitude());
                        }

                        int speed = buf.readUnsignedShortLE();
                        position.setSpeed(UnitsConverter.knotsFromKph(BitUtil.to(speed, 14) * 0.1));
                        position.setCourse(buf.readUnsignedByte() + (BitUtil.check(speed, 15) ? 0x100 : 0));

                        position.set(Position.KEY_ODOMETER, buf.readUnsignedMediumLE() * 100);
                        position.set(Position.KEY_INPUT, buf.readUnsignedByte());
                        position.set(Position.KEY_EVENT, buf.readUnsignedByte());

                        if (BitUtil.check(posFlags, 7)) {
                            position.setAltitude(buf.readMediumLE());
                        }
                        break;

                    case MSG_EXT_POS_DATA:
                        // Обработка дополнительных данных о координатах
                        int extPosFlags = buf.readUnsignedByte();

                        if (BitUtil.check(extPosFlags, 0)) {
                            position.set(Position.KEY_VDOP, buf.readUnsignedShortLE());
                        }
                        if (BitUtil.check(extPosFlags, 1)) {
                            position.set(Position.KEY_HDOP, buf.readUnsignedShortLE());
                        }
                        if (BitUtil.check(extPosFlags, 2)) {
                            position.set(Position.KEY_PDOP, buf.readUnsignedShortLE());
                        }
                        if (BitUtil.check(extPosFlags, 3)) {
                            position.set(Position.KEY_SATELLITES, buf.readUnsignedByte());
                        }
                        break;

                    case MSG_STATE_DATA:
                        // Обработка данных о состоянии устройства
                        int stateFlags = buf.readUnsignedByte();

                        if (BitUtil.check(stateFlags, 0)) {
                            position.set(Position.KEY_BATTERY, buf.readUnsignedByte()); // Уровень заряда батареи
                        }
                        if (BitUtil.check(stateFlags, 1)) {
                            position.set(Position.KEY_INPUT, buf.readUnsignedByte()); // Состояние входов
                        }
                        if (BitUtil.check(stateFlags, 2)) {
                            position.set(Position.KEY_OUTPUT, buf.readUnsignedByte()); // Состояние выходов
                        }
                        if (BitUtil.check(stateFlags, 3)) {
                            position.set("adc1", buf.readUnsignedShortLE()); // Значение АЦП 1
                        }
                        if (BitUtil.check(stateFlags, 4)) {
                            position.set("adc2", buf.readUnsignedShortLE()); // Значение АЦП 2
                        }
                        break;

                    // Обработка других типов сообщений...
                    case MSG_AD_SENSORS_DATA:
                        // Обработка данных аналоговых датчиков
                        int inputMask = buf.readUnsignedByte();

                        position.set(Position.KEY_OUTPUT, buf.readUnsignedByte());

                        int adcMask = buf.readUnsignedByte();

                        for (int i = 0; i < 8; i++) {
                            if (BitUtil.check(inputMask, i)) {
                                buf.readUnsignedByte(); // input
                            }
                        }

                        for (int i = 0; i < 8; i++) {
                            if (BitUtil.check(adcMask, i)) {
                                position.set(Position.PREFIX_ADC + (i + 1), buf.readUnsignedMediumLE());
                            }
                        }
                        break;

                    case MSG_ABS_CNTR_DATA:
                        // Обработка данных счетчиков
                        int cntrFlags = buf.readUnsignedByte();

                        if (BitUtil.check(cntrFlags, 0)) {
                            position.set(Position.KEY_ODOMETER, buf.readUnsignedIntLE()); // Пробег
                        }
                        if (BitUtil.check(cntrFlags, 1)) {
                            position.set("engineHours", buf.readUnsignedIntLE()); // Моточасы
                        }
                        if (BitUtil.check(cntrFlags, 2)) {
                            position.set("fuelConsumption", buf.readUnsignedIntLE()); // Расход топлива
                        }
                        if (BitUtil.check(cntrFlags, 3)) {
                            position.set("fuelLevel", buf.readUnsignedIntLE()); // Уровень топлива
                        }
                        if (BitUtil.check(cntrFlags, 4)) {
                            position.set("fuelTemperature", buf.readUnsignedIntLE()); // Температура топлива
                        }
                        if (BitUtil.check(cntrFlags, 5)) {
                            position.set("fuelPressure", buf.readUnsignedIntLE()); // Давление топлива
                        }
                        if (BitUtil.check(cntrFlags, 6)) {
                            position.set("coolantTemperature", buf.readUnsignedIntLE()); // Температура охлаждающей жидкости
                        }
                        if (BitUtil.check(cntrFlags, 7)) {
                            position.set("batteryVoltage", buf.readUnsignedShortLE()); // Напряжение аккумулятора
                        }
                        break;

                    case MSG_LIQUID_LEVEL_SENSOR:
                        // Обработка данных датчиков уровня жидкости
                        int liquidFlags = buf.readUnsignedByte();
                        int sensorAddress = buf.readUnsignedShortLE();

                        if (BitUtil.check(liquidFlags, 3)) {
                            byte[] rawData = new byte[end - buf.readerIndex()];
                            buf.readBytes(rawData);
                            position.set("liquidRaw_" + sensorAddress, ByteBufUtil.hexDump(rawData));
                        } else {
                            int liquidLevel = buf.readIntLE();
                            position.set("liquidLevel_" + sensorAddress, liquidLevel);
                        }

                        while (buf.readerIndex() < end) {
                            int nextType = buf.readUnsignedByte();
                            int nextEnd = buf.readUnsignedShortLE() + buf.readerIndex();

                            if (nextType == MSG_LIQUID_LEVEL_SENSOR) {
                                int nextFlags = buf.readUnsignedByte();
                                int nextSensorAddress = buf.readUnsignedShortLE();

                                if (BitUtil.check(nextFlags, 3)) {
                                    byte[] nextRawData = new byte[nextEnd - buf.readerIndex()];
                                    buf.readBytes(nextRawData);
                                    position.set("liquidRaw_" + nextSensorAddress, ByteBufUtil.hexDump(nextRawData));
                                } else {
                                    int nextLiquidLevel = buf.readIntLE();
                                    position.set("liquidLevel_" + nextSensorAddress, nextLiquidLevel);
                                }
                            }

                            buf.readerIndex(nextEnd);
                        }
                        break;
                    //end Обработкаи других типов сообщений...

                    default:
                        logger.warn("Unknown packet type: {}", type);
                        break;
                }

                buf.readerIndex(end);
            }

            if (serviceType == SERVICE_TELEDATA && position.getValid()) {
                if (useObjectIdAsDeviceId && objectId != 0L) {
                    deviceSession = getDeviceSession(channel, remoteAddress, String.valueOf(objectId));
                    if (deviceSession != null) {
                        position.setDeviceId(deviceSession.getDeviceId());
                    }
                }
                if (deviceSession != null) {
                    positions.add(position);
                }
            }
        }

        // Отправляем подтверждение на уровне всего пакета
        ByteBuf ackResponse = Unpooled.buffer();
        ackResponse.writeShortLE(packetId); // Индекс пакета
        ackResponse.writeByte(0); // Успешное завершение
        sendResponse(channel, PT_RESPONSE, packetId, SERVICE_TELEDATA, MSG_RECORD_RESPONSE, ackResponse);

        // Отправляем команду EGTS_SR_COMMAND_DATA
        ByteBuf commandResponse = Unpooled.buffer();
        commandResponse.writeByte(0); // Успешное завершение
        sendResponse(channel, PT_APPDATA, packetId, SERVICE_COMMANDS, MSG_RECORD_RESPONSE, commandResponse);

        return positions.isEmpty() ? null : positions;
    }
}


