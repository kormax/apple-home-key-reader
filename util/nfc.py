def crc16a(data):
    w_crc = 0x6363
    for byte in data:
        byte = byte ^ (w_crc & 0x00FF)
        byte = (byte ^ (byte << 4)) & 0xFF
        w_crc = ((w_crc >> 8) ^ (byte << 8) ^ (byte << 3) ^ (byte >> 4)) & 0xFFFF
    return bytearray([w_crc & 0xFF, (w_crc >> 8) & 0xFF])


def with_crc16(data):
    return bytes([*data, *crc16a(data)])


with_crc16a = with_crc16
