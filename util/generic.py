def get_tlv_tag(tlv_array, tag_value):
    try:
        return next(tlv_ for tlv_ in tlv_array if tlv_.tag.data[0] == tag_value).value
    except StopIteration:
        return None


def chunked(source, size):
    for i in range(0, len(source), size):
        yield source[i : i + size]


def int_to_bytes(value, byteorder="big"):
    i = 1
    while True:
        try:
            return value.to_bytes(i, byteorder=byteorder)
        except OverflowError:
            i += 1


def bits(data):
    if isinstance(data, int):
        data = int_to_bytes(data)
    return [
        int(bit) for byte in data for bit in ("{:0>{w}}".format(bin(byte)[2:], w=8))
    ]
