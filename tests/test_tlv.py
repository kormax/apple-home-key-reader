from util.tlv import BERTLV


class TestBERTLV:
    def test_encode_simple_tag(self):
        tlv = BERTLV(0x5A, value=b"\x01\x02\x03")
        packed = tlv.pack()
        assert packed == b"\x5a\x03\x01\x02\x03"

    def test_decode_simple_tag(self):
        data = b"\x5a\x03\x01\x02\x03"
        tlv = BERTLV.unpack(data)
        assert tlv.tag.data == b"\x5a"
        assert tlv.length.value == 3
        assert tlv.value == b"\x01\x02\x03"

    def test_encode_decode_roundtrip(self):
        original = BERTLV(0x5A, value=b"\xde\xad\xbe\xef")
        packed = original.pack()
        unpacked = BERTLV.unpack(packed)
        assert unpacked.tag.data == original.tag.data
        assert unpacked.length.value == len(original.value)
        assert unpacked.value == original.value

    def test_decode_empty_value(self):
        data = b"\x5a\x00"
        tlv = BERTLV.unpack(data)
        assert tlv.tag.data == b"\x5a"
        assert tlv.length.value == 0
        assert tlv.value == b""

    def test_encode_empty_value(self):
        tlv = BERTLV(0x5A, value=b"")
        packed = tlv.pack()
        assert packed == b"\x5a\x00"

    def test_decode_constructed_tlv(self):
        # Constructed TLV: 0x70 containing two primitive TLVs
        inner1 = b"\x5a\x02\x01\x02"
        inner2 = b"\x5b\x01\xff"
        data = b"\x70" + bytes([len(inner1 + inner2)]) + inner1 + inner2
        tlv = BERTLV.unpack(data)
        assert tlv.tag.is_constructed
        assert len(tlv.value) == 2
        assert tlv.value[0].tag.data == b"\x5a"
        assert tlv.value[1].tag.data == b"\x5b"

    def test_long_length_encoding(self):
        # Test length > 127 bytes (requires extended length encoding)
        long_value = bytes(range(256)) * 2  # 512 bytes
        tlv = BERTLV(0x5A, value=long_value)
        packed = tlv.pack()
        unpacked = BERTLV.unpack(packed)
        assert unpacked.value == long_value

    def test_unpack_array(self):
        data = b"\x5a\x02\x01\x02\x5b\x03\xaa\xbb\xcc"
        result = BERTLV.unpack_array(data)
        assert len(result) == 2
        assert result[0].tag.data == b"\x5a"
        assert result[0].value == b"\x01\x02"
        assert result[1].tag.data == b"\x5b"
        assert result[1].value == b"\xaa\xbb\xcc"
