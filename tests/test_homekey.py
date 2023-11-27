import os

import pytest

from util.structable import pack
from util.tlv import BERTLV as TLV
from util.iso7816 import ISO7816Response, ISO7816Tag
from homekey import read_homekey, ProtocolError


class FakeTag:
    def __init__(self, generator):
        self.generator = generator

    def transceive(self, _):
        return pack(next(self.generator))


# Three basic test for now, should/will be expanded soon with FAST/STANDARD/ATTESTATION flows
class TestHomekey:
    @pytest.fixture()
    def read_homekey_params(self):
        return {
            "reader_private_key": None,
            "reader_identifier": os.urandom(16),
            "issuers": [],
        }

    @pytest.fixture()
    def endpoint_with_error_status_on_select(self):
        def generator():
            yield ISO7816Response(sw1=0x6A, sw2=0x00)

        return ISO7816Tag(FakeTag(generator()))

    def test_read_fails_on_select_error_status(
        self, endpoint_with_error_status_on_select, read_homekey_params
    ):
        with pytest.raises(ProtocolError):
            _ = read_homekey(
                tag=endpoint_with_error_status_on_select, **read_homekey_params
            )

    @pytest.fixture()
    def endpoint_with_wrong_response_on_select(self):
        def generator():
            yield ISO7816Response(sw1=0x90, sw2=0x00, data=TLV(0x13, value=0x37))

        return ISO7816Tag(FakeTag(generator()))

    def test_read_fails_on_wrong_select_response(
        self, endpoint_with_wrong_response_on_select, read_homekey_params
    ):
        with pytest.raises(ProtocolError):
            _ = read_homekey(
                tag=endpoint_with_wrong_response_on_select, **read_homekey_params
            )

    @pytest.fixture()
    def endpoint_without_v2_support_on_select(self):
        def generator():
            yield ISO7816Response(
                sw1=0x90, sw2=0x00, data=TLV(0x5C, value=bytes.fromhex("0100"))
            )

        return ISO7816Tag(FakeTag(generator()))

    def test_read_fails_on_v2_unsupported(
        self, endpoint_without_v2_support_on_select, read_homekey_params
    ):
        with pytest.raises(ProtocolError):
            _ = read_homekey(
                tag=endpoint_without_v2_support_on_select, **read_homekey_params
            )
