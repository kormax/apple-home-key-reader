from enum import Enum, IntEnum
from typing import Any, Union

from util.structable import Packable, Unpackable, pack

#
# Command and response classes were inspired by and based on similar classes from following projects:
# https://github.com/apuigsech/emv-framework
# Documentation regarding the params was taken from:
# https://cardwerk.com/smart-card-standard-iso7816-4-section-6-basic-interindustry-commands/
#


class ISO7816Application(Enum):
    HOME_KEY = bytes.fromhex("A0000008580101")
    HOME_KEY_CONFIGURATION = bytes.fromhex("A0000008580102")


class ISO7816Instruction(IntEnum):
    READ_BINARY = 0xB0
    WRITE_BINARY = 0xD0
    UPDATE_BINARY = 0xD6
    ERASE_BINARY = 0x0E

    READ_RECORD = 0xB2
    WRITE_RECORD = 0xD2
    APPEND_RECORD = 0xE2

    GET_DATA = 0xCA
    PUT_DATA = 0xDA

    SELECT_FILE = 0xA4

    VERIFY = 0x20

    INTERNAL_AUTHENTICATE = 0x88
    EXTERNAL_AUTHENTICATE = 0x82

    GET_CHALLENGE = 0x84

    MANAGE_CHANNEL = 0x70

    GET_RESPONSE = 0xC0


class ISO7816Class(int):
    pass


class ISO7816Command(Packable):
    cla: Union[int, ISO7816Class]
    ins: Union[int, ISO7816Instruction]
    p1: int
    p2: int
    lc: int
    data: bytes
    le: int

    def __init__(self, *, cla=0x00, ins=0x00, p1=0x00, p2=0x00, data=None, le=None):
        super().__init__()
        self.cla = cla
        self.ins = ins
        self.p1 = p1
        self.p2 = p2
        self.data = data if data is not None else b""
        self.le = le

    @staticmethod
    def unpack(data: bytearray):
        cla, ins, p1, p2 = data[:4]
        data_le = data[4:]
        if len(data_le):
            data_length = data_le[0]
            data = data_le[1 : 1 + data_length]
            le = None if len(data_le) == data_length else data_le[-1]
        else:
            data = bytearray()
            le = None
        return ISO7816Command(cla=cla, ins=ins, p1=p1, p2=p2, data=data, le=le)

    @property
    def lc(self):
        return len(pack(self.data))

    def pack(self) -> bytearray:
        force_extended_length = False

        le = (self.le,) if self.le is not None else ()

        if 256 <= self.lc <= 65_535 or force_extended_length:
            lc_data = pack((0x00, self.lc.to_bytes(2, "big"), self.data))
        elif 0 < self.lc < 256:
            lc_data = pack((self.lc, self.data))
        elif self.lc == 0:
            lc_data = ()
        else:
            raise ValueError(
                f"Length of an APDU should be in range [0, 65535], actual = {self.lc}"
            )
        return bytes([self.cla, self.ins, self.p1, self.p2, *lc_data, *le])

    def __repr__(self):
        return (
            "ISO7816Command("
            + f"cla=0x{pack(self.cla).hex()}"
            + f"; ins=0x{pack(self.ins).hex()}"
            + f"; p1=0x{pack(self.p1).hex()}"
            + f"; p2=0x{pack(self.p2).hex()}"
            + (f"; lc=0x{pack(self.lc).hex()}({self.lc})" if self.lc else "")
            + (f"; data={pack(self.data).hex()}" if self.lc else "")
            + (f"; le=0x{pack(self.le).hex()}" if self.le is not None else "")
            + ")"
        )


class ISO7816StatusGroup(IntEnum):
    SUCCESS = 0x90
    OK = 0x91
    OK_MORE_DATA_LEFT = 0x61

    WARNING_AND_MEMORY_WAS_CHANGED = 0x62
    WARNING_AND_MEMORY_WAS_NOT_CHANGED = 0x63

    ERROR_COMMAND_NOT_EXECUTED_MEMORY_NOT_CHANGED = 0x64
    ERROR_COMMAND_NOT_EXECUTED_MEMORY_CHANGED = 0x65
    ERROR_COMMAND_NOT_EXECUTED_DUE_TO_SECURITY_SETTINGS = 0x66

    ERROR_FORMAT_WRONG_COMMAND_LENGTH = 0x67
    ERROR_LOGIC_CHANNEL_UNSUPPORTED = 0x68
    ERROR_COMMAND_NOT_ALLOWED = 0x69
    ERROR_WRONG_PARAMETERS_V1 = 0x6A
    ERROR_WRONG_PARAMETERS_V2 = 0x6B
    ERROR_WRONG_LE = 0x6C
    ERROR_WRONG_INS = 0x6D
    ERROR_UNKNOWN_CLA = 0x6E
    ERROR_UNKNOWN = 0x6F


class ISO7816Response(Unpackable, Packable):
    sw1: Union[int, ISO7816StatusGroup]
    sw2: int
    data: bytearray

    def __init__(self, *, sw1=0x00, sw2=0x00, data=None):
        try:
            self.sw1 = ISO7816StatusGroup(sw1)
        except (TypeError, ValueError):
            self.sw1 = sw1
        self.sw2 = sw2
        self.data = data or bytearray()

    @classmethod
    def unpack(cls, data: Union[bytes, bytearray]) -> "ISO7816Response":
        *data, sw1, sw2 = data
        return ISO7816Response(sw1=sw1, sw2=sw2, data=bytearray(data))

    @property
    def sw(self):
        return self.sw1, self.sw2

    def pack(self):
        return pack((self.data, self.sw1, self.sw2))

    def __repr__(self):
        return (
            "ISO7816Response("
            + f"sw1=0x{hex(self.sw1)[2:].zfill(2)}"
            + f"; sw2=0x{hex(self.sw2)[2:].zfill(2)}"
            + (f"; data={self.data.hex()}({len(self.data)})" if len(self.data) else "")
            + ")"
        )


class ISO7816:
    @classmethod
    def select_file(cls, data: bytes, cla=0x00, p1=0x00, p2=0x00, le=0x00):
        return ISO7816Command(
            cla=cla,
            ins=ISO7816Instruction.SELECT_FILE,
            p1=p1,
            p2=p2,
            data=data,
            le=le,
        )

    @classmethod
    def select_aid(
        cls, aid: Union[bytes, ISO7816Application], p1=0x04, p2=0x00, le=0x00
    ):
        return cls.select_file(data=aid, p1=p1, p2=p2, le=0x00)


class ISO7816Tag:
    def __init__(self, implementation: Any) -> None:
        self._implementation = implementation

    def transceive(self, data: Union[bytes, ISO7816Command]) -> ISO7816Response:
        return ISO7816Response.unpack(
            self._implementation.transceive(
                bytes(data.pack()) if isinstance(data, ISO7816Command) else bytes(data)
            )
        )
