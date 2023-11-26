from typing import Tuple

from util.structable import PackableData, Packable, pack


ECP_HEADER = 0x6A

TYPE_ACCESS = 0x02
SUBTYPE_HOMEKEY = 0x06
TCI_HOMEKEY = bytes.fromhex("021100")


class ECP(Packable):
    """Elliptic Curve Point"""

    command: int
    version: int

    @staticmethod
    def home(identifier: bytes, **kwargs):
        assert len(identifier) == 8

        return ECPV2(
            terminal_type=TYPE_ACCESS,
            terminal_subtype=SUBTYPE_HOMEKEY,
            payload=(
                TCI_HOMEKEY,
                # 8 bytes long unique identifier that is the same on all locks in one household
                identifier,
            ),
            **kwargs
        )

    def pack(self):
        raise NotImplementedError()


class ECPV2(ECP):
    """Elliptic Curve Point Version 2"""

    params: Tuple[int, int, int, int, int, int, int]
    unknown: Tuple[int, int, int]

    def __init__(
        self,
        terminal_type: int,
        terminal_subtype: int,
        payload: PackableData = b"",
        flag_1=1,  # Usually set to 1. Will require auth if not set
        flag_2=1,  # Authentication not required flag; Usually set to 1 (to enable express mode)
        flag_3=0,
        flag_4=0,
    ):
        self.terminal_type = terminal_type
        self.terminal_subtype = terminal_subtype
        self.payload = payload
        self.flag_1 = flag_1
        self.flag_2 = flag_2
        self.flag_3 = flag_3
        self.flag_4 = flag_4

    @property
    def version(self):
        return 0x02

    def pack(self):
        payload = pack(self.payload)
        assert len(payload) <= 15
        terminal_info = (
            (self.flag_1 << 7)
            + (self.flag_2 << 6)
            + (self.flag_3 << 5)
            + (self.flag_4 << 4)
            + len(payload)
        )
        terminal = (terminal_info, self.terminal_type, self.terminal_subtype)
        return pack(
            (
                ECP_HEADER,
                self.version,
                terminal,
                payload,
            )
        )
