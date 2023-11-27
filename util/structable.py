import abc
import base64
from collections.abc import Iterable
from enum import Enum
from string import printable
from typing import Collection, ForwardRef, TypeVar, Union

PRINATBLE_BYTES = set(bytes(printable, "ascii"))


Packable = ForwardRef("Packable")
T = TypeVar("T")


PackableBase = Union[bytes, bytearray, memoryview, str, int, Packable]

PackableData = Union[PackableBase, Collection[PackableBase]]
UnpackableData = Union[bytes, bytearray, Collection[int]]


def isprintable(bytestring):
    return all(b in PRINATBLE_BYTES for b in bytestring)


class Packable:
    @abc.abstractmethod
    def pack(self) -> Union[bytearray, bytes]:
        raise NotImplementedError()


class Unpackable:
    @classmethod
    def unpack(cls, data: UnpackableData) -> T:
        raise NotImplementedError()


def int_to_bytes(i: int, *, byteorder="big", signed: bool = False) -> bytes:
    length = max(1, (i.bit_length() + 7 + signed) // 8)
    return i.to_bytes(length, byteorder=byteorder, signed=i < 0 or signed)


def pack(data: PackableData, *, byteorder="big", signed=False) -> bytes:
    if isinstance(data, Packable):
        return data.pack()
    elif isinstance(data, bytes):
        return data
    elif isinstance(data, memoryview):
        return bytes(data)
    elif isinstance(data, str):
        return data.encode()
    elif isinstance(data, bytearray):
        return bytes(data)
    elif isinstance(data, Enum):
        return pack(data.value, byteorder=byteorder, signed=signed)
    elif isinstance(data, Iterable):
        return b"".join(
            pack(element, byteorder=byteorder, signed=signed) for element in data
        )
    elif isinstance(data, int):
        return int_to_bytes(data, byteorder=byteorder, signed=signed)
    raise TypeError(f"Cannot pack data {type(data)} {data}")


def represent(data: PackableData):
    if isinstance(data, Packable):
        return f"{data}"
    elif isinstance(data, (bytes, bytearray)):
        if isprintable(data):
            return f"{data}"
        return f"0x{data.hex()}"
    elif isinstance(data, str):
        return f'"{data}"'
    elif isinstance(data, Iterable):
        return "[" + ", ".join(represent(element) for element in data) + "]"
    elif isinstance(data, Enum):
        return f"{data.name.upper()}({represent(data.value)})"
    elif isinstance(data, int):
        return f"0x{int_to_bytes(data).hex()}"
    raise TypeError(f"Cannot pack data {type(data)} {data}")


def pack_into_base64_string(objects: Union[Collection[PackableData], PackableData]):
    if not isinstance(objects, tuple) and not isinstance(objects, list):
        objects = [objects]
    byte_string = b"".join(
        (obj.pack() if isinstance(obj, Packable) else bytes(obj)) for obj in objects
    )
    return base64.b64encode(byte_string).decode("ASCII")


def unpack_from_base64_string(string: Union[str, bytes]) -> bytes:
    if isinstance(string, str):
        string = string.encode("ASCII")
    return base64.b64decode(string)
