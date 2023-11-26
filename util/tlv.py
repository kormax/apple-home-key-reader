from enum import Enum, IntEnum
from typing import Collection, List, Union

from util.generic import int_to_bytes
from util.structable import PackableData, Packable, Unpackable, pack, represent


def try_cast_type(value: bytes, type):
    if isinstance(value, Packable):
        value = value.pack()
    if (
        not isinstance(value, memoryview)
        and not isinstance(value, bytes)
        and not isinstance(value, bytearray)
    ):
        return value

    try:
        if issubclass(type, IntEnum):
            return type(int.from_bytes(value, "big"))
        elif issubclass(type, Enum):
            return type(value)
        elif issubclass(type, Unpackable):
            return type.unpack(value)
        elif type == bytes or type == memoryview or type == bytearray:
            return bytes(value)
        elif type == int:
            return int.from_bytes(value, "big")
        else:
            return value
    except (TypeError, ValueError, Exception):
        return value


def unpack_optional_tlv(value):
    if isinstance(value, TLV):
        return value.value
    return value


class TLV:
    tag: int
    length: int
    value: Union[bytearray, bytes, Packable, List[Packable]]

    def __repr__(self):
        if isinstance(self.value, list):
            result = f"{self.tag}[{self.length}]:"
            for el in self.value:
                if isinstance(el, bytearray) or isinstance(el, bytes):
                    result += f"\n{el.hex()}"
                else:
                    nested = "\n".join(" " + line for line in str(el).splitlines())
                    result += f"\n {nested}"
            return result
        elif (
            isinstance(self.value, bytearray)
            or isinstance(self.value, bytes)
            or isinstance(self.value, memoryview)
        ):
            return f"{self.tag}[{int_to_bytes(int(self.length)).hex()}]" + (
                f": \n  {self.value.hex()}" if int(self.length) > 0 else ""
            )
        else:
            return f"UNKNOWN TYPE {type(self.value)}"


class TLVList(list):
    def __repr__(self) -> str:
        result = "["
        for el in self:
            result += f"\n{el}"
        result += "\n]"
        return result


class BERTLVTagClass(IntEnum):
    UNIVERSAL = 0b00
    APPLICATION = 0b01
    CONTEXT_SPECIFIC = 0b10
    PRIVATE = 0b11


class BERTLVTag(Packable, Unpackable):
    data: bytes

    @property
    def value(self):
        raise NotImplementedError()

    @property
    def class_(self):
        return BERTLVTagClass((self.data[0] & 0b11000000) >> 6)

    @property
    def is_constructed(self):
        return bool(self.data[0] & 0b00100000)

    def __init__(self, data):
        if isinstance(data, int):
            self.data = int_to_bytes(data)
        elif (
            isinstance(data, bytes)
            or isinstance(data, bytearray)
            or isinstance(data, list)
        ):
            self.data = bytes(data)

    def __repr__(self):
        return f"{self.pack().hex()}"

    @classmethod
    def unpack(cls, data: bytes):
        return cls._unpack_tag(data)

    @classmethod
    def _unpack_tag(cls, data: bytes):
        result = []
        index = 0
        tag = data[index]

        index += 1
        result.append(tag)
        tag_number = tag & 0b00011111
        tag_extension_left = tag_number & 0b00011111 == 0b00011111
        while tag_extension_left:
            tag_extension = data[index]
            result.append(tag_extension)
            tag_extension_left = bool(tag_extension & 0b10000000)
            index += 1
        return BERTLVTag(result)

    def pack(self) -> bytes:
        return self.data


class BERTLVLength(Packable, Unpackable):
    data: bytes

    def __init__(self, data):
        if isinstance(data, int):
            if data <= 127:
                self.data = int_to_bytes(data)
            else:
                data = int_to_bytes(data)
                fb = 0b10000000 + len(data)
                self.data = bytes([fb] + [d for d in data])
        elif (
            isinstance(data, bytes)
            or isinstance(data, bytearray)
            or isinstance(data, list)
        ):
            self.data = bytes(data)
        else:
            raise TypeError(f"UNKNOWN TYPE {type(data)}")

    def __int__(self):
        return self.value

    @property
    def is_indefinite(self):
        return bool((self.data[0] & 0b01111111) == 0)

    @property
    def value(self):
        data = self.data
        index = 0
        length_base_data = data[index]
        length_form_is_simple = bool(~length_base_data & 0b10000000)
        if length_form_is_simple:
            return length_base_data & 0b01111111
        else:
            length_length = length_base_data & 0b01111111
            if length_length:
                # Definite form
                length_data = bytes(data[1 : 1 + length_length])
                index += length_length
            else:
                # Indefinite form
                length_data = b""
                while not length_data.endswith(b"\x00\x00"):
                    index += 1
                    length_data += bytes([data[index]])
            return int.from_bytes(length_data, "big")

    @classmethod
    def unpack(cls, data: bytes):
        return cls._unpack_length(data)

    @classmethod
    def _unpack_length(cls, data: bytes):
        index = 0
        result = []
        length_base_data = data[index]
        result.append(data[index])
        index += 1

        length_form_is_simple = bool(~length_base_data & 0b10000000)
        if length_form_is_simple:
            return BERTLVLength(data=result)
        else:
            length_length = length_base_data & 0b01111111

            if length_length:
                # Definite form
                result.extend(data[index : index + length_length])
                index += length_length
                if len(result) != length_length + 1:
                    raise ValueError("Bad format")
            else:
                # Indefinite form
                while not bytes(result).endswith(b"\x00\x00"):
                    result.append(data[index])
                    index += 1
            return BERTLVLength(result)

    def pack(self):
        return self.data

    def __repr__(self):
        return f"{self.pack().hex()}"


class BERTLV(TLV, Packable, Unpackable):
    tag: BERTLVTag
    length: BERTLVLength
    value: PackableData

    def __init__(self, tag, length=None, value: PackableData = b""):
        tag = BERTLVTag(tag) if isinstance(tag, int) else tag
        length = length or len(pack(value))
        length = BERTLVLength(length) if isinstance(length, int) else length

        self.tag = tag
        self.value = value
        self.length = length

    def __getitem__(self, key: Union[int, bytes, bytearray, Collection[int]]):
        if (
            isinstance(key, bytes)
            or isinstance(key, bytearray)
            or isinstance(key, list)
            or isinstance(key, tuple)
        ):
            if self.tag.is_constructed:
                return list(
                    tlv for tlv in self.value if bytes(tlv.tag.data) == bytes(key)
                )
            else:
                raise Exception(
                    "Cannot get child tags by key because this TLV is not constructed"
                )
        else:
            return self.value[key]

    def pack(self):
        return pack((self.tag, self.length, self.value))

    @classmethod
    def unpack_array(cls, data: bytes):
        result = []
        index = 0
        while index < len(data) - 1:
            _tlv = BERTLV.unpack(data[index:])
            index += len(_tlv.pack())
            result.append(_tlv)
        return TLVList(result)

    @classmethod
    def unpack(cls, data: bytes):
        return cls._unpack_tlv(data)

    @classmethod
    def _unpack_tlv(cls, data: bytes):
        index = 0
        data = memoryview(data)
        tag = BERTLVTag.unpack(data[index:])
        index += len(tag.data)
        length = BERTLVLength.unpack(data[index:])
        index += len(length.data)
        data = memoryview(data)[index : index + length.value]
        if len(data) != length.value:
            raise ValueError("Tag length does not match data size")
        if tag.is_constructed:
            return BERTLV(tag, length, cls.unpack_array(data[index:]))
        else:
            return BERTLV(tag, length, bytes(data))


class TLV8(TLV, Packable, Unpackable):
    tag: int
    length: int
    value: PackableData

    def __init__(self, tag, value) -> None:
        self.tag = tag
        self.value = value
        super().__init__()

    @classmethod
    def unpack(cls, data: bytes):
        return cls._unpack_tlv(data)

    @classmethod
    def unpack_array(cls, data: bytes):
        result = []
        while len(data):
            tlv = cls._unpack_tlv(data)
            data = data[len(tlv.pack()) :]
            result.append(tlv)
        return TLVList(result)

    @property
    def length(self):
        return len(pack(self.value))

    def pack(self):
        data = pack(self.value)
        return bytes([self.tag, len(data), *data])

    @classmethod
    def _unpack_tlv(cls, data: bytes):
        index = 0
        data = memoryview(data)
        tag = data[index]
        index += 1
        length = data[index]
        index += 1
        data = memoryview(data)[index : index + length]
        return TLV8(tag, data)


class TLV8Field:
    def __init__(self, index=None, optional=True, default=None):
        self.index = index
        self.optional = optional
        self.default = default


class TLV8ObjectMeta(type):
    class _TLV8Field:
        def __init__(self, index, type: "type", optional=True, default=None):
            self.index = index
            self.type = type
            self.optional = optional
            self.default = default

    def __new__(cls, name, bases, attrs):
        _tlv8_fields = dict()
        for index, (fname, field) in enumerate(attrs.copy().items()):
            if isinstance(field, TLV8Field):
                attrs[fname] = field.default
                _tlv8_fields[fname] = TLV8ObjectMeta._TLV8Field(
                    field.index or index + 1,
                    type=attrs.get("__annotations__", {}).get(fname, None),
                    optional=field.optional,
                    default=field.default,
                )
        new_class = super().__new__(cls, name, bases, attrs)
        new_class._tlv8_fields = _tlv8_fields
        return new_class


class TLV8Object(Packable, Unpackable, metaclass=TLV8ObjectMeta):
    _tlv8_fields: dict[str, TLV8Field]

    def __init__(self, **kwargs):
        super().__init__()
        for name, field in self._tlv8_fields.items():
            value = kwargs.get(name, None)
            if not field.optional and value is None:
                raise ValueError(f"Field {name} cannot be null")
            setattr(self, name, value)

    @classmethod
    def unpack(cls, data) -> "TLV8Object":
        tlv_array = TLV8.unpack_array(data)
        result = {
            name: try_cast_type(
                unpack_optional_tlv(
                    next((tlv for tlv in tlv_array if tlv.tag == field.index), None)
                ),
                type=field.type,
            )
            for name, field in cls._tlv8_fields.items()
        }
        return cls(**result)

    def pack(self) -> bytes:
        result = []
        for name, field in self._tlv8_fields.items():
            value = getattr(self, name)
            if value is not None:
                result.append(TLV8(field.index, value))
        return b"".join(tlv.pack() for tlv in result)

    def __repr__(self) -> str:
        data = {
            name: getattr(self, name)
            for name, _ in self._tlv8_fields.items()
            if getattr(self, name) is not None
        }
        keys_string = ", ".join(
            f"{key}={represent(value)}" for key, value in data.items()
        )
        return f"{self.__class__.__name__}({keys_string})"
