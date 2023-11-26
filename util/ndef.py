from enum import IntEnum
from typing import Collection, Union

from util.generic import bits
from util.structable import Packable, Unpackable, pack, represent


#
# Code inspired by information from "Beginning NFC book from O'reilly" and ndeflib
#


class NDEFRecordType(IntEnum):
    EMPTY = 0
    WELL_KNOWN = 1
    MIME = 2
    URI = 3
    EXTERNAL = 4
    UNKNOWN = 5
    UNCHANGED = 6
    RESERVED = 7


class NDEFRecord:
    id: bytes
    tnf: NDEFRecordType
    type: bytes
    payload: Union[Packable, bytes]

    def __init__(self, tnf, type, payload, id=b""):
        self.id = id
        self.tnf = tnf
        self.type = type
        self.payload = payload

    def __repr__(self):
        return f"NDEFRecord(tnf={represent(self.tnf)}, type={represent(self.type)}, id={represent(self.id)}, payload={represent(self.payload)})"


class NDEFMessage(Packable, Unpackable):
    records: Collection["NDEFRecord"]

    def __init__(self, records: Collection["NDEFRecord"]):
        self.records = records

    @classmethod
    def unpack(cls, data: bytes):
        index = 0
        records = []
        while index < len(data) - 1:
            first = data[index]
            index += 1

            mb, me, ch, sr, il, *tnf = bits(first)
            tnf = NDEFRecordType(int("".join(str(b) for b in tnf), 2))

            type_length = data[index]
            index += 1

            assert mb == (len(records) == 0)

            if sr:
                payload_length = data[index]
                index += 1
            else:
                payload_length = int.from_bytes(data[index : index + 4], "big")
                index += 4

            if il:
                id_length = data[index]
                index += 1
            else:
                id_length = 0

            type_ = data[index : index + type_length]
            index += type_length

            id_ = data[index : index + id_length]
            index += id_length

            payload = data[index : index + payload_length]
            index += payload_length

            records.append(NDEFRecord(id=id_, tnf=tnf, type=type_, payload=payload))
        return NDEFMessage(records)

    def pack(self) -> bytes:
        result = b""
        for index, record in enumerate(self.records):
            payload = pack(record.payload)

            mb = 0b10000000 * (index == 0)
            me = 0b01000000 * (index == len(self.records) - 1)  # Message end
            ch = 0b00100000 * 0  # Chunk flag
            sr = 0b00010000 * (len(payload) <= 255)  # Short record
            il = 0b00001000 * (len(record.id) > 0)  # ID length present
            tnf = record.tnf  # Record type

            header = mb + me + ch + sr + il + tnf

            id_length = [len(record.id)] if len(record.id) else []

            payload_length = [
                len(payload).to_bytes(4, byteorder="big") if not sr else len(payload)
            ]

            record_data = [
                header,
                len(record.type),
                payload_length,
                id_length,
                record.type,
                record.id,
                payload,
            ]
            result += pack(record_data)
        return result

    def find(self, filter, *, selection="first", default=None):
        if selection == "first":
            return next((record for record in self.records if filter(record)), default)
        elif selection == "last":
            return next(
                (record for record in reversed(self.records) if filter(record)), default
            )
        elif selection == "all":
            return [record for record in self.records if filter(record)]

    def __repr__(self):
        return (
            "NDEFMessage("
            + ", ".join("" + str(record) for record in self.records)
            + ")"
        )

    __all__ = ("NDEFMessage", "NDEFRecord")
