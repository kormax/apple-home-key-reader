import hashlib
import os
from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import List, Optional, Union

from util.structable import represent
from util.tlv import TLV8Field, TLV8Object


class KeyType(IntEnum):
    CURVE25519 = 0x01
    SECP256R1 = 0x02


class Context(Enum):
    PERSISTENT = "Persistent"
    VOLATILE = "Volatile"
    VOLATILE_FAST = "VolatileFast"


@dataclass
class Enrollment:
    at: int
    payload: Union[bytes, str]

    @classmethod
    def from_dict(cls, enrollment: dict):
        return Enrollment(at=enrollment.get("at", 0), payload=enrollment.get("payload"))

    def to_dict(self):
        return {"at": self.at, "payload": self.payload}


@dataclass
class Enrollments:
    hap: Optional[Enrollment]
    attestation: Optional[Enrollment]

    @classmethod
    def from_dict(cls, enrollments: dict):
        return Enrollments(
            hap=Enrollment.from_dict(enrollments.get("hap", None))
            if enrollments.get("hap", None) is not None
            else None,
            attestation=Enrollment.from_dict(enrollments.get("attestation", None))
            if enrollments.get("attestation", None) is not None
            else None,
        )

    def to_dict(self):
        return {
            "hap": self.hap.to_dict() if self.hap is not None else None,
            "attestation": self.attestation.to_dict()
            if self.attestation is not None
            else None,
        }

    def __repr__(self) -> str:
        return f"Enrollments({'hap' if self.hap else ''}, {'attestation' if self.attestation else ''})"


@dataclass
class Endpoint:
    last_used_at: int
    counter: int
    key_type: KeyType
    public_key: bytes
    persistent_key: bytes
    enrollments: Enrollments

    @property
    def id(self):
        return hashlib.sha1(self.public_key).digest()[:6]

    @classmethod
    def from_dict(cls, endpoint: dict):
        return Endpoint(
            endpoint.get("last_used_at", 0),
            endpoint.get("counter", 0),
            KeyType(endpoint.get("key_type", 2)),
            bytes.fromhex(endpoint.get("public_key", "04" + ("00" * 32))),
            bytes.fromhex(endpoint.get("persistent_key", os.urandom(16).hex())),
            Enrollments.from_dict(endpoint.get("enrollments", dict())),
        )

    def to_dict(self):
        return {
            "last_used_at": self.last_used_at,
            "counter": self.counter,
            "key_type": self.key_type,
            "public_key": self.public_key.hex(),
            "persistent_key": self.persistent_key.hex(),
            "enrollments": self.enrollments.to_dict(),
        }

    def __repr__(self) -> str:
        return f"Endpoint(last_used_at={self.last_used_at}, counter={self.counter}, key_type={represent(self.key_type)}, public_key={self.public_key.hex()}; persistent_key={self.persistent_key.hex()}, enrollments={self.enrollments})"


@dataclass
class Issuer:
    public_key: bytes
    endpoints: List[Endpoint]

    @property
    def id(self):
        return hashlib.sha256("key-identifier".encode() + self.public_key).digest()[:8]

    @classmethod
    def from_dict(cls, issuer: dict):
        return Issuer(
            public_key=bytes.fromhex(issuer.get("public_key", "00" * 32)),
            endpoints=[
                Endpoint.from_dict(endpoint)
                for _, endpoint in issuer.get("endpoints", {}).items()
            ],
        )

    def to_dict(self):
        return {
            "public_key": self.public_key.hex(),
            "endpoints": {
                endpoint.id.hex(): endpoint.to_dict() for endpoint in self.endpoints
            },
        }

    def __repr__(self) -> str:
        return f"Issuer(public_key={self.public_key.hex()}, endpoints={self.endpoints})"


class HardwareFinishColor(Enum):
    TAN = bytes.fromhex("CED5DA00")
    GOLD = bytes.fromhex("AAD6EC00")
    SILVER = bytes.fromhex("E3E3E300")
    BLACK = bytes.fromhex("00000000")


class Operation(IntEnum):
    GET = 0x01
    ADD = 0x02
    REMOVE = 0x03


class Interface(IntEnum):
    CONTACTLESS = 0x5E


class KeyState(IntEnum):
    INACTIVE = 0x00
    ACTIVE = 0x01


class OperationStatus(IntEnum):
    SUCCESS = 0x00
    OUT_OF_RESOURCES = 0x01
    DUPLICATE = 0x02
    DOES_NOT_EXIST = 0x03
    NOT_SUPPORTED = 0x04


class HardwareFinishResponse(TLV8Object):
    color: HardwareFinishColor = TLV8Field(1)


class SupportedConfigurationResponse(TLV8Object):
    number_of_issuer_keys: int = TLV8Field(1)
    number_of_inactive_credentials: int = TLV8Field(2)


class DeviceCredentialRequest(TLV8Object):
    key_type: KeyType = TLV8Field(1)
    credential_public_key: bytes = TLV8Field(2)
    issuer_key_identifier: bytes = TLV8Field(3)
    key_state: KeyState = TLV8Field(4)
    key_identifier: bytes = TLV8Field(5)


class ReaderKeyRequest(TLV8Object):
    key_type: KeyType = TLV8Field(1)
    reader_private_key: bytes = TLV8Field(2)
    unique_reader_identifier: bytes = TLV8Field(3)
    key_identifier: bytes = TLV8Field(4)


class ControlPointRequest(TLV8Object):
    operation: Operation = TLV8Field(1, optional=False)
    device_credential_request: DeviceCredentialRequest = TLV8Field(4)
    reader_key_request: ReaderKeyRequest = TLV8Field(6)


class DeviceCredentialResponse(TLV8Object):
    key_identifier: bytes = TLV8Field(1)
    issuer_key_identifier: bytes = TLV8Field(2)
    status: OperationStatus = TLV8Field(3)


class ReaderKeyResponse(TLV8Object):
    key_identifier: bytes = TLV8Field(1)
    status: OperationStatus = TLV8Field(2)


class ControlPointResponse(TLV8Object):
    device_credential_response: DeviceCredentialResponse = TLV8Field(5)
    reader_key_response: DeviceCredentialResponse = TLV8Field(7)
