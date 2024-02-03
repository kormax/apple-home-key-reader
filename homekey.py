import base64
import hashlib
import logging
import os
import time
from typing import Collection, List, Optional, Tuple

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF

from entity import (
    Context,
    Endpoint,
    Enrollment,
    Enrollments,
    Interface,
    Issuer,
    KeyType,
)
from util.crypto import get_ec_key_public_points, load_ec_public_key_from_bytes
from util.digital_key import (
    DigitalKeyFlow,
    DigitalKeySecureContext,
    DigitalKeyTransactionFlags,
    DigitalKeyTransactionType,
)
from util.generic import chunked, get_tlv_tag
from util.iso18013 import ISO18013SecureContext
from util.iso7816 import ISO7816, ISO7816Application, ISO7816Command, ISO7816Tag
from util.ndef import NDEFMessage, NDEFRecord
from util.structable import pack
from util.tlv import BERTLV as TLV

log = logging.getLogger()


class ProtocolError(Exception):
    pass


COSE_CONTEXT = "Signature1"
COSE_AAD = b""


# Random numbers presumably used to provide entropy.
# Coincidentally, they're valid UNIX epochs
READER_CONTEXT = int(1096652137).to_bytes(4, "big")
DEVICE_CONTEXT = int(1317567308).to_bytes(4, "big")


def find_issuer_by_id(issuers: List[Issuer], id):
    return next((i for i in issuers if i.id == id), None)


def find_endpoint_by_id_in_issuers(issuers: List[Issuer], id):
    return next((e for i in issuers for e in i.endpoints if e.id == id), None)


def get_endpoints_from_issuers(issuers: List[Issuer]):
    return (e for i in issuers for e in i.endpoints)


def generate_ec_key_if_provided_is_none(
    private_key: Optional[ec.EllipticCurvePrivateKey],
):
    return (
        ec.derive_private_key(int.from_bytes(private_key, "big"), ec.SECP256R1())
        if private_key
        else ec.generate_private_key(ec.SECP256R1())
    )


def get_key_material_generator(
    reader_ephemeral_private_key: ec.EllipticCurvePrivateKey,
    endpoint_ephemeral_public_key: ec.EllipticCurvePublicKey,
    transaction_identifier: bytes,
    interface: int,
    flags: bytes,
    protocol_version: bytes,
    device_protocol_versions: List[bytes],
):
    reader_ephemeral_public_key = reader_ephemeral_private_key.public_key()

    endpoint_ephemeral_public_key_x, _ = get_ec_key_public_points(
        endpoint_ephemeral_public_key
    )
    reader_ephemeral_public_key_x, _ = get_ec_key_public_points(
        reader_ephemeral_public_key
    )

    shared_key = reader_ephemeral_private_key.exchange(
        ec.ECDH(), endpoint_ephemeral_public_key
    )
    log.info(f"shared_key={shared_key.hex()}")

    derived_key = X963KDF(
        algorithm=hashes.SHA256(),
        length=32,
        sharedinfo=transaction_identifier,
    ).derive(shared_key)
    log.info(f"derived_key={derived_key.hex()}")

    def generate_keying_material(context: Context, key_size: int):
        info_material = (
            reader_ephemeral_public_key_x,
            endpoint_ephemeral_public_key_x,
            transaction_identifier,
            interface,
            flags,
            context,
            TLV(0x5C, value=protocol_version),
            TLV(0x5C, value=device_protocol_versions),
        )

        info = pack(info_material)
        log.info(f"info={info.hex()}")

        material = HKDF(
            algorithm=hashes.SHA256(),
            length=key_size,
            salt=None,
            info=info,
        ).derive(derived_key)
        return material

    return generate_keying_material


def fast_auth(
    tag: ISO7816Tag,
    device_protocol_versions: List[bytes],
    protocol_version: bytes,
    interface: int,
    flags: bytes,
    reader_identifier: bytes,
    reader_public_key: ec.EllipticCurvePublicKey,
    reader_ephemeral_public_key: ec.EllipticCurvePublicKey,
    transaction_identifier: bytes,
    issuers: List[Issuer],
    key_size=16,
) -> Tuple[
    ec.EllipticCurvePublicKey, Optional[Endpoint], Optional[DigitalKeySecureContext]
]:
    (
        reader_ephemeral_public_key_x,
        reader_ephemeral_public_key_y,
    ) = get_ec_key_public_points(reader_ephemeral_public_key)
    reader_ephemeral_public_key_bytes = bytes(
        [0x04, *reader_ephemeral_public_key_x, *reader_ephemeral_public_key_y]
    )
    reader_public_key_x, _ = get_ec_key_public_points(reader_public_key)

    command_tlv = [
        TLV(0x5C, value=protocol_version),
        TLV(0x87, value=reader_ephemeral_public_key_bytes),
        TLV(0x4C, value=transaction_identifier),
        TLV(0x4D, value=reader_identifier),
    ]
    command_data = pack(command_tlv)

    command = ISO7816Command(
        cla=0x80, ins=0x80, p1=flags[0], p2=flags[1], data=command_data, le=None
    )
    log.info(f"AUTH0 CMD = {command}")
    response = tag.transceive(command)
    if response.sw != (0x90, 0x00):
        raise ProtocolError(f"AUTH0 INVALID STATUS {response.sw}")
    log.info(f"AUTH0 RES = {response}")
    tlv_array = TLV.unpack_array(response.data)

    endpoint_ephemeral_public_key_tag = get_tlv_tag(tlv_array, 0x86)
    if endpoint_ephemeral_public_key_tag is None:
        raise ProtocolError(
            "Response does not contain endpoint_ephemeral_public_key_tag 0x86"
        )

    endpoint_ephemeral_public_key = load_ec_public_key_from_bytes(
        endpoint_ephemeral_public_key_tag
    )
    endpoint_ephemeral_public_key_x, _ = get_ec_key_public_points(
        endpoint_ephemeral_public_key
    )

    returned_cryptogram = get_tlv_tag(tlv_array, 0x9D)
    if returned_cryptogram is None:
        return endpoint_ephemeral_public_key, None, None

    endpoint = None
    # FAST gives us no way to find out the identity of endpoint from the data for security reasons,
    # so we have to iterate over all provisioned endpoints and hope that it's there
    log.info("Searching for an endpoint with matching cryptogram...")
    for endpoint in get_endpoints_from_issuers(issuers):
        k_persistent = endpoint.persistent_key
        endpoint_public_key_bytes = endpoint.public_key
        endpoint_public_key: ec.EllipticCurvePublicKey = load_ec_public_key_from_bytes(
            endpoint_public_key_bytes
        )
        endpoint_public_key_x, _ = get_ec_key_public_points(endpoint_public_key)

        # Whoever did this. Did that help? ;)
        info_material = (
            reader_public_key_x,
            Context.VOLATILE_FAST,
            reader_identifier,
            endpoint_public_key_x,
            interface,
            TLV(0x5C, value=device_protocol_versions),
            TLV(0x5C, value=protocol_version),
            reader_ephemeral_public_key_x,
            transaction_identifier,
            flags,
            endpoint_ephemeral_public_key_x,
        )

        info = pack(info_material)

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=key_size * 4,
            salt=None,
            info=info,
        ).derive(k_persistent)
        kcmac = hkdf[: key_size * 1]
        kenc = hkdf[key_size * 1 : key_size * 2]
        kmac = hkdf[key_size * 2 : key_size * 3]
        krmac = hkdf[key_size * 3 :]
        calculated_cryptogram = kcmac
        log.info(
            f"Endpoint({endpoint.id.hex()}):"
            f" returned_cryptogram={returned_cryptogram.hex()}"
            f" ? calculated_cryptogram={calculated_cryptogram.hex()}"
        )
        if returned_cryptogram == calculated_cryptogram:
            log.info(
                f"Cryptograms match for Endpoint({endpoint.id.hex()}):"
                f" kcmac={kcmac.hex()} kenc={kenc.hex()} kmac={kmac.hex()} krmac={krmac.hex()};"
            )
            return (
                endpoint_ephemeral_public_key,
                endpoint,
                DigitalKeySecureContext(tag, kenc, kmac, krmac),
            )
        else:
            endpoint = None
    return endpoint_ephemeral_public_key, endpoint, None


def standard_auth(
    tag: ISO7816Tag,
    device_protocol_versions: List[bytes],
    protocol_version: bytes,
    interface: int,
    flags: bytes,
    reader_identifier: bytes,
    reader_ephemeral_private_key: ec.EllipticCurvePrivateKey,
    reader_private_key: ec.EllipticCurvePrivateKey,
    transaction_identifier: bytes,
    endpoint_ephemeral_public_key: ec.EllipticCurvePublicKey,
    issuers: List[Issuer],
    key_size=16,
) -> Tuple[Optional[bytes], Optional[Endpoint], Optional[DigitalKeySecureContext]]:
    reader_ephemeral_public_key = reader_ephemeral_private_key.public_key()

    endpoint_ephemeral_public_key_x, _ = get_ec_key_public_points(
        endpoint_ephemeral_public_key
    )
    reader_ephemeral_public_key_x, _ = get_ec_key_public_points(
        reader_ephemeral_public_key
    )
    log.info(
        f"endpoint_ephemeral_public_key_x={endpoint_ephemeral_public_key_x.hex()}"
        f" reader_ephemeral_public_key_x={reader_ephemeral_public_key_x.hex()}"
    )

    authentication_hash_input_material = [
        TLV(0x4D, value=reader_identifier),
        TLV(0x86, value=endpoint_ephemeral_public_key_x),
        TLV(0x87, value=reader_ephemeral_public_key_x),
        TLV(0x4C, value=transaction_identifier),
        TLV(0x93, value=READER_CONTEXT),
    ]
    authentication_hash_input = pack(authentication_hash_input_material)
    log.info(f"authentication_hash_input={authentication_hash_input.hex()}")

    signature = reader_private_key.sign(
        authentication_hash_input, ec.ECDSA(hashes.SHA256())
    )
    log.info(f"signature={signature.hex()} ({hex(len(signature))})")
    x, y = decode_dss_signature(signature)
    signature_point_form = bytes([*x.to_bytes(32, "big"), *y.to_bytes(32, "big")])
    log.info(f"signature_point_form={signature_point_form.hex()} ({hex(len(signature_point_form))})")

    data = TLV(0x9E, value=signature_point_form)
    command = ISO7816Command(cla=0x80, ins=0x81, p1=0x00, p2=0x00, data=data)

    log.info(f"AUTH1 COMMAND {command}")
    response = tag.transceive(command)
    log.info(f"AUTH1 RESPONSE: {response}")
    if response.sw != (0x90, 0x00):
        raise ProtocolError(f"AUTH1 INVALID STATUS {response.sw}")

    get_key_material = get_key_material_generator(
        reader_ephemeral_private_key=reader_ephemeral_private_key,
        endpoint_ephemeral_public_key=endpoint_ephemeral_public_key,
        transaction_identifier=transaction_identifier,
        interface=interface,
        flags=flags,
        protocol_version=protocol_version,
        device_protocol_versions=device_protocol_versions,
    )

    k_persistent = get_key_material(context=Context.PERSISTENT, key_size=key_size * 2)
    log.info(f"k_persistent={k_persistent.hex()}")

    hkdf = get_key_material(context=Context.VOLATILE, key_size=key_size * 3)
    log.info(f"hkdf={hkdf.hex()}")
    kenc = hkdf[: key_size * 1]
    kmac = hkdf[key_size * 1 : key_size * 2]
    krmac = hkdf[key_size * 2 :]
    log.info(f"kenc={kenc.hex()} kmac={kmac.hex()} krmac={krmac.hex()}")

    secure = DigitalKeySecureContext(tag, kenc, kmac, krmac)

    try:
        response, secure.counter = secure.decrypt_response(response)
    except (AssertionError,):
        log.info("AUTH1 COULD NOT DECRYPT RESPONSE")
        return k_persistent, None, None

    log.info(f"AUTH1 DECRYPTED RESPONSE: {response}")

    tlv_array = TLV.unpack_array(response.data)

    signature = get_tlv_tag(tlv_array, 0x9E)
    if signature is None:
        raise ProtocolError("No device signature in response at tag 0x9E")

    device_identifier = get_tlv_tag(tlv_array, 0x4E)
    if device_identifier is None:
        raise ProtocolError("No device identifier in response at tag 0x4E")

    log.info(f"device_identifier={device_identifier.hex()}")

    endpoint = find_endpoint_by_id_in_issuers(issuers, device_identifier)
    if endpoint is None:
        log.warning("Could not find matching endpoint")
        return k_persistent, None, secure

    endpoint_public_key: ec.EllipticCurvePublicKey = load_ec_public_key_from_bytes(
        endpoint.public_key
    )

    log.info(f"signature={signature.hex()}")
    signature = encode_dss_signature(
        int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    )

    verification_hash_input_material = [
        TLV(0x4D, value=reader_identifier),
        TLV(0x86, value=endpoint_ephemeral_public_key_x),
        TLV(0x87, value=reader_ephemeral_public_key_x),
        TLV(0x4C, value=transaction_identifier),
        TLV(0x93, value=DEVICE_CONTEXT),
    ]
    verification_hash_input = pack(verification_hash_input_material)
    log.info(f"verification_hash_input={verification_hash_input.hex()}")

    try:
        endpoint_public_key.verify(
            signature, verification_hash_input, ec.ECDSA(hashes.SHA256())
        )
    except InvalidSignature as e:
        log.warning(f"Signature data does not match {e}")
        return k_persistent, None, secure
    return k_persistent, endpoint, secure


def exchange_attestation(tag: ISO7816Tag, shared_secret: bytes):
    """Performs attestation exchange, returns attestation package"""
    _ = select_applet(tag, ISO7816Application.HOME_KEY_CONFIGURATION)

    envelope1_engagement_message = NDEFMessage(
        [
            NDEFRecord(
                tnf=0x01,
                type=b"Hr",
                id=b"",
                payload=bytes.fromhex(
                    "1591020263720102510211616301036e6663010a6d646f63726561646572"
                ),
            ),
            NDEFRecord(tnf=0x04, type=b"iso.org:18013:nfc", id=b"nfc", payload=0x01),
            NDEFRecord(
                tnf=0x04,
                type=b"iso.org:18013:readerengagement",
                id=b"mdocreader",
                payload=bytes.fromhex("a20063312e30208129"),
            ),
        ]
    )
    envelope1_command = ISO7816Command(
        cla=0x00,
        ins=0xC3,
        p1=0x00,
        p2=0x01,
        le=0x00,
        data=pack(TLV(0x53, value=envelope1_engagement_message)),
    )
    log.info(f"ENVELOPE1 CMD = {envelope1_command}")
    envelope1_response = tag.transceive(envelope1_command)
    log.info(f"ENVELOPE1 RES = {envelope1_response}")

    envelope1_command_ndef = NDEFMessage.unpack(
        TLV.unpack(envelope1_command.data).value
    )
    envelope1_response_ndef = NDEFMessage.unpack(
        TLV.unpack(envelope1_response.data).value
    )

    response_engagement = next(
        (
            r
            for r in envelope1_response_ndef.records
            if r.type == b"iso.org:18013:deviceengagement"
        ),
        None,
    )
    response_engagement_cbor = cbor2.loads(response_engagement.payload)

    session_transcript = cbor2.dumps(
        cbor2.CBORTag(
            24,
            cbor2.dumps(
                [
                    cbor2.CBORTag(24, cbor2.dumps(response_engagement_cbor)),
                    [
                        envelope1_response_ndef.pack(),
                        envelope1_command_ndef.pack(),
                    ],
                ]
            ),
        )
    )
    salt = hashlib.sha256(session_transcript).digest()

    iso18013secure = ISO18013SecureContext(
        tag=tag, shared_secret=shared_secret, salt=salt, key_length=16
    )

    envelope2_command_data = TLV(
        0x53,
        value=iso18013secure.encrypt_message_to_endpoint(
            cbor2.dumps(
                {
                    "version": "1.0",
                    "docRequests": [
                        {
                            "itemsRequest": cbor2.CBORTag(
                                24,
                                cbor2.dumps(
                                    {
                                        "docType": "com.apple.HomeKit.1.credential",
                                        "nameSpaces": {
                                            "com.apple.HomeKit": {
                                                "credential_id": False,
                                            }
                                        },
                                    }
                                ),
                            )
                        }
                    ],
                }
            )
        ),
    )

    command = ISO7816Command(
        cla=0x00, ins=0xC3, p1=0x00, p2=0x00, data=envelope2_command_data, le=0x00
    )
    log.info(f"ENVELOPE2 CMD = {command}")
    response = tag.transceive(command)
    log.info(f"ENVELOPE2 RES = {response}")

    data = response.data

    while response.sw1 == 0x61:
        command = ISO7816Command(
            cla=0x00, ins=0xC0, p1=0x00, p2=0x00, data=None, le=response.sw2
        )
        log.info(f"GET DATA CMD = {command}")
        response = tag.transceive(command)
        log.info(f"GET DATA RES = {response}")
        data += response.data

    endpoint_cbor_plaintext = iso18013secure.decrypt_message_from_endpoint(
        TLV.unpack(data).value
    )
    return endpoint_cbor_plaintext


def mailbox_exchange(
    secure: DigitalKeySecureContext, mailbox_operations: Collection[TLV] = None
):
    command_tlv = [
        0x00,
        *(mailbox_operations or []),
    ]

    command_data = pack(command_tlv)
    command = ISO7816Command(
        cla=0x84, ins=0xC9, p1=0x00, p2=0x00, data=command_data, le=0x00
    )
    log.info(f"EXCHANGE COMMAND {command}")

    response = secure.transceive(command)
    log.info(f"EXCHANGE RESPONSE {response}")
    if response.sw1 != 0x90:
        raise ProtocolError("Mailbox exchange failed")
    return response.data


def select_applet(tag: ISO7816Tag, applet=ISO7816Application.HOME_KEY):
    command = ISO7816.select_aid(applet)
    log.info(f"SELECT CMD = {command}")
    response = tag.transceive(command)
    if response.sw != (0x90, 0x00):
        raise ProtocolError(
            f"Could not select {applet} {hex(response.sw1)} {hex(response.sw2)}"
        )
    log.info(f"SELECT RES = {response}")
    return response.data


def control_flow(tag: ISO7816Tag, p1=0x01, p2=0x00):
    command = ISO7816Command(cla=0x80, ins=0x3C, p1=p1, p2=p2, data=None, le=None)
    log.info(f"OP_CONTROL_FLOW CMD = {command}")
    response = tag.transceive(command)
    log.info(f"OP_CONTROL_FLOW RES = {response}")
    return response.data


def perform_authentication_flow(
    tag: ISO7816Tag,
    flow: DigitalKeyFlow,
    reader_identifier: bytes,
    reader_private_key: ec.EllipticCurvePrivateKey,
    reader_ephemeral_private_key: ec.EllipticCurvePrivateKey,
    attestation_exchange_common_secret: bytes,
    protocol_version: bytes,
    device_protocol_versions: List[bytes],
    transaction_identifier: bytes,
    flags: bytes,
    interface: int,
    issuers: List[Issuer],
    key_size=16,
) -> Tuple[DigitalKeyFlow, Optional[Issuer], Optional[Endpoint]]:
    """Returns an Endpoint if one was found and successfully authenticated.
    Returns an Issuer if endpoint was authenticated via Attestation
    """
    reader_public_key = reader_private_key.public_key()
    reader_public_key_x, reader_public_key_y = get_ec_key_public_points(
        reader_public_key
    )
    log.info(
        f"Reader public key: x={reader_public_key_x.hex()} y={reader_public_key_y.hex()}"
    )

    reader_ephemeral_public_key = reader_ephemeral_private_key.public_key()

    log.info(f"protocol_version={protocol_version.hex()}")

    endpoint_ephemeral_public_key, endpoint, secure = fast_auth(
        tag=tag,
        device_protocol_versions=device_protocol_versions,
        protocol_version=protocol_version,
        interface=interface,
        flags=flags,
        reader_identifier=reader_identifier,
        reader_public_key=reader_public_key,
        reader_ephemeral_public_key=reader_ephemeral_public_key,
        transaction_identifier=transaction_identifier,
        issuers=issuers,
        key_size=key_size,
    )

    if endpoint is not None and flow <= DigitalKeyFlow.FAST:
        return DigitalKeyFlow.FAST, None, endpoint

    k_persistent, endpoint, secure = standard_auth(
        tag=tag,
        device_protocol_versions=device_protocol_versions,
        protocol_version=protocol_version,
        interface=interface,
        flags=flags,
        transaction_identifier=transaction_identifier,
        reader_identifier=reader_identifier,
        reader_private_key=reader_private_key,
        reader_ephemeral_private_key=reader_ephemeral_private_key,
        issuers=issuers,
        endpoint_ephemeral_public_key=endpoint_ephemeral_public_key,
        key_size=key_size,
    )

    if endpoint is not None and k_persistent is not None:
        endpoint.persistent_key = k_persistent

    if endpoint is not None and flow <= DigitalKeyFlow.STANDARD:
        return DigitalKeyFlow.STANDARD, None, endpoint

    log.info(f"attestation_exchange_common_secret={attestation_exchange_common_secret.hex()}")
    # Notify OS about intent of exchanging attestation, provide common secret
    operation = TLV(0x8E, value=TLV(0xC0, value=attestation_exchange_common_secret))
    _ = mailbox_exchange(secure, mailbox_operations=(operation,))

    control_flow(tag, 0x40, 0xA0)

    attestation_package = exchange_attestation(tag, attestation_exchange_common_secret)
    log.info(f"attestation_package={attestation_package}")

    attestation_package_cbor = cbor2.loads(attestation_package)
    issuer_signed_cbor = attestation_package_cbor["documents"][0]["issuerSigned"][
        "issuerAuth"
    ]
    protected_headers, unprotected_headers, data, signature = issuer_signed_cbor
    issuer_id = unprotected_headers[4]
    data_cbor = cbor2.loads(cbor2.loads(data).value)
    device_key_info = data_cbor["deviceKeyInfo"]["deviceKey"]
    device_public_key_x, device_public_key_y = (
        device_key_info[-2],
        device_key_info[-3],
    )
    device_public_key_bytes = (
        bytes.fromhex("04") + device_public_key_x + device_public_key_y
    )

    issuer = find_issuer_by_id(issuers, id=issuer_id)
    if issuer is None:
        raise ProtocolError(f"Could not find issuer {issuer_id}")

    public_key = ed25519.Ed25519PublicKey.from_public_bytes(issuer.public_key)

    data_to_sign = cbor2.dumps([COSE_CONTEXT, protected_headers, COSE_AAD, data])

    try:
        public_key.verify(signature, data_to_sign)
    except InvalidSignature:
        log.info("Attestation signature is invalid ")
        return DigitalKeyFlow.ATTESTATION, None, None

    log.info(f"Attestation signature is valid {endpoint}")

    return (
        DigitalKeyFlow.ATTESTATION,
        issuer,
        endpoint
        or Endpoint(
            last_used_at=0,
            counter=0,
            key_type=KeyType.SECP256R1,
            public_key=device_public_key_bytes,
            persistent_key=k_persistent or os.urandom(32),
            enrollments=Enrollments(
                hap=None,
                attestation=Enrollment(
                    at=int(time.time()),
                    payload=base64.b64encode(attestation_package).decode(),
                ),
            ),
        ),
    )


def read_homekey(
    tag: ISO7816Tag,
    reader_identifier: bytes,
    reader_private_key: bytes,
    issuers: List[Issuer],
    preferred_versions: Collection[bytes] = None,
    flow=DigitalKeyFlow.FAST,
    transaction_code: DigitalKeyTransactionType = DigitalKeyTransactionType.UNLOCK,
    # Generated at random if not provided
    reader_ephemeral_private_key: Optional[bytes] = None,
    # Generated at random if not provided
    transaction_identifier: Optional[bytes] = None,
    # Generated at random if not provided
    attestation_exchange_common_secret: Optional[bytes] = None,
    interface=Interface.CONTACTLESS,
    key_size=16,
) -> Tuple[DigitalKeyFlow, List[Issuer], Optional[Endpoint]]:
    """
    Returns a list representing new configured issuer state
    and an optional endpoint in case authentication has been successful
    """
    transaction_flags = {
        DigitalKeyTransactionFlags.FAST
        if flow <= DigitalKeyFlow.FAST
        else DigitalKeyTransactionFlags.STANDARD
    }
    flags = bytes([sum(transaction_flags), transaction_code])

    response = select_applet(tag, applet=ISO7816Application.HOME_KEY)
    tlv_array = TLV.unpack_array(response)
    log.info(f"reader_identifier={reader_identifier.hex()}")

    versions_tag = get_tlv_tag(tlv_array, 0x5C)
    if versions_tag is None:
        raise ProtocolError(
            "Response does not contain supported version list at tag 0x5C"
        )

    device_protocol_versions = [ver for ver in chunked(versions_tag, 2)]
    preferred_versions = preferred_versions or []
    for preferred_version in preferred_versions:
        if preferred_version in device_protocol_versions:
            protocol_version = preferred_version
            log.info(f"Choosing preferred version {protocol_version}")
            break
    else:
        protocol_version = device_protocol_versions[0]
        log.info(f"Defaulting to the newest available version {protocol_version}")
    if protocol_version != b"\x02\x00":
        raise ProtocolError("Only officially supported protocol version is 0200")

    reader_private_key = ec.derive_private_key(
        int.from_bytes(reader_private_key, "big"), ec.SECP256R1()
    )

    result_flow, issuer, endpoint = perform_authentication_flow(
        tag=tag,
        flow=flow,
        reader_identifier=reader_identifier,
        reader_private_key=reader_private_key,
        reader_ephemeral_private_key=generate_ec_key_if_provided_is_none(
            reader_ephemeral_private_key
        ),
        attestation_exchange_common_secret=attestation_exchange_common_secret
        or os.urandom(32),
        protocol_version=protocol_version,
        device_protocol_versions=device_protocol_versions,
        transaction_identifier=transaction_identifier or os.urandom(16),
        flags=flags,
        interface=interface,
        issuers=issuers,
        key_size=key_size,
    )
    if endpoint is not None:
        endpoint.last_used_at = int(time.time())
        endpoint.counter += 1

    if issuer and endpoint not in get_endpoints_from_issuers(issuers):
        issuer.endpoints.append(endpoint)

    # Notify about transaction completion.
    if result_flow != DigitalKeyFlow.ATTESTATION:
        control_flow(tag)

    return result_flow, issuers, endpoint
