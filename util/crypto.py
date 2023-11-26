from typing import Union

from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_der_public_key


ECSDA_PUBLIC_KEY_ASN_HEADER = bytearray.fromhex(
    "3039301306072a8648ce3d020106082a8648ce3d030107032200"
)


def get_ec_key_public_points(key):
    return key.public_numbers().x.to_bytes(32, "big"), key.public_numbers().y.to_bytes(
        32, "big"
    )


def load_ec_public_key_from_bytes(data: Union[bytes, str], curve=ec.SECP256R1()):
    if isinstance(data, str):
        data = bytes.fromhex(data)
    if data[0] == 0x04:
        return EllipticCurvePublicNumbers(
            int.from_bytes(data[1:33], "big"),
            int.from_bytes(data[33:], "big"),
            curve=curve,
        ).public_key()
    elif data[0] in (0x03, 0x02):
        return load_der_public_key(ECSDA_PUBLIC_KEY_ASN_HEADER + data)
    else:
        raise ValueError("Does not look like an ec key")


def decrypt_aes_cbc(key: bytes, iv: bytes, ciphertext: bytes):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def encrypt_aes_cbc(key: bytes, iv: bytes, plaintext: bytes):
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def aes_cmac(key: bytes, value: bytes):
    cm = cmac.CMAC(algorithms.AES(key))
    cm.update(value)
    return cm.finalize()


def pad_mode_3(message, pad_byte=0x80, *, block_size=8):
    return message + bytes(
        [pad_byte]
        + ([0x00] * ((block_size - (len(message) + 1) % block_size) % block_size))
    )


def unpad_mode_3(message, pad_flag_byte=0x80, *, block_size=8):
    result = bytes()
    padding = True
    for b in reversed(message):
        if not padding:
            result += bytes([b])
        elif b in (0x00,):
            pass
            # Still padding
        elif b in (pad_flag_byte,):
            padding = False

    if len(result) == 0:
        return message
    if padding:
        raise ValueError("Message does not contain padding to remove")
    return bytes(reversed(result))
