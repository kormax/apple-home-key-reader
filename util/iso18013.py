import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from util.iso7816 import ISO7816Tag


#
# Code in this file is highly inspired by https://github.com/google/identity-credential
#

READER_CONTEXT = "SKReader".encode()
ENDPOINT_CONTEXT = "SKDevice".encode()

READER_MODE = bytes.fromhex("00000000")
ENDPOINT_MODE = bytes.fromhex("00000001")


class ISO18013SecureContext:
    def __init__(self, tag: ISO7816Tag, shared_secret, salt, key_length):
        self.tag = tag

        self.reader_counter = 1
        self.reader_key = HKDF(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            info=READER_CONTEXT,
        ).derive(shared_secret)

        self.endpoint_counter = 1
        self.endpoint_key = HKDF(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            info=ENDPOINT_CONTEXT,
        ).derive(shared_secret)

    @property
    def reader_iv(self):
        return bytes([0x00] * 4) + READER_MODE + self.reader_counter.to_bytes(4, "big")

    @property
    def endpoint_iv(self):
        return (
            bytes([0x00] * 4) + ENDPOINT_MODE + self.endpoint_counter.to_bytes(4, "big")
        )

    def encrypt_message_to_endpoint(self, message: bytes):
        ciphertext = cbor2.dumps(
            {
                "data": AESGCM(self.reader_key).encrypt(
                    nonce=self.reader_iv, associated_data=None, data=message
                )
            }
        )
        self.reader_counter += 1
        return ciphertext

    def decrypt_message_from_endpoint(self, message: bytes):
        cbor = cbor2.loads(message)
        cbor_ciphertext = cbor["data"]
        cbor_plaintext = AESGCM(self.endpoint_key).decrypt(
            nonce=self.endpoint_iv, data=cbor_ciphertext, associated_data=None
        )
        self.endpoint_counter += 1
        return cbor_plaintext


__all__ = "ISO18013SecureContext"
