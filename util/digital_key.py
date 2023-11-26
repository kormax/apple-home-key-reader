from enum import IntEnum
from typing import Tuple

from util.crypto import (
    aes_cmac,
    decrypt_aes_cbc,
    encrypt_aes_cbc,
    pad_mode_3,
    unpad_mode_3,
)
from util.iso7816 import ISO7816Command, ISO7816Response, ISO7816Tag


COMMAND_PCB = bytes.fromhex("000000000000000000000000000000")
RESPONSE_PCB = bytes.fromhex("800000000000000000000000000000")
INITIAL_MAC_CHAINING_VALUE = bytes.fromhex("00000000000000000000000000000000")


class DigitalKeyTransactionType(IntEnum):
    UNLOCK = 0x01


class DigitalKeyTransactionFlags(IntEnum):
    STANDARD = 0x00
    FAST = 0x01


class DigitalKeyFlow(IntEnum):
    FAST = 0x00
    STANDARD = 0x01
    ATTESTATION = 0x02


def encrypt(plaintext: bytes, pcb: bytes, kenc: bytes, counter: int, block_size=16):
    if not len(plaintext):
        return plaintext
    padded_plaintext = pad_mode_3(plaintext, block_size=block_size)
    icv = encrypt_aes_cbc(
        kenc,
        iv=b"\x00" * 16,
        plaintext=pcb + bytes([counter % 256]),
    )
    return encrypt_aes_cbc(kenc, iv=icv, plaintext=padded_plaintext)


def decrypt(ciphertext: bytes, pcb: bytes, kenc: bytes, counter: int, block_size=16):
    if not len(ciphertext):
        return ciphertext

    icv = encrypt_aes_cbc(
        kenc,
        iv=b"\x00" * 16,
        plaintext=pcb + bytes([counter % 256]),
    )
    padded_plaintext = decrypt_aes_cbc(kenc, iv=icv, ciphertext=ciphertext)
    return unpad_mode_3(padded_plaintext, block_size=block_size)


class DigitalKeySecureContext:
    def __init__(self, tag: ISO7816Tag, kenc, kmac, krmac):
        self.tag = tag
        self.kenc = kenc
        self.kmac = kmac
        self.krmac = krmac
        self.counter = 0
        self.mac_chaining_value = INITIAL_MAC_CHAINING_VALUE

    def encrypt_command(self, command: ISO7816Command) -> Tuple[ISO7816Command, bytes]:
        ciphertext = encrypt(
            plaintext=command.data,
            pcb=COMMAND_PCB,
            kenc=self.kenc,
            counter=self.counter,
        )
        calculated_rmac = aes_cmac(self.kmac, self.mac_chaining_value + ciphertext)
        data = ciphertext + calculated_rmac[:8]
        return (
            ISO7816Command(
                cla=command.cla,
                ins=command.ins,
                p1=command.p1,
                p2=command.p2,
                data=data,
                le=command.le,
            ),
            calculated_rmac,
        )

    def encrypt_response(
        self, response: ISO7816Response
    ) -> Tuple[ISO7816Response, int]:
        ciphertext = encrypt(
            plaintext=response.data,
            pcb=RESPONSE_PCB,
            kenc=self.kenc,
            counter=self.counter,
        )
        calculated_rmac = aes_cmac(self.krmac, self.mac_chaining_value + ciphertext)
        data = ciphertext + calculated_rmac[:8]
        return (
            ISO7816Response(sw1=response.sw1, sw2=response.sw2, data=data),
            self.counter + 1,
        )

    def decrypt_command(self, command: ISO7816Command) -> Tuple[ISO7816Command, bytes]:
        ciphertext, mac = command.data[:-8], command.data[-8:]
        calculated_mac = aes_cmac(self.kmac, self.mac_chaining_value + ciphertext)
        assert (
            mac == calculated_mac[:8]
        ), f"MAC Does  {mac.hex()=} {calculated_mac[:8].hex()=}"
        plaintext = decrypt(
            ciphertext=ciphertext, pcb=COMMAND_PCB, kenc=self.kenc, counter=self.counter
        )
        return (
            ISO7816Command(
                cla=command.cla,
                ins=command.ins,
                p1=command.p1,
                p2=command.p2,
                data=plaintext,
                le=command.le,
            ),
            calculated_mac,
        )

    def decrypt_response(
        self, response: ISO7816Response
    ) -> Tuple[ISO7816Response, int]:
        ciphertext, rmac = response.data[:-8], response.data[-8:]
        calculated_rmac = aes_cmac(self.krmac, self.mac_chaining_value + ciphertext)
        assert (
            rmac == calculated_rmac[:8]
        ), f"RMAC Does  {rmac.hex()=} {calculated_rmac[:8].hex()=}"
        plaintext = decrypt(
            ciphertext=ciphertext,
            pcb=RESPONSE_PCB,
            kenc=self.kenc,
            counter=self.counter,
        )
        return (
            ISO7816Response(sw1=response.sw1, sw2=response.sw2, data=plaintext),
            self.counter + 1,
        )

    def transceive_plain_secure(self, command: ISO7816Command) -> ISO7816Response:
        """Sends a plain command and expects a secure response"""
        decrypted_response, self.counter = self.decrypt_response(
            self.tag.transceive(command)
        )
        return decrypted_response

    def transceive_secure_secure(self, command: ISO7816Command) -> ISO7816Response:
        """Sends a secure command and expects a secure response"""
        encrypted_command, self.mac_chaining_value = self.encrypt_command(command)

        encrypted_response = self.tag.transceive(encrypted_command)
        decrypted_response, self.counter = self.decrypt_response(encrypted_response)
        return decrypted_response

    def transceive(self, command: ISO7816Command) -> ISO7816Response:
        return self.transceive_secure_secure(command)


__all__ = (
    "DigitalKeyFlow",
    "DigitalKeyTransactionType",
    "DigitalKeyTransactionFlags",
    "DigitalKeySecureContext",
)
