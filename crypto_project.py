"""
Fundamental of Cryptography Group Project
Symmetric Cryptography Implementation:
1. LFSR-based Stream Cipher
2. AES-CBC Block Cipher

Group Members:
- MUHAMMAD AFIF ASHRIQ BIN NASARUDDIN (AM2505019013)
- MUHAMMAD SHAFWAN FIRDAUS BIN MUHAMMAD ALBERT FRANCIS (AM2505019417)
- MUHAMMAD FAREEZ IMRAN BIN ROSMEN (AM2505018450)
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# =====================================================
# PART A1: LFSR-BASED STREAM CIPHER
# =====================================================

@dataclass
class LFSRConfig:
    """Configuration for a 16-bit Linear Feedback Shift Register."""
    seed: int
    taps: Tuple[int, ...] = (16, 14, 13, 11)
    register_size: int = 16


class LFSRStreamCipher:
    """
    Educational LFSR-based stream cipher.

    The cipher generates a pseudo-random keystream and combines it with
    plaintext using XOR.

    Encryption:
        Ciphertext = Plaintext XOR Keystream

    Decryption:
        Plaintext = Ciphertext XOR Keystream

    The same seed must be used during decryption so that the same keystream
    can be regenerated.
    """

    def __init__(self, config: LFSRConfig):
        if config.seed <= 0 or config.seed >= (1 << config.register_size):
            raise ValueError("Seed must be non-zero and fit inside the register size.")

        self.config = config
        self.state = config.seed
        self.mask = (1 << config.register_size) - 1

    @staticmethod
    def generate_key(register_size: int = 16) -> int:
        """Generate a random non-zero LFSR seed."""
        seed = 0
        byte_length = register_size // 8

        while seed == 0:
            seed = int.from_bytes(os.urandom(byte_length), "big")

        return seed

    def _next_bit(self) -> int:
        """Generate the next bit from the LFSR."""
        feedback = 0

        for tap in self.config.taps:
            feedback ^= (self.state >> (tap - 1)) & 1

        output_bit = self.state & 1
        self.state = (
            (self.state >> 1)
            | (feedback << (self.config.register_size - 1))
        ) & self.mask

        return output_bit

    def next_byte(self) -> int:
        """Generate one byte from eight LFSR bits."""
        byte_value = 0

        for bit_position in range(8):
            byte_value |= self._next_bit() << bit_position

        return byte_value

    def keystream(self, length: int) -> bytes:
        """Generate keystream bytes based on the requested length."""
        return bytes(self.next_byte() for _ in range(length))

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt plaintext bytes using XOR with the generated keystream."""
        stream = self.keystream(len(data))
        return bytes(data_byte ^ key_byte for data_byte, key_byte in zip(data, stream))

    def decrypt(self, encrypted_data: bytes) -> bytes:
        """Decrypt ciphertext bytes. XOR encryption is reversible."""
        return self.encrypt(encrypted_data)


# =====================================================
# PART A2: AES-CBC BLOCK CIPHER
# =====================================================

class AESCBC:
    """
    AES-CBC block cipher implementation.

    AES is a modern symmetric block cipher with a 128-bit block size.
    This implementation uses:
    - AES-256 key length
    - CBC mode
    - Random 128-bit IV
    - PKCS7 padding

    Output format:
        IV || Ciphertext
    """

    @staticmethod
    def generate_key() -> bytes:
        """Generate a 256-bit AES key."""
        return os.urandom(32)

    @staticmethod
    def encrypt(data: bytes, key: bytes) -> bytes:
        """Encrypt data using AES-CBC and return IV + ciphertext."""
        iv = os.urandom(16)

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()

        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return iv + ciphertext

    @staticmethod
    def decrypt(encrypted_data: bytes, key: bytes) -> bytes:
        """Decrypt AES-CBC data where the input format is IV + ciphertext."""
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext


# =====================================================
# HELPER FUNCTIONS
# =====================================================

def create_test_file(path: Path, size_bytes: int) -> None:
    """Create a random binary test file of the required size."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(os.urandom(size_bytes))


def verify_correctness() -> None:
    """Verify that both implemented algorithms encrypt and decrypt correctly."""
    plaintext = b"Confidential organization message and file data must be protected."

    # LFSR correctness test
    lfsr_seed = LFSRStreamCipher.generate_key()
    lfsr_encryptor = LFSRStreamCipher(LFSRConfig(seed=lfsr_seed))
    lfsr_ciphertext = lfsr_encryptor.encrypt(plaintext)

    lfsr_decryptor = LFSRStreamCipher(LFSRConfig(seed=lfsr_seed))
    lfsr_plaintext = lfsr_decryptor.decrypt(lfsr_ciphertext)

    # AES-CBC correctness test
    aes_key = AESCBC.generate_key()
    aes_ciphertext = AESCBC.encrypt(plaintext, aes_key)
    aes_plaintext = AESCBC.decrypt(aes_ciphertext, aes_key)

    assert lfsr_plaintext == plaintext, "LFSR decryption failed."
    assert aes_plaintext == plaintext, "AES-CBC decryption failed."

    print("Correctness test passed for LFSR Stream Cipher and AES-CBC Block Cipher.")
    print("Original plaintext:", plaintext)
    print("LFSR ciphertext sample:", lfsr_ciphertext[:16])
    print("AES-CBC ciphertext sample:", aes_ciphertext[:16])


if __name__ == "__main__":
    verify_correctness()
