from __future__ import annotations

import os
import struct
import time
from typing import TYPE_CHECKING, Union

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from mimir.model import Vault

if TYPE_CHECKING:
    from mimir.session import Session

MAGIC = b"MIMIR"
FORMAT_VERSION = 0x01
SALT_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16

# Header field offsets (bytes): magic(5) version(1) modified(8) salt(32) nonce(12)
_VERSION_OFFSET = 5
_MODIFIED_OFFSET = 6
_SALT_OFFSET = 14
_NONCE_OFFSET = 46
HEADER_SIZE = 58  # also the offset at which the ciphertext body begins


def derive_key(password: str, salt: bytes) -> bytes:
    # n=2**20 (~1 GiB, memory-hard) so the encrypted vault stays brute-force
    # resistant even when stored somewhere publicly readable. The cost is paid
    # once per session unlock, not per command.
    kdf = Scrypt(salt=salt, length=32, n=2**20, r=8, p=1)
    return kdf.derive(password.encode("utf-8"))


class VaultFile:
    """Reads and writes the on-disk vault format.

    Layout:
        [ magic     5 ] b"MIMIR"
        [ version   1 ]
        [ modified  8 ] big-endian uint64, Unix epoch
        [ salt     32 ] scrypt salt
        [ nonce    12 ] AES-GCM nonce
        [ body      N ] AES-GCM ciphertext + 16-byte tag

    Parsing methods accept either a path (``str``) or the raw file content
    (``bytes``), so the same code reads a local file or a blob fetched from a
    remote. They raise ``ValueError`` on a malformed or unsupported file.
    """

    @staticmethod
    def _raw(source: Union[str, bytes]) -> bytes:
        if isinstance(source, (bytes, bytearray)):
            return bytes(source)
        with open(source, "rb") as f:
            return f.read()

    @staticmethod
    def _validate(raw: bytes) -> None:
        """Check the header is present, well-formed, and a supported version."""
        if len(raw) < HEADER_SIZE:
            raise ValueError("Vault file is too small or corrupted")
        if raw[:_VERSION_OFFSET] != MAGIC:
            raise ValueError("Invalid vault file: bad magic bytes")
        version = raw[_VERSION_OFFSET]
        if version != FORMAT_VERSION:
            raise ValueError(f"Unsupported vault format version: {version}")

    @classmethod
    def salt(cls, source: Union[str, bytes]) -> bytes:
        """Read the scrypt salt from the header without decrypting."""
        raw = cls._raw(source)
        cls._validate(raw)
        return raw[_SALT_OFFSET:_SALT_OFFSET + SALT_SIZE]

    @classmethod
    def modified(cls, source: Union[str, bytes]) -> int:
        """Read the last-modified timestamp from the header without decrypting."""
        raw = cls._raw(source)
        cls._validate(raw)
        return struct.unpack(">Q", raw[_MODIFIED_OFFSET:_SALT_OFFSET])[0]

    @classmethod
    def read(cls, source: Union[str, bytes], session: Session) -> Vault:
        """Decrypt and parse the full vault using the session key."""
        raw = cls._raw(source)
        cls._validate(raw)
        if len(raw) < HEADER_SIZE + TAG_SIZE:
            raise ValueError("Vault file is too small or corrupted")

        header = raw[:HEADER_SIZE]
        nonce = raw[_NONCE_OFFSET:HEADER_SIZE]
        body = raw[HEADER_SIZE:]
        try:
            # The header is authenticated (AAD) but not encrypted, so tampering
            # with the version/modified/salt/nonce fields fails the tag check
            # just like tampering with the ciphertext does.
            plaintext = AESGCM(session.key).decrypt(nonce, body, header)
        except Exception:
            raise ValueError("Decryption failed: wrong password or corrupted vault")

        vault = Vault.from_json(plaintext)
        vault.salt = raw[_SALT_OFFSET:_SALT_OFFSET + SALT_SIZE]
        vault.version = raw[_VERSION_OFFSET]
        vault.modified = struct.unpack(">Q", raw[_MODIFIED_OFFSET:_SALT_OFFSET])[0]
        return vault

    @staticmethod
    def serialize(vault: Vault, session: Session) -> bytes:
        """Encrypt the vault and return the full file bytes, stamping the header."""
        vault.version = FORMAT_VERSION
        vault.modified = int(time.time())

        nonce = os.urandom(NONCE_SIZE)
        header = b"".join(
            [
                MAGIC,
                bytes([vault.version]),
                struct.pack(">Q", vault.modified),
                vault.salt,
                nonce,
            ]
        )
        # Authenticate the header (AAD) so the plaintext fields in front of the
        # ciphertext are covered by the GCM tag.
        body = AESGCM(session.key).encrypt(nonce, vault.to_json(), header)
        return header + body

    @classmethod
    def write(cls, path: str, vault: Vault, session: Session) -> None:
        """Encrypt and write the vault to disk."""
        with open(path, "wb") as f:
            f.write(cls.serialize(vault, session))
