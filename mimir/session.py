from __future__ import annotations

import os
import stat
import struct
import time
from typing import Optional

from mimir.crypto import derive_key

DEFAULT_SESSION_TIMEOUT = 900

# 32-byte key + 8-byte last-access timestamp
_KEY_SIZE = 32
_RECORD_SIZE = _KEY_SIZE + 8


def _session_path() -> str:
    return f"/tmp/mimir-{os.getuid()}"


class Session:
    def __init__(self, key: bytes, timeout: int = DEFAULT_SESSION_TIMEOUT) -> None:
        self.key: bytes = key
        self.timeout: int = timeout

    @staticmethod
    def resume(timeout: int = DEFAULT_SESSION_TIMEOUT) -> Optional[Session]:
        """Return the active session from the temp file, or None if none/expired."""
        path = _session_path()
        # O_NOFOLLOW + an fstat ownership/type check guard against a local
        # attacker pre-planting /tmp/mimir-<uid> as a symlink to redirect the
        # read (the path is fixed and world-predictable).
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            return None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid():
                return None
            data = os.read(fd, _RECORD_SIZE)
        finally:
            os.close(fd)

        if len(data) < _RECORD_SIZE:
            return None

        key = data[:_KEY_SIZE]
        last_access = struct.unpack(">Q", data[_KEY_SIZE:])[0]

        if timeout > 0 and time.time() - last_access > timeout:
            Session.lock()
            return None

        session = Session(key, timeout)
        session.persist()  # refresh last-access timestamp
        return session

    @classmethod
    def start(cls, password: str, salt: bytes, timeout: int = DEFAULT_SESSION_TIMEOUT) -> Session:
        """Derive the key from the password and persist a new session."""
        session = cls(derive_key(password, salt), timeout)
        session.persist()
        return session

    def persist(self) -> None:
        record = self.key + struct.pack(">Q", int(time.time()))
        path = _session_path()
        # Unlink first, then create with O_NOFOLLOW: if an attacker pre-planted
        # the path as a symlink, O_NOFOLLOW makes the open fail rather than
        # truncating/writing the key through the link to an arbitrary file.
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, record)
        finally:
            os.close(fd)

    @staticmethod
    def lock() -> None:
        """Delete the session temp file (mimir lock)."""
        try:
            os.unlink(_session_path())
        except FileNotFoundError:
            pass
