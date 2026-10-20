"""Where the client keeps its session.

A storage holds strings by key. The client stores one JSON document under ``openback.auth.<client id>``:
``{accessToken, refreshToken, idToken, expiresAt (epoch ms), user, org}`` -- the same shape as every OpenBack App Auth
SDK -- and, during a hosted-page sign-in, the pending PKCE transaction under ``<key>.pkce``.

Implement :class:`Storage` to keep it elsewhere (OS keyring, database, encrypted file, a web framework's server-side
session). Methods are synchronous and should be quick; they are called from both :class:`~openback_app_auth.Client`
and :class:`~openback_app_auth.AsyncClient`.
"""
from __future__ import annotations

import json
import os
import secrets
import threading
from pathlib import Path
from typing import Dict, Optional, Protocol, Union, runtime_checkable

__all__ = ["Storage", "MemoryStorage", "FileStorage"]


@runtime_checkable
class Storage(Protocol):
    """Key/value strings: the session store of a client."""

    def get(self, key: str) -> Optional[str]:
        """The value, or ``None``."""
        ...

    def set(self, key: str, value: str) -> None:
        """Store the value (replace it atomically when possible)."""
        ...

    def remove(self, key: str) -> None:
        """Forget the key (no error when missing)."""
        ...


class MemoryStorage:
    """In-memory storage (the default): the session ends with the process."""

    def __init__(self) -> None:
        self._data: Dict[str, str] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[str]:
        with self._lock:
            return self._data.get(key)

    def set(self, key: str, value: str) -> None:
        with self._lock:
            self._data[key] = str(value)

    def remove(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)


class FileStorage:
    """A JSON file readable only by the current user (mode 0600; its directory is created with mode 0700).

    Good for CLI and desktop apps. Writes go to a temporary file renamed over the old one, so a crash never leaves half
    a session. On Windows the POSIX mode bits are not enforced; the file inherits the ACL of its folder (by default
    the user's profile is private) -- prefer a location under the user's profile there.

    It is NOT a lock between processes: two processes refreshing at the same moment can still race (the second refresh
    is refused and that process signs out). Use one process per session, or a storage with your own locking.
    """

    def __init__(self, path: Union[str, "os.PathLike[str]"]) -> None:
        self.path = Path(path).expanduser()
        self._lock = threading.Lock()

    def _read(self) -> Dict[str, str]:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return {}
        return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}

    def _write(self, data: Dict[str, str]) -> None:
        directory = self.path.parent
        if not directory.exists():
            directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        if not data:
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass
            return
        tmp = directory / f".{self.path.name}.{secrets.token_hex(6)}.tmp"
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(json.dumps(data, separators=(",", ":")).encode("utf-8"))
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(str(tmp), str(self.path))
        except BaseException:
            try:
                tmp.unlink()
            except OSError:
                pass
            raise
        try:
            os.chmod(str(self.path), 0o600)
        except OSError:  # pragma: no cover - best effort (Windows, unusual file systems)
            pass

    def get(self, key: str) -> Optional[str]:
        with self._lock:
            return self._read().get(key)

    def set(self, key: str, value: str) -> None:
        with self._lock:
            data = self._read()
            data[key] = str(value)
            self._write(data)

    def remove(self, key: str) -> None:
        with self._lock:
            data = self._read()
            if key in data:
                del data[key]
                self._write(data)
