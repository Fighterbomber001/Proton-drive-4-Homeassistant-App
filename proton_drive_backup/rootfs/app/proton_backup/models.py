from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path


class BackupStatus(StrEnum):
    OBSERVING = "observing"
    READY = "ready"
    UPLOADING = "uploading"
    CONFIRMING = "confirming"
    UPLOADED = "uploaded"
    RETRY_WAIT = "retry_wait"
    AUTH_REQUIRED = "auth_required"
    REMOTE_AMBIGUOUS = "remote_ambiguous"


@dataclass(frozen=True)
class StableBackup:
    local_path: Path
    display_name: str
    size: int
    mtime_ns: int
    sha256: str


@dataclass(frozen=True)
class RemoteFile:
    uid: str
    name: str
    path: str
    size: int
    modified_at: datetime | None


@dataclass(frozen=True)
class CommandResult:
    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    cancelled: bool = False
