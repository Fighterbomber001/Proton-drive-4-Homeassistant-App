"""Bounded dashboard projection of Home Assistant's validated Proton metadata."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from .native_storage import NativeStorageError, validate_metadata


_LIMIT = 14
_REFRESH_INTERVAL_SECONDS = 5 * 60
NativeHistoryState = Literal["loading", "ready", "stale", "unavailable"]


@dataclass(frozen=True)
class NativeHistoryEntry:
    name: str
    size: int
    date: datetime


def project_backup(metadata: object) -> tuple[str, NativeHistoryEntry]:
    if type(metadata) is not dict:
        raise NativeStorageError()
    identity = metadata.get("backup_id")
    validate_metadata(identity, metadata)
    date = datetime.fromisoformat(metadata["date"])
    # Native metadata also accepts an ISO timestamp without an offset.
    date = date.replace(tzinfo=UTC) if date.tzinfo is None else date.astimezone(UTC)
    return identity, NativeHistoryEntry(metadata["name"], metadata["size"], date)


def project_inventory(inventory: object) -> dict[str, NativeHistoryEntry]:
    if type(inventory) is not list:
        raise NativeStorageError()
    return _newest(dict(project_backup(metadata) for metadata in inventory))


def _newest(records: dict[str, NativeHistoryEntry]) -> dict[str, NativeHistoryEntry]:
    return dict(sorted(records.items(), key=lambda record: (record[1].date, record[0]),
                       reverse=True)[:_LIMIT])


class NativeHistory:
    """Accessed only under the service lock; record identities are never exposed."""

    def __init__(self) -> None:
        self._records: dict[str, NativeHistoryEntry] = {}
        self._listed = False
        self.state: NativeHistoryState = "loading"
        self._next_refresh_at = 0.0

    @property
    def entries(self) -> tuple[NativeHistoryEntry, ...]:
        return tuple(self._records.values())

    def due(self, now: float) -> bool:
        return now >= self._next_refresh_at

    def defer_refresh(self, now: float) -> None:
        self._next_refresh_at = now + _REFRESH_INTERVAL_SECONDS

    def listed(self, records: dict[str, NativeHistoryEntry], now: float) -> None:
        self._records = records
        self._listed = True
        self.state = "ready"
        self.defer_refresh(now)

    def listing_failed(self, now: float) -> None:
        self.state = "stale" if self._listed or self._records else "unavailable"
        self.defer_refresh(now)

    def uploaded(self, record: tuple[str, NativeHistoryEntry]) -> None:
        identity, entry = record
        self._records[identity] = entry
        self._records = _newest(self._records)
        if not self._listed:
            self.state = "stale"
