from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from threading import Event

from .config import RETENTION_COUNT
from .models import RemoteFile
from .proton_cli import FinalListing, RemoteLayout


_INSTALLATION_ID = re.compile(r"^[0-9a-f]{32}$")
_REMOTE_UID = re.compile(r"^(?:[A-Za-z0-9_-]{1,128}|[A-Za-z0-9_=-]{1,108}~[A-Za-z0-9_=-]{1,108})$")
_OWNED_FINAL_NAME = re.compile(
    r"^ha-v1--(?P<installation>[0-9a-f]{32})--"
    r"(?P<timestamp>[0-9]{8}T[0-9]{6}Z)--"
    r"(?P<base>[a-z0-9][a-z0-9-]{0,47})--(?P<sha>[0-9a-f]{12})\.tar$"
)
_OWNED_PARENT = "/my-files/HomeAssistant-Backups"
_MAX_FILE_SIZE = 2**63 - 1


class _Client(Protocol):
    def list_final(self, layout: RemoteLayout) -> FinalListing: ...

    def permanently_delete_owned(
        self, remote: RemoteFile, layout: RemoteLayout
    ) -> None: ...


class _State(Protocol):
    def confirmed_remote_files(self) -> Mapping[str, RemoteFile]: ...


class _AmbiguousRemoteMetadata(ValueError):
    pass


@dataclass(frozen=True)
class RetentionResult:
    deleted: list[RemoteFile]
    error_code: str | None = None


class RetentionManager:
    def __init__(self, client: _Client, state: _State) -> None:
        self._client = client
        self._state = state

    def reconcile_after_success(
        self, layout: RemoteLayout, installation_id: str
    ) -> RetentionResult:
        if not _valid_scope(layout, installation_id):
            return RetentionResult([], "invalid_retention_scope")

        try:
            confirmed = self._state.confirmed_remote_files()
            if not isinstance(confirmed, Mapping):
                raise TypeError
            confirmed = dict(confirmed)
        except Exception:
            return RetentionResult([], "state_read_failed")

        try:
            listing_result = self._client.list_final(layout)
        except Exception:
            return RetentionResult([], "remote_listing_failed")
        if (
            type(listing_result) is not FinalListing
            or listing_result.complete is not True
            or not isinstance(listing_result.files, tuple)
        ):
            return RetentionResult([], "remote_listing_incomplete")
        listing = listing_result.files

        owned: list[tuple[datetime, RemoteFile]] = []
        for remote in listing:
            try:
                sort_time = _owned_timestamp(
                    remote, confirmed, installation_id, layout
                )
            except _AmbiguousRemoteMetadata:
                return RetentionResult([], "ambiguous_remote_metadata")
            if sort_time is not None:
                owned.append((sort_time, remote))

        owned_files = [remote for _, remote in owned]
        if (
            len({remote.uid for remote in owned_files}) != len(owned_files)
            or len({remote.name for remote in owned_files}) != len(owned_files)
            or len({remote.path for remote in owned_files}) != len(owned_files)
        ):
            return RetentionResult([], "ambiguous_remote_listing")

        owned.sort(key=lambda item: (item[0], item[1].name, item[1].uid))
        to_delete = [
            remote for _, remote in owned[: max(0, len(owned) - RETENTION_COUNT)]
        ]
        deleted: list[RemoteFile] = []
        for remote in to_delete:
            try:
                self._client.permanently_delete_owned(remote, layout)
            except Exception:
                return RetentionResult(deleted, "remote_delete_failed")
            deleted.append(remote)
        return RetentionResult(deleted)

    def reconcile_external(
        self,
        layout: RemoteLayout,
        installation_id: str,
        confirmed_files: tuple[RemoteFile, ...],
        *,
        cancel: Event,
    ) -> RetentionResult:
        """Reconcile using an immutable owner snapshot and cancellable I/O only."""
        if not isinstance(cancel, Event) or not isinstance(confirmed_files, tuple):
            return RetentionResult([], "state_read_failed")
        confirmed: dict[str, RemoteFile] = {}
        for remote in confirmed_files:
            if not isinstance(remote, RemoteFile) or remote.uid in confirmed:
                return RetentionResult([], "state_read_failed")
            confirmed[remote.uid] = remote
        if not _valid_scope(layout, installation_id):
            return RetentionResult([], "invalid_retention_scope")
        if cancel.is_set():
            return RetentionResult([], "remote_listing_failed")
        try:
            listing_result = self._client.list_final(layout, cancel=cancel)
        except Exception:
            return RetentionResult([], "remote_listing_failed")
        if (
            type(listing_result) is not FinalListing
            or listing_result.complete is not True
            or not isinstance(listing_result.files, tuple)
        ):
            return RetentionResult([], "remote_listing_incomplete")
        owned: list[tuple[datetime, RemoteFile]] = []
        for remote in listing_result.files:
            try:
                sort_time = _owned_timestamp(
                    remote, confirmed, installation_id, layout
                )
            except _AmbiguousRemoteMetadata:
                return RetentionResult([], "ambiguous_remote_metadata")
            if sort_time is not None:
                owned.append((sort_time, remote))
        owned_files = [remote for _, remote in owned]
        if (
            len({remote.uid for remote in owned_files}) != len(owned_files)
            or len({remote.name for remote in owned_files}) != len(owned_files)
            or len({remote.path for remote in owned_files}) != len(owned_files)
        ):
            return RetentionResult([], "ambiguous_remote_listing")
        owned.sort(key=lambda item: (item[0], item[1].name, item[1].uid))
        to_delete = [
            remote for _, remote in owned[: max(0, len(owned) - RETENTION_COUNT)]
        ]
        deleted: list[RemoteFile] = []
        for remote in to_delete:
            if cancel.is_set():
                return RetentionResult(deleted, "remote_delete_failed")
            try:
                self._client.permanently_delete_owned(
                    remote, layout, cancel=cancel
                )
            except Exception:
                return RetentionResult(deleted, "remote_delete_failed")
            deleted.append(remote)
        return RetentionResult(deleted)


def _valid_scope(layout: RemoteLayout, installation_id: str) -> bool:
    if (
        not isinstance(installation_id, str)
        or _INSTALLATION_ID.fullmatch(installation_id) is None
        or not isinstance(layout, RemoteLayout)
    ):
        return False
    root = f"{_OWNED_PARENT}/{installation_id}"
    return (
        layout.root == root
        and layout.incoming == f"{root}/incoming"
        and layout.final == f"{root}/backups"
        and layout.trash == "/trash"
    )


def _owned_timestamp(
    remote: object,
    confirmed: Mapping[str, RemoteFile],
    installation_id: str,
    layout: RemoteLayout,
) -> datetime | None:
    if not isinstance(remote, RemoteFile):
        return None
    if (
        not isinstance(remote.uid, str)
        or _REMOTE_UID.fullmatch(remote.uid) is None
        or not isinstance(remote.name, str)
        or not isinstance(remote.path, str)
        or isinstance(remote.size, bool)
        or not isinstance(remote.size, int)
        or remote.size < 0
        or remote.size > _MAX_FILE_SIZE
        or remote.path != f"{layout.final}/{remote.name}"
    ):
        return None
    match = _OWNED_FINAL_NAME.fullmatch(remote.name)
    if match is None or match.group("installation") != installation_id:
        return None
    base = match.group("base")
    if base.endswith("-") or "--" in base:
        return None
    try:
        timestamp = datetime.strptime(
            match.group("timestamp"), "%Y%m%dT%H%M%SZ"
        ).replace(tzinfo=UTC)
    except ValueError:
        return None
    confirmed_remote = confirmed.get(remote.uid)
    if not isinstance(confirmed_remote, RemoteFile):
        return None
    if (
        confirmed_remote.uid != remote.uid
        or confirmed_remote.name != remote.name
        or confirmed_remote.path != remote.path
        or confirmed_remote.size != remote.size
    ):
        return None
    if (
        not _is_strict_utc(remote.modified_at)
        or not _is_strict_utc(confirmed_remote.modified_at)
        or confirmed_remote.modified_at != remote.modified_at
    ):
        raise _AmbiguousRemoteMetadata
    return timestamp


def _is_strict_utc(value: object) -> bool:
    return type(value) is datetime and value.tzinfo is UTC
