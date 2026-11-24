from __future__ import annotations

import json
import logging
import posixpath
import re
import time
import math
import unicodedata
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from threading import Event, Lock
from typing import Protocol

from .config import PROCESS_TIMEOUT_SECONDS
from .events import EventLog
from .models import CommandResult, RemoteFile, StableBackup
from .process import ProtonLoginSecretEvent, ProcessExecutionError, ProcessRunner
from .redaction import SafeLogger


_CLI = "/usr/local/bin/proton-drive"
_INSTALLATION_ID = re.compile(r"^[0-9a-f]{32}$")
_TRANSFER_ID = re.compile(r"^[0-9a-f]{32}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REMOTE_UID = re.compile(r"^(?:[A-Za-z0-9_-]{1,128}|[A-Za-z0-9_=-]{1,108}~[A-Za-z0-9_=-]{1,108})$")
_OWNED_FINAL_NAME = re.compile(
    r"^ha-v1--(?P<installation>[0-9a-f]{32})--"
    r"(?P<timestamp>[0-9]{8}T[0-9]{6}Z)--"
    r"(?P<base>[a-z0-9][a-z0-9-]{0,47})--(?P<sha>[0-9a-f]{12})\.tar$"
)
_NODE_KEYS = frozenset({"uid", "name", "path", "type", "size", "modified_at"})
_LOGIN_URL_TTL_SECONDS = 120
_LOGIN_TIMEOUT_SECONDS = 120
_LOGIN_CLEANUP_TIMEOUT_SECONDS = 15.0
_JSON_MAX_CHARS = 2_097_152
_JSON_MAX_BYTES = 2_097_152
_JSON_MAX_ITEMS = 1_024
_JSON_MAX_OBJECT_ITEMS = 64
_JSON_MAX_TOTAL_NODES = 65_536
_JSON_MAX_DEPTH = 32
_JSON_MAX_STRING_CHARS = 4_096
_JSON_MAX_KEY_CHARS = 128
_JSON_MAX_NUMBER_CHARS = 64
_MAX_FILE_SIZE = 2**63 - 1
_JSON_MIN_INTEGER = -(2**63)
_JSON_MAX_FLOAT_ABS = 1e308
_MAX_MTIME_NS = 253_402_300_799_999_999_999
_MAX_NAME_CHARS = 255
_MAX_TIMESTAMP_CHARS = 32
_OWNED_PARENT = "/my-files/HomeAssistant-Backups"


class ProtonCliError(RuntimeError):
    """A neutral adapter error that contains no CLI output or remote path."""


class ProtonCliCancelled(ProtonCliError):
    pass


class ProtonProcessTimeout(ProtonCliError):
    pass


class ProtonNetworkError(ProtonCliError):
    pass


class ProtonAuthenticationRequired(ProtonCliError):
    pass


class ProtonRemoteConflict(ProtonCliError):
    """The final folder holds this backup's exact name with other metadata."""


class TransferControl(Event):
    """Cancellation event that closes atomically on confirmed upload success."""

    def __init__(self) -> None:
        super().__init__()
        self._control_lock = Lock()
        self._accepting_cancel = True

    def request_cancel(self) -> bool:
        with self._control_lock:
            if not self._accepting_cancel or self.is_set():
                return False
            self.set()
            return True

    def mark_success(self) -> bool:
        with self._control_lock:
            if self.is_set():
                return False
            self._accepting_cancel = False
            return True

    @property
    def accepting_cancel(self) -> bool:
        with self._control_lock:
            return self._accepting_cancel and not self.is_set()


class LoginInProgressError(ProtonCliError):
    pass


@dataclass(frozen=True)
class RemoteLayout:
    root: str
    incoming: str
    final: str
    trash: str = "/trash"


@dataclass(frozen=True)
class FinalListing:
    files: tuple[RemoteFile, ...]
    complete: bool


@dataclass(frozen=True)
class _Node:
    remote: RemoteFile
    kind: str

    @property
    def uid(self) -> str:
        return self.remote.uid

    @property
    def name(self) -> str:
        return self.remote.name

    @property
    def path(self) -> str:
        return self.remote.path


    @property
    def size(self) -> int:
        return self.remote.size


class _Runner(Protocol):
    def run(
        self,
        args: Sequence[str],
        *,
        timeout: float,
        cancel: Event,
        on_stdout_line=None,
        secret_event: ProtonLoginSecretEvent | None = None,
    ) -> CommandResult: ...


class _CredentialStore(Protocol):
    def remove(self) -> None: ...


class ProtonDriveClient:
    def __init__(
        self,
        *,
        runner: _Runner | None = None,
        executable: str = _CLI,
        transfer_id_factory: Callable[[], str] | None = None,
        logger: SafeLogger | None = None,
        credential_store: _CredentialStore | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        login_url_ttl: int = _LOGIN_URL_TTL_SECONDS,
        login_cleanup_timeout: float = _LOGIN_CLEANUP_TIMEOUT_SECONDS,
    ):
        if not isinstance(executable, str) or not executable or "\0" in executable:
            raise ValueError("Invalid Proton Drive executable")
        if (
            isinstance(login_url_ttl, bool)
            or not isinstance(login_url_ttl, int)
            or login_url_ttl <= 0
            or login_url_ttl > _LOGIN_URL_TTL_SECONDS
        ):
            raise ValueError("Invalid login URL lifetime")
        if (
            isinstance(login_cleanup_timeout, bool)
            or not isinstance(login_cleanup_timeout, (int, float))
            or login_cleanup_timeout <= 0
            or login_cleanup_timeout > _LOGIN_CLEANUP_TIMEOUT_SECONDS
        ):
            raise ValueError("Invalid login cleanup timeout")
        self._runner = runner or ProcessRunner()
        self._executable = executable
        self._transfer_id_factory = transfer_id_factory or (lambda: uuid.uuid4().hex)
        self._logger = logger or SafeLogger(logging.getLogger(__name__))
        self._credential_store = credential_store
        self._monotonic = monotonic
        self._login_url_ttl = login_url_ttl
        self._login_cleanup_timeout = float(login_cleanup_timeout)
        self._login_lock = Lock()
        self._login_active = False
        self._login_cancel: Event | None = None
        self._login_done = Event()
        self._login_done.set()

    def is_authenticated(
        self,
        *,
        cancel: Event | None = None,
        deadline: float | None = None,
    ) -> bool:
        result = self._run(
            ("filesystem", "list", "/my-files", "--json"),
            cancel=cancel,
            deadline=deadline,
        )
        if result.cancelled:
            raise ProtonCliCancelled("Authentication check was cancelled")
        if result.timed_out:
            raise ProtonProcessTimeout("Authentication check timed out")
        if result.returncode != 0:
            return False
        self._parse_list(result.stdout, expected_parent="/my-files")
        return True

    def start_login(
        self,
        on_url: Callable[[str], None],
        cancel: Event,
        *,
        deadline: float | None = None,
    ) -> None:
        if not callable(on_url) or not isinstance(cancel, Event):
            raise ValueError("Invalid login request")
        with self._login_lock:
            if self._login_active:
                raise LoginInProgressError("A login attempt is already active")
            self._login_active = True
            self._login_cancel = cancel
            self._login_done.clear()

        now = self._monotonic()
        if (
            deadline is not None
            and (
                isinstance(deadline, bool)
                or not isinstance(deadline, (int, float))
                or not math.isfinite(deadline)
                or deadline > now + _LOGIN_TIMEOUT_SECONDS
            )
        ):
            with self._login_lock:
                self._login_active = False
                self._login_cancel = None
                self._login_done.set()
            raise ValueError("Invalid login deadline")
        expires_at = min(
            now + self._login_url_ttl,
            deadline if deadline is not None else now + self._login_url_ttl,
        )
        if expires_at <= now:
            with self._login_lock:
                self._login_active = False
                self._login_cancel = None
                self._login_done.set()
            raise ProtonCliError("Browser login deadline expired")

        events = EventLog(logger=self._logger)

        def deliver_url(url: str) -> None:
            on_url(url)
            events.record("auth_login_link_ready")

        channel = ProtonLoginSecretEvent(
            deliver_url,
            expires_at=expires_at,
            monotonic=self._monotonic,
        )
        events.record("auth_login_started")
        try:
            try:
                remaining = min(
                    float(_LOGIN_TIMEOUT_SECONDS),
                    expires_at - self._monotonic(),
                )
                if remaining <= 0:
                    raise ProtonCliError("Browser login deadline expired")
                result = self._runner.run(
                    self._command("auth", "login"),
                    timeout=remaining,
                    cancel=cancel,
                    secret_event=channel,
                )
            except ProcessExecutionError as error:
                events.auth_process_failure(
                    failure_kind=error.failure_kind, exit_code=error.exit_code,
                    stdout_seen=error.stdout_seen, stderr_seen=error.stderr_seen,
                    stderr_hint=error.stderr_hint,
                )
                raise ProtonCliError("Unable to complete browser login") from None
            if result.cancelled:
                raise ProtonCliCancelled("Browser login was cancelled")
            if result.timed_out or result.returncode != 0:
                raise ProtonCliError("Unable to complete browser login")
            events.record("auth_login_finished")
        except Exception:
            events.record("auth_login_failed")
            raise
        finally:
            with self._login_lock:
                self._login_active = False
                self._login_cancel = None
                self._login_done.set()

    def logout(self, *, cancel: Event, deadline: float | None = None) -> None:
        if not isinstance(cancel, Event):
            raise ValueError("Invalid logout cancellation")
        failed = False
        with self._login_lock:
            active_cancel = self._login_cancel
            login_done = self._login_done
        if active_cancel is not None:
            active_cancel.set()
            if not login_done.wait(self._login_cleanup_timeout):
                failed = True

        try:
            result = self._run(
                ("auth", "logout"), cancel=cancel, deadline=deadline
            )
        except Exception:
            result = None
            failed = True
        if result is not None and (
            result.returncode != 0 or result.timed_out or result.cancelled
        ):
            failed = True
        if self._credential_store is not None:
            try:
                self._credential_store.remove()
            except Exception:
                failed = True
        if failed:
            raise ProtonCliError("Unable to disconnect Proton Drive")

    def ensure_layout(
        self, installation_id: str, *, cancel: Event | None = None
    ) -> RemoteLayout:
        if not isinstance(installation_id, str) or not _INSTALLATION_ID.fullmatch(
            installation_id
        ):
            raise ProtonCliError("Invalid installation identity")
        self._ensure_folder("/my-files", "HomeAssistant-Backups", cancel=cancel)
        self._ensure_folder(_OWNED_PARENT, installation_id, cancel=cancel)
        root = f"{_OWNED_PARENT}/{installation_id}"
        self._ensure_folder(root, "incoming", cancel=cancel)
        self._ensure_folder(root, "backups", cancel=cancel)
        return RemoteLayout(root, f"{root}/incoming", f"{root}/backups")

    def upload_and_finalize(
        self,
        backup: StableBackup,
        layout: RemoteLayout,
        cancel: Event,
    ) -> RemoteFile:
        installation_id = _validate_layout(layout)
        local_path = _validate_backup(backup)
        transfer_id = self._transfer_id_factory()
        if not isinstance(transfer_id, str) or not _TRANSFER_ID.fullmatch(transfer_id):
            raise ProtonCliError("Unable to create transfer identity")
        transfer_folder = f"{layout.incoming}/{transfer_id}"
        created = self._run_node(
            (
                "filesystem",
                "create-folder",
                layout.incoming,
                transfer_id,
                "--json",
            ),
            cancel=cancel,
        )
        _require_folder(created, transfer_folder, transfer_id)

        uploaded = self._run_node(
            (
                "filesystem",
                "upload",
                local_path,
                transfer_folder,
                "--conflict-strategy",
                "skip",
                "--skip-thumbnails",
                "--json",
            ),
            cancel=cancel,
        )
        expected_uploaded_path = f"{transfer_folder}/{backup.local_path.name}"
        _require_file(uploaded, expected_uploaded_path, backup.local_path.name)
        if uploaded.size != backup.size:
            raise ProtonCliError("Uploaded file could not be verified")

        safe_name = _final_name(backup, installation_id)
        renamed = self._run_node(
            (
                "filesystem",
                "rename",
                uploaded.path,
                safe_name,
                "--json",
            ),
            cancel=cancel,
        )
        renamed_path = f"{transfer_folder}/{safe_name}"
        _require_file(renamed, renamed_path, safe_name)

        moved = self._run_node(
            ("filesystem", "move", renamed.path, layout.final, "--json"),
            cancel=cancel,
        )
        final_path = f"{layout.final}/{safe_name}"
        _require_file(moved, final_path, safe_name)

        confirmed = self._run_node(
            ("filesystem", "info", final_path, "--json"),
            cancel=cancel,
        )
        _require_file(confirmed, final_path, safe_name)
        if confirmed.size != backup.size or confirmed.uid != uploaded.uid:
            raise ProtonCliError("Uploaded file could not be verified")
        remote = validate_upload_result(confirmed.remote, backup, layout)
        if isinstance(cancel, TransferControl) and not cancel.mark_success():
            raise ProtonCliCancelled("Proton Drive command was cancelled")
        return remote

    def list_final(
        self, layout: RemoteLayout, *, cancel: Event | None = None
    ) -> FinalListing:
        _validate_layout(layout)
        result = self._run_json(
            ("filesystem", "list", layout.final, "--json"), cancel=cancel
        )
        nodes = self._parse_list(result.stdout, expected_parent=layout.final)
        if any(node.name in (".", "..") for node in nodes):
            raise ProtonCliError("Unable to validate remote listing")
        if any(node.kind != "file" for node in nodes):
            raise ProtonCliError("Unable to validate remote listing")
        return FinalListing(tuple(node.remote for node in nodes), complete=True)

    def find_final(
        self,
        backup: StableBackup,
        layout: RemoteLayout,
        *,
        cancel: Event | None = None,
    ) -> RemoteFile | None:
        """Locate a possible name collision; a match does not prove ownership."""
        installation_id = _validate_layout(layout)
        _validate_backup(backup)
        expected = _final_name(backup, installation_id)
        listing = self.list_final(layout, cancel=cancel)
        if type(listing) is not FinalListing or listing.complete is not True or type(listing.files) is not tuple:
            raise ProtonRemoteConflict("Final backup listing is incomplete")
        matches = [item for item in listing.files if item.name == expected]
        if not matches:
            return None
        if len(matches) != 1:
            raise ProtonRemoteConflict("Final backup name is ambiguous")
        try:
            return validate_upload_result(matches[0], backup, layout)
        except ProtonCliError:
            raise ProtonRemoteConflict("Final backup name is ambiguous") from None

    def permanently_delete_owned(
        self,
        remote: RemoteFile,
        layout: RemoteLayout,
        *,
        cancel: Event | None = None,
    ) -> None:
        installation_id = _validate_layout(layout)
        if not isinstance(remote, RemoteFile):
            raise ProtonCliError("Remote file is not owned")
        _validate_remote_file(remote)
        expected_path = f"{layout.final}/{remote.name}"
        _validate_owned_final_name(remote.name, installation_id)
        if remote.path != expected_path:
            raise ProtonCliError("Remote file is not owned")

        observed = self._run_node(
            ("filesystem", "info", remote.path, "--json"), cancel=cancel
        )
        if getattr(self, "_sdk_json", False):
            # 0.7.0 resolves trash entries by decrypted name even when the
            # supplied argument looks like a UID. Do not mutate the remote
            # object until an atomic UID-bound delete is actually available.
            raise ProtonCliError("Safe permanent deletion is not supported by CLI 0.7.0")
        _require_file(observed, remote.path, remote.name)
        if (
            not _is_strict_utc_metadata(observed.remote.modified_at)
            or observed.remote != remote
        ):
            raise ProtonCliError("Remote file is not owned")
        trashed = self._run_node(
            ("filesystem", "trash", remote.path, "--json"), cancel=cancel
        )
        _require_file(trashed, trashed.path, remote.name)
        if (
            trashed.uid != remote.uid
            or trashed.name != remote.name
            or trashed.size != remote.size
            or not _is_strict_utc_metadata(trashed.remote.modified_at)
            or trashed.remote.modified_at != remote.modified_at
            or not _is_unique_trash_path(trashed.path, layout.trash, remote.name)
        ):
            raise ProtonCliError("Trashed file could not be verified")
        trash_result = self._run_json(
            ("filesystem", "list", layout.trash, "--json"), cancel=cancel
        )
        trash_nodes = self._parse_list(trash_result.stdout)
        trash_matches = [
            node
            for node in trash_nodes
            if node.kind == "file"
            and node.uid == remote.uid
            and node.name == remote.name
            and node.size == remote.size
            and _is_strict_utc_metadata(node.remote.modified_at)
            and node.remote.modified_at == remote.modified_at
            and _is_unique_trash_path(
                node.path, layout.trash, remote.name
            )
        ]
        if len(trash_matches) != 1:
            raise ProtonCliError("Trashed file could not be verified")
        confirmed_trash = trash_matches[0]
        _require_file(confirmed_trash, trashed.path, remote.name)
        delete_result = self._run_json(
            ("filesystem", "delete", confirmed_trash.path, "--json"),
            cancel=cancel,
        )
        delete_value = _load_json(delete_result.stdout)
        if isinstance(delete_value, list):
            if _operation_uid(delete_value) != confirmed_trash.uid:
                raise ProtonCliError("Deleted file could not be verified")
            return
        deleted = _parse_node_value(delete_value)
        _require_file(deleted, confirmed_trash.path, remote.name)
        if (
            not _is_strict_utc_metadata(deleted.remote.modified_at)
            or deleted.remote != confirmed_trash.remote
        ):
            raise ProtonCliError("Deleted file could not be verified")

    def _ensure_folder(
        self, parent: str, name: str, *, cancel: Event | None = None
    ) -> _Node:
        result = self._run_json(
            ("filesystem", "list", parent, "--json"), cancel=cancel
        )
        items = self._parse_list(result.stdout, expected_parent=parent)
        matches = [item for item in items if item.name == name]
        expected_path = f"{parent}/{name}"
        if len(matches) > 1:
            raise ProtonCliError("Remote folder state is ambiguous")
        if matches:
            _require_folder(matches[0], expected_path, name)
            return matches[0]
        created = self._run_node(
            ("filesystem", "create-folder", parent, name, "--json"),
            cancel=cancel,
        )
        _require_folder(created, expected_path, name)
        return created

    def _command(self, *arguments: str) -> tuple[str, ...]:
        if any(not isinstance(value, str) or "\0" in value for value in arguments):
            raise ProtonCliError("Invalid CLI arguments")
        return (self._executable, *arguments)

    def _run(
        self,
        arguments: Sequence[str],
        *,
        cancel: Event | None = None,
        deadline: float | None = None,
    ) -> CommandResult:
        timeout = PROCESS_TIMEOUT_SECONDS
        if deadline is not None:
            now = self._monotonic()
            if (
                isinstance(deadline, bool)
                or not isinstance(deadline, (int, float))
                or not math.isfinite(deadline)
                or deadline > now + _LOGIN_TIMEOUT_SECONDS
            ):
                raise ProtonCliError("Invalid login deadline")
            timeout = min(float(PROCESS_TIMEOUT_SECONDS), deadline - now)
            if timeout <= 0:
                raise ProtonProcessTimeout("Authentication deadline expired")
        try:
            return self._runner.run(
                self._command(*arguments),
                timeout=timeout,
                cancel=cancel or Event(),
            )
        except ConnectionError:
            raise ProtonNetworkError("Proton Drive network is unavailable") from None
        except TimeoutError:
            raise ProtonProcessTimeout("Proton Drive command timed out") from None
        except ProcessExecutionError:
            raise ProtonCliError("Proton Drive command failed") from None

    def _run_json(
        self,
        arguments: Sequence[str],
        *,
        cancel: Event | None = None,
    ) -> CommandResult:
        result = self._run(arguments, cancel=cancel)
        if result.cancelled:
            raise ProtonCliCancelled("Proton Drive command was cancelled")
        if result.timed_out:
            raise ProtonProcessTimeout("Proton Drive command timed out")
        if result.returncode != 0:
            raise ProtonCliError("Proton Drive command failed")
        return result

    def _run_node(
        self,
        arguments: Sequence[str],
        *,
        cancel: Event | None = None,
    ) -> _Node:
        value = _load_json(self._run_json(arguments, cancel=cancel).stdout)
        if isinstance(value, dict) and frozenset(value) == _NODE_KEYS:
            return _parse_node_value(value)
        self._sdk_json = True
        operation = arguments[1]
        if operation == "upload":
            if (
                not isinstance(value, dict)
                or set(value) != {"transferredItems", "transferredBytes", "skippedItems", "failedItems", "failures"}
                or type(value["transferredItems"]) is not int or value["transferredItems"] != 1
                or type(value["transferredBytes"]) is not int or value["transferredBytes"] < 0
                or type(value["skippedItems"]) is not int or value["skippedItems"] != 0
                or type(value["failedItems"]) is not int or value["failedItems"] != 0
                or value["failures"] != []
            ):
                raise ProtonCliError("Uploaded file could not be verified")
            path = f"{arguments[3]}/{PurePosixPath(arguments[2]).name}"
            observed = self._run_node(("filesystem", "info", path, "--json"), cancel=cancel)
            if observed.size != value["transferredBytes"]:
                raise ProtonCliError("Uploaded file could not be verified")
            return observed
        if operation in {"move", "trash"}:
            uid = _operation_uid(value)
            if operation == "move":
                path = f"{arguments[3]}/{posixpath.basename(arguments[2])}"
                observed = self._run_node(("filesystem", "info", path, "--json"), cancel=cancel)
                if observed.uid != uid:
                    raise ProtonCliError("Moved file could not be verified")
                return observed
            listing = self._run_json(("filesystem", "list", "/trash", "--json"), cancel=cancel)
            matches = [node for node in self._parse_list(listing.stdout) if node.uid == uid]
            if len(matches) != 1:
                raise ProtonCliError("Trashed file could not be verified")
            return matches[0]
        if operation == "create-folder":
            path = f"{arguments[2]}/{arguments[3]}"
        elif operation == "rename":
            path = f"{posixpath.dirname(arguments[2])}/{arguments[3]}"
        elif operation == "info":
            path = arguments[2]
        else:
            raise ProtonCliError("Unable to validate Proton Drive response")
        return _parse_sdk_node(value, path)

    @staticmethod
    def _parse_list(output: str, expected_parent: str | None = None) -> list[_Node]:
        value = _load_json(output)
        if not isinstance(value, list) or len(value) > _JSON_MAX_ITEMS:
            raise ProtonCliError("Unable to validate remote listing")
        items = []
        for item in value:
            if isinstance(item, dict) and isinstance(item.get("name"), dict):
                parent = expected_parent or "/trash"
                name = _sdk_name(item)
                if parent == "/trash":
                    path = f"/trash/{item.get('uid', '')}/{name}"
                else:
                    path = f"{parent}/{name}"
                items.append(_parse_sdk_node(item, path))
            else:
                items.append(_parse_node_value(item))
        if len({item.uid for item in items}) != len(items) or len(
            {item.path for item in items}
        ) != len(items):
            raise ProtonCliError("Unable to validate remote listing")
        if expected_parent is not None and any(
            posixpath.dirname(item.path) != expected_parent for item in items
        ):
            raise ProtonCliError("Unable to validate remote listing")
        return items


def _load_json(output: str):
    if not isinstance(output, str) or not output or len(output) > _JSON_MAX_CHARS:
        raise ProtonCliError("Unable to validate Proton Drive response")
    try:
        if len(output.encode("utf-8", errors="strict")) > _JSON_MAX_BYTES:
            raise _JsonBoundaryError
        value = json.loads(
            output,
            object_pairs_hook=_unique_object,
            parse_int=_parse_json_int,
            parse_float=_parse_json_float,
            parse_constant=_reject_json_constant,
        )
        _validate_json_value(value, depth=0, nodes=[0])
        return value
    except (
        json.JSONDecodeError,
        ValueError,
        TypeError,
        OverflowError,
        RecursionError,
    ):
        raise ProtonCliError("Unable to validate Proton Drive response") from None


class _JsonBoundaryError(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    if not isinstance(pairs, list) or len(pairs) > _JSON_MAX_OBJECT_ITEMS:
        raise _JsonBoundaryError
    result: dict[str, object] = {}
    for key, value in pairs:
        if (
            not isinstance(key, str)
            or not key
            or len(key) > _JSON_MAX_KEY_CHARS
            or key in result
        ):
            raise _JsonBoundaryError
        result[key] = value
    return result


def _parse_json_int(value: str) -> int:
    if not isinstance(value, str) or len(value) > _JSON_MAX_NUMBER_CHARS:
        raise _JsonBoundaryError
    digits = value[1:] if value.startswith("-") else value
    if not digits or len(digits) > 19 or not digits.isascii() or not digits.isdigit():
        raise _JsonBoundaryError
    parsed = int(value)
    if parsed < _JSON_MIN_INTEGER or parsed > _MAX_FILE_SIZE:
        raise _JsonBoundaryError
    return parsed


def _parse_json_float(value: str) -> float:
    if not isinstance(value, str) or len(value) > _JSON_MAX_NUMBER_CHARS:
        raise _JsonBoundaryError
    parsed = float(value)
    if not math.isfinite(parsed) or abs(parsed) > _JSON_MAX_FLOAT_ABS:
        raise _JsonBoundaryError
    return parsed


def _reject_json_constant(value: str):
    raise _JsonBoundaryError


def _validate_json_value(value: object, *, depth: int, nodes: list[int]) -> None:
    if depth > _JSON_MAX_DEPTH:
        raise _JsonBoundaryError
    nodes[0] += 1
    if nodes[0] > _JSON_MAX_TOTAL_NODES:
        raise _JsonBoundaryError
    if value is None or isinstance(value, bool):
        return
    if type(value) is int:
        if value < _JSON_MIN_INTEGER or value > _MAX_FILE_SIZE:
            raise _JsonBoundaryError
        return
    if type(value) is float:
        if not math.isfinite(value) or abs(value) > _JSON_MAX_FLOAT_ABS:
            raise _JsonBoundaryError
        return
    if isinstance(value, str):
        if len(value) > _JSON_MAX_STRING_CHARS:
            raise _JsonBoundaryError
        return
    if isinstance(value, list):
        if len(value) > _JSON_MAX_ITEMS:
            raise _JsonBoundaryError
        for item in value:
            _validate_json_value(item, depth=depth + 1, nodes=nodes)
        return
    if isinstance(value, dict):
        if len(value) > _JSON_MAX_OBJECT_ITEMS:
            raise _JsonBoundaryError
        for key, item in value.items():
            if (
                not isinstance(key, str)
                or not key
                or len(key) > _JSON_MAX_KEY_CHARS
            ):
                raise _JsonBoundaryError
            _validate_json_value(item, depth=depth + 1, nodes=nodes)
        return
    raise _JsonBoundaryError


def _operation_uid(value: object) -> str:
    if not isinstance(value, list) or len(value) != 1:
        raise ProtonCliError("Unable to validate operation result")
    item = value[0]
    if (not isinstance(item, dict) or set(item) != {"uid", "ok"}
            or item["ok"] is not True or not isinstance(item["uid"], str)
            or _REMOTE_UID.fullmatch(item["uid"]) is None):
        raise ProtonCliError("Unable to validate operation result")
    return item["uid"]


def _sdk_name(value: dict) -> str:
    name = value.get("name")
    if not isinstance(name, dict) or name.get("ok") is not True or not isinstance(name.get("value"), str):
        raise ProtonCliError("Unable to validate decrypted node name")
    return name["value"]


def _parse_sdk_node(value: object, path: str) -> _Node:
    if not isinstance(value, dict) or value.get("errors"):
        raise ProtonCliError("Unable to validate Proton Drive response")
    kind = value.get("type")
    for field in ("nameAuthor", "keyAuthor"):
        author = value.get(field)
        if author is not None and (not isinstance(author, dict) or author.get("ok") is not True):
            raise ProtonCliError("Unable to validate node signature")
    size = 0
    if kind == "file":
        revision = value.get("activeRevision")
        if not isinstance(revision, dict) or "claimedSize" not in revision:
            raise ProtonCliError("Unable to validate file revision")
        size = revision["claimedSize"]
    return _parse_node_value({
        "uid": value.get("uid"), "name": _sdk_name(value), "path": path,
        "type": kind, "size": size, "modified_at": value.get("modificationTime"),
    })


def _parse_node(output: str) -> _Node:
    return _parse_node_value(_load_json(output))


def _parse_node_value(value: object) -> _Node:
    if not isinstance(value, dict) or frozenset(value) != _NODE_KEYS:
        raise ProtonCliError("Unable to validate Proton Drive response")
    uid = value["uid"]
    name = value["name"]
    path = value["path"]
    kind = value["type"]
    size = value["size"]
    modified_value = value["modified_at"]
    if not isinstance(uid, str) or not _REMOTE_UID.fullmatch(uid):
        raise ProtonCliError("Unable to validate Proton Drive response")
    if (
        not isinstance(name, str)
        or not name
        or len(name) > _MAX_NAME_CHARS
        or name in (".", "..")
        or "/" in name
        or "\\" in name
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        raise ProtonCliError("Unable to validate Proton Drive response")
    _validate_remote_path(path)
    if posixpath.basename(path) != name:
        raise ProtonCliError("Unable to validate Proton Drive response")
    if kind not in ("file", "folder"):
        raise ProtonCliError("Unable to validate Proton Drive response")
    if (
        isinstance(size, bool)
        or not isinstance(size, int)
        or size < 0
        or size > _MAX_FILE_SIZE
    ):
        raise ProtonCliError("Unable to validate Proton Drive response")
    modified_at = _parse_timestamp(modified_value)
    return _Node(RemoteFile(uid, name, path, size, modified_at), kind)


def _parse_timestamp(value: object) -> datetime | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or len(value) > _MAX_TIMESTAMP_CHARS
        or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{3}|\.[0-9]{6})?Z", value) is None
    ):
        raise ProtonCliError("Unable to validate Proton Drive response")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise ProtonCliError("Unable to validate Proton Drive response") from None
    if parsed.tzinfo != UTC:
        raise ProtonCliError("Unable to validate Proton Drive response")
    return parsed


def _validate_remote_path(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or value == "/"
        or len(value) > 4_096
        or "\\" in value
        or "\0" in value
        or "//" in value
        or value.endswith("/")
        or posixpath.normpath(value) != value
        or any(part in (".", "..", "") for part in value.split("/")[1:])
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ProtonCliError("Unable to validate remote path")
    return value


def _validate_layout(layout: RemoteLayout) -> str:
    if not isinstance(layout, RemoteLayout):
        raise ProtonCliError("Invalid remote layout")
    for path in (layout.root, layout.incoming, layout.final, layout.trash):
        _validate_remote_path(path)
    prefix = f"{_OWNED_PARENT}/"
    if not layout.root.startswith(prefix):
        raise ProtonCliError("Invalid remote layout")
    installation_id = layout.root[len(prefix) :]
    if not _INSTALLATION_ID.fullmatch(installation_id):
        raise ProtonCliError("Invalid remote layout")
    if (
        layout.incoming != f"{layout.root}/incoming"
        or layout.final != f"{layout.root}/backups"
        or layout.trash != "/trash"
    ):
        raise ProtonCliError("Invalid remote layout")
    return installation_id


def _validate_backup(backup: StableBackup) -> str:
    if not isinstance(backup, StableBackup) or not isinstance(backup.local_path, Path):
        raise ProtonCliError("Invalid local backup")
    path = str(backup.local_path).replace("\\", "/")
    pure_path = PurePosixPath(path)
    display_name = backup.display_name
    if (
        not path.startswith("/backup/")
        or pure_path.parent != PurePosixPath("/backup")
        or not isinstance(display_name, str)
        or not display_name.casefold().endswith(".tar")
        or not display_name
        or len(display_name) > _MAX_NAME_CHARS
        or display_name in (".", "..")
        or "/" in display_name
        or "\\" in display_name
        or any(ord(character) < 32 or ord(character) == 127 for character in display_name)
        or pure_path.name != display_name
        or "\0" in path
        or "//" in path
        or posixpath.normpath(path) != path
    ):
        raise ProtonCliError("Invalid local backup")
    if (
        isinstance(backup.size, bool)
        or not isinstance(backup.size, int)
        or backup.size < 0
        or backup.size > _MAX_FILE_SIZE
        or isinstance(backup.mtime_ns, bool)
        or not isinstance(backup.mtime_ns, int)
        or backup.mtime_ns < 0
        or backup.mtime_ns > _MAX_MTIME_NS
        or not isinstance(backup.sha256, str)
        or not _SHA256.fullmatch(backup.sha256)
    ):
        raise ProtonCliError("Invalid local backup")
    try:
        datetime.fromtimestamp(backup.mtime_ns // 1_000_000_000, UTC)
    except (OverflowError, OSError, ValueError):
        raise ProtonCliError("Invalid local backup") from None
    return path


def validate_upload_result(
    remote: object,
    backup: StableBackup,
    layout: RemoteLayout,
) -> RemoteFile:
    """Validate the exact confirmed remote identity returned for one upload."""
    if type(remote) is not RemoteFile:
        raise ProtonCliError("Uploaded file could not be verified")
    installation_id = _validate_layout(layout)
    _validate_backup(backup)
    _validate_remote_file(remote)
    expected_name = _final_name(backup, installation_id)
    if (
        remote.name != expected_name
        or remote.path != f"{layout.final}/{expected_name}"
        or remote.size != backup.size
    ):
        raise ProtonCliError("Uploaded file could not be verified")
    return remote


def _validate_remote_file(remote: RemoteFile) -> None:
    if (
        not isinstance(remote.uid, str)
        or not _REMOTE_UID.fullmatch(remote.uid)
        or not isinstance(remote.name, str)
        or not isinstance(remote.path, str)
    ):
        raise ProtonCliError("Remote file is not owned")
    _validate_remote_path(remote.path)
    if (
        not remote.name
        or posixpath.basename(remote.path) != remote.name
        or isinstance(remote.size, bool)
        or not isinstance(remote.size, int)
        or remote.size < 0
        or remote.size > _MAX_FILE_SIZE
        or not _is_strict_utc_metadata(remote.modified_at)
    ):
        raise ProtonCliError("Remote file is not owned")


def _is_strict_utc_metadata(value: object) -> bool:
    return type(value) is datetime and value.tzinfo is UTC


def _require_folder(remote: _Node, expected_path: str, expected_name: str) -> None:
    if (
        remote.kind != "folder"
        or remote.path != expected_path
        or remote.name != expected_name
    ):
        raise ProtonCliError("Remote folder could not be verified")


def _require_file(remote: _Node, expected_path: str, expected_name: str) -> None:
    if (
        remote.kind != "file"
        or remote.path != expected_path
        or remote.name != expected_name
    ):
        raise ProtonCliError("Remote file could not be verified")


def _validate_owned_final_name(name: str, installation_id: str) -> None:
    match = _OWNED_FINAL_NAME.fullmatch(name)
    if match is None or match.group("installation") != installation_id:
        raise ProtonCliError("Remote file is not owned")
    safe_base = match.group("base")
    if safe_base.endswith("-") or "--" in safe_base:
        raise ProtonCliError("Remote file is not owned")
    timestamp = match.group("timestamp")
    try:
        parsed = datetime.strptime(timestamp, "%Y%m%dT%H%M%SZ")
    except ValueError:
        raise ProtonCliError("Remote file is not owned") from None
    if parsed.strftime("%Y%m%dT%H%M%SZ") != timestamp:
        raise ProtonCliError("Remote file is not owned")


def _is_unique_trash_path(path: str, parent: str, name: str) -> bool:
    _validate_remote_path(path)
    _validate_remote_path(parent)
    prefix = f"{parent}/"
    if not path.startswith(prefix):
        return False
    parts = path[len(prefix) :].split("/")
    return len(parts) == 2 and bool(_REMOTE_UID.fullmatch(parts[0])) and parts[1] == name


def _final_name(backup: StableBackup, installation_id: str) -> str:
    timestamp = datetime.fromtimestamp(backup.mtime_ns // 1_000_000_000, UTC).strftime(
        "%Y%m%dT%H%M%SZ"
    )
    original = (
        backup.display_name[:-4]
        if backup.display_name.casefold().endswith(".tar")
        else backup.display_name
    )
    normalized = unicodedata.normalize("NFKD", original).encode("ascii", "ignore").decode()
    safe_base = re.sub(r"[^A-Za-z0-9]+", "-", normalized).strip("-").casefold()
    safe_base = safe_base[:48].rstrip("-") or "backup"
    return (
        f"ha-v1--{installation_id}--{timestamp}--{safe_base}--"
        f"{backup.sha256[:12]}.tar"
    )
