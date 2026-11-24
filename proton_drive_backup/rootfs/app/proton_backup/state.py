from __future__ import annotations

import secrets
import sqlite3
import re
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import get_ident
from typing import Iterator

from .config import STABLE_OBSERVATIONS
from .models import BackupStatus, RemoteFile, StableBackup


SCHEMA_VERSION = 1
_INSTALLATION_ID = re.compile(r"^[a-f0-9]{32}$")
_CLAIM_ID = re.compile(r"^[a-f0-9]{32}$")
_ERROR_CODE = re.compile(r"^[a-z_]{1,64}$")
_UTC_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_TABLE_COLUMNS = {
    "metadata": ("key", "value"),
    "backups": ("sha256", "local_path", "display_name", "size", "mtime_ns", "status", "error_code", "retry_at", "uploaded_at", "attempt_count", "claim_id"),
    "remote_files": ("uid", "sha256", "name", "path", "size", "modified_at", "uploaded_at"),
    "observations": ("path", "size", "mtime_ns", "count", "seen_at"),
}


@dataclass(frozen=True)
class BackupClaim:
    backup: StableBackup
    claim_id: str
    attempt_count: int


@dataclass(frozen=True)
class QueueSnapshot:
    queue_size: int
    next_retry_at: datetime | None
    remote_files: tuple[RemoteFile, ...]
    retry_sha256: str | None = None


@dataclass(frozen=True)
class ObservationSnapshot:
    path: Path
    size: int
    mtime_ns: int
    count: int


@dataclass(frozen=True)
class ObservationUpdate:
    path: Path
    size: int
    mtime_ns: int
    reset: bool = False


class ClaimLostError(RuntimeError):
    """The durable upload claim is no longer owned by the caller."""


def _as_utc_iso(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _from_utc_iso(value: str | None) -> datetime | None:
    if value is None:
        return None
    _validate_timestamp(value)
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)


def _validate_timestamp(value: str) -> None:
    if _UTC_TIMESTAMP.fullmatch(value) is None:
        raise RuntimeError("state contains an invalid UTC timestamp")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as error:
        raise RuntimeError("state contains an invalid UTC timestamp") from error


class StateStore:
    """Durable, non-secret SQLite state for the backup queue."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._owner_id = get_ident()
        self._connection: sqlite3.Connection | None = None
        db_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._connection = sqlite3.connect(db_path, isolation_level=None)
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._initialize_schema()
        except sqlite3.DatabaseError as error:
            self.close()
            if self._is_corrupt_database(error):
                self._preserve_corrupt_database()
                raise RuntimeError("state database is corrupt and was preserved") from error
            raise
        except RuntimeError:
            self.close()
            raise

    @property
    def _db(self) -> sqlite3.Connection:
        self._assert_owner()
        if self._connection is None:
            raise RuntimeError("state store is closed")
        return self._connection

    def _assert_owner(self) -> None:
        if get_ident() != self._owner_id:
            raise RuntimeError("state store used outside owner thread")

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._db
        connection.execute("BEGIN IMMEDIATE")
        try:
            yield connection
        except BaseException:
            connection.rollback()
            raise
        else:
            connection.commit()

    def _initialize_schema(self) -> None:
        with self._transaction() as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
            if version not in (0, SCHEMA_VERSION):
                raise RuntimeError(f"unsupported state schema version: {version}")
            if version == SCHEMA_VERSION:
                self._validate_schema(connection, tables)
                self._validate_state(connection)
                return
            if tables:
                raise RuntimeError("unversioned state schema contains material tables")
            connection.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            connection.execute(
                "CREATE TABLE backups ("
                "sha256 TEXT PRIMARY KEY, local_path TEXT NOT NULL, display_name TEXT NOT NULL, "
                "size INTEGER NOT NULL, mtime_ns INTEGER NOT NULL, status TEXT NOT NULL, "
                "error_code TEXT, retry_at TEXT, uploaded_at TEXT, "
                "attempt_count INTEGER NOT NULL DEFAULT 0, claim_id TEXT)"
            )
            connection.execute(
                "CREATE TABLE remote_files ("
                "uid TEXT PRIMARY KEY, sha256 TEXT NOT NULL UNIQUE, name TEXT NOT NULL, path TEXT NOT NULL, "
                "size INTEGER NOT NULL, modified_at TEXT, uploaded_at TEXT NOT NULL, "
                "FOREIGN KEY (sha256) REFERENCES backups(sha256))"
            )
            connection.execute(
                "CREATE TABLE observations ("
                "path TEXT PRIMARY KEY, size INTEGER NOT NULL, mtime_ns INTEGER NOT NULL, "
                "count INTEGER NOT NULL, seen_at TEXT NOT NULL)"
            )
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    @staticmethod
    def _is_corrupt_database(error: sqlite3.DatabaseError) -> bool:
        return getattr(error, "sqlite_errorname", "") in {"SQLITE_CORRUPT", "SQLITE_NOTADB"}

    @staticmethod
    def _validate_schema(connection: sqlite3.Connection, tables: set[str]) -> None:
        if not set(_TABLE_COLUMNS).issubset(tables):
            raise RuntimeError("state schema is incomplete")
        for table, expected_columns in _TABLE_COLUMNS.items():
            actual_columns = tuple(row[1] for row in connection.execute(f"PRAGMA table_info({table})"))
            if actual_columns != expected_columns:
                raise RuntimeError(f"state schema for {table} is invalid")

    @staticmethod
    def _validate_state(connection: sqlite3.Connection) -> None:
        installation = connection.execute("SELECT value FROM metadata WHERE key = ?", ("installation_id",)).fetchone()
        if installation is not None and _INSTALLATION_ID.fullmatch(installation[0]) is None:
            raise RuntimeError("state contains an invalid installation ID")
        statuses = tuple(status.value for status in BackupStatus)
        placeholders = ", ".join("?" for _ in statuses)
        if connection.execute(f"SELECT 1 FROM backups WHERE status NOT IN ({placeholders}) LIMIT 1", statuses).fetchone() is not None:
            raise RuntimeError("state contains an invalid backup status")
        if connection.execute(
            "SELECT 1 FROM backups WHERE typeof(attempt_count) != 'integer' "
            "OR attempt_count < 0 LIMIT 1"
        ).fetchone() is not None:
            raise RuntimeError("state contains an invalid retry attempt count")
        claims = connection.execute(
            "SELECT status, claim_id FROM backups WHERE claim_id IS NOT NULL "
            "OR status IN (?, ?)",
            (BackupStatus.UPLOADING.value, BackupStatus.CONFIRMING.value),
        ).fetchall()
        if len(claims) > 1 or any(
            status not in {
                BackupStatus.UPLOADING.value,
                BackupStatus.CONFIRMING.value,
            }
            or not isinstance(claim_id, str)
            or _CLAIM_ID.fullmatch(claim_id) is None
            for status, claim_id in claims
        ):
            raise RuntimeError("state contains an invalid upload claim")
        for table, column in (("backups", "retry_at"), ("backups", "uploaded_at"), ("remote_files", "modified_at"), ("remote_files", "uploaded_at"), ("observations", "seen_at")):
            for (value,) in connection.execute(f"SELECT {column} FROM {table} WHERE {column} IS NOT NULL"):
                _validate_timestamp(value)

    def _preserve_corrupt_database(self) -> None:
        if self.db_path.exists():
            timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
            destination = self.db_path.with_name(f"{self.db_path.name}.corrupt-{timestamp}")
            if destination.exists():
                destination = self.db_path.with_name(f"{destination.name}-{secrets.token_hex(4)}")
            self.db_path.replace(destination)

    def installation_id(self) -> str:
        with self._transaction() as connection:
            row = connection.execute("SELECT value FROM metadata WHERE key = ?", ("installation_id",)).fetchone()
            if row is None:
                installation_id = secrets.token_hex(16)
                connection.execute("INSERT INTO metadata(key, value) VALUES (?, ?)", ("installation_id", installation_id))
                return installation_id
            return row[0]

    def observe(self, path: Path, size: int, mtime_ns: int, seen_at: datetime) -> bool:
        path_value = str(path)
        with self._transaction() as connection:
            row = connection.execute("SELECT size, mtime_ns, count FROM observations WHERE path = ?", (path_value,)).fetchone()
            count = row[2] + 1 if row is not None and row[0] == size and row[1] == mtime_ns else 1
            connection.execute(
                "INSERT INTO observations(path, size, mtime_ns, count, seen_at) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(path) DO UPDATE SET size = excluded.size, mtime_ns = excluded.mtime_ns, "
                "count = excluded.count, seen_at = excluded.seen_at",
                (path_value, size, mtime_ns, count, _as_utc_iso(seen_at)),
            )
            return count >= STABLE_OBSERVATIONS

    def observation_snapshot(self) -> tuple[ObservationSnapshot, ...]:
        rows = self._db.execute(
            "SELECT path, size, mtime_ns, count FROM observations ORDER BY path"
        ).fetchall()
        return tuple(
            ObservationSnapshot(Path(path), size, mtime_ns, count)
            for path, size, mtime_ns, count in rows
        )

    def apply_observation_batch(
        self,
        updates: tuple[ObservationUpdate, ...],
        backups: tuple[StableBackup, ...],
        seen_at: datetime,
    ) -> None:
        if not isinstance(updates, tuple) or any(
            type(update) is not ObservationUpdate
            or not isinstance(update.path, Path)
            or isinstance(update.size, bool)
            or not isinstance(update.size, int)
            or update.size < 0
            or isinstance(update.mtime_ns, bool)
            or not isinstance(update.mtime_ns, int)
            or update.mtime_ns < 0
            or type(update.reset) is not bool
            for update in updates
        ):
            raise ValueError("invalid scan observation batch")
        if len({update.path for update in updates}) != len(updates):
            raise ValueError("duplicate scan observation")
        if not isinstance(backups, tuple) or any(
            type(backup) is not StableBackup for backup in backups
        ):
            raise ValueError("invalid scan backup batch")
        update_by_path = {update.path: update for update in updates}
        if any(
            backup.local_path not in update_by_path
            or backup.size != update_by_path[backup.local_path].size
            or backup.mtime_ns != update_by_path[backup.local_path].mtime_ns
            for backup in backups
        ):
            raise ValueError("scan backup lacks matching observation")
        seen_at_iso = _as_utc_iso(seen_at)
        with self._transaction() as connection:
            counts: dict[Path, int] = {}
            for update in updates:
                row = connection.execute(
                    "SELECT size, mtime_ns, count FROM observations WHERE path = ?",
                    (str(update.path),),
                ).fetchone()
                count = (
                    row[2] + 1
                    if not update.reset
                    and row is not None
                    and row[0] == update.size
                    and row[1] == update.mtime_ns
                    else 1
                )
                counts[update.path] = count
                connection.execute(
                    "INSERT INTO observations(path, size, mtime_ns, count, seen_at) "
                    "VALUES (?, ?, ?, ?, ?) ON CONFLICT(path) DO UPDATE SET "
                    "size = excluded.size, mtime_ns = excluded.mtime_ns, "
                    "count = excluded.count, seen_at = excluded.seen_at",
                    (
                        str(update.path),
                        update.size,
                        update.mtime_ns,
                        count,
                        seen_at_iso,
                    ),
                )
            retained = {str(update.path) for update in updates}
            stale = tuple(
                (path,)
                for (path,) in connection.execute("SELECT path FROM observations")
                if path not in retained
            )
            connection.executemany(
                "DELETE FROM observations WHERE path = ?", stale
            )
            for backup in backups:
                if counts[backup.local_path] < STABLE_OBSERVATIONS:
                    continue
                connection.execute(
                    "INSERT INTO backups(sha256, local_path, display_name, size, "
                    "mtime_ns, status) VALUES (?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(sha256) DO NOTHING",
                    (
                        backup.sha256,
                        str(backup.local_path),
                        backup.display_name,
                        backup.size,
                        backup.mtime_ns,
                        BackupStatus.READY.value,
                    ),
                )

    def invalidate_observation(self, path: Path) -> None:
        with self._transaction() as connection:
            connection.execute("DELETE FROM observations WHERE path = ?", (str(path),))

    def retain_observations(self, paths: set[Path]) -> None:
        retained = {str(path) for path in paths}
        with self._transaction() as connection:
            stale = tuple(
                (path,)
                for (path,) in connection.execute("SELECT path FROM observations")
                if path not in retained
            )
            connection.executemany("DELETE FROM observations WHERE path = ?", stale)

    def enqueue(self, backup: StableBackup) -> None:
        with self._transaction() as connection:
            connection.execute(
                "INSERT INTO backups(sha256, local_path, display_name, size, mtime_ns, status) "
                "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(sha256) DO NOTHING",
                (backup.sha256, str(backup.local_path), backup.display_name, backup.size, backup.mtime_ns, BackupStatus.READY.value),
            )

    def next_ready(self, now: datetime) -> StableBackup | None:
        now_iso = _as_utc_iso(now)
        row = self._db.execute(
            "SELECT local_path, display_name, size, mtime_ns, sha256 FROM backups "
            "WHERE status = ? OR (status = ? AND retry_at <= ?) ORDER BY rowid LIMIT 1",
            (BackupStatus.READY.value, BackupStatus.RETRY_WAIT.value, now_iso),
        ).fetchone()
        return None if row is None else StableBackup(Path(row[0]), row[1], row[2], row[3], row[4])

    def claim_next(self, now: datetime, claim_id: str) -> BackupClaim | None:
        if not isinstance(claim_id, str) or _CLAIM_ID.fullmatch(claim_id) is None:
            raise ValueError("invalid claim identity")
        now_iso = _as_utc_iso(now)
        with self._transaction() as connection:
            if connection.execute(
                "SELECT 1 FROM backups WHERE status IN (?, ?) LIMIT 1",
                (BackupStatus.UPLOADING.value, BackupStatus.CONFIRMING.value),
            ).fetchone() is not None:
                return None
            row = connection.execute(
                "SELECT local_path, display_name, size, mtime_ns, sha256, status, attempt_count "
                "FROM backups WHERE status = ? OR (status = ? AND retry_at <= ?) "
                "ORDER BY rowid LIMIT 1",
                (BackupStatus.READY.value, BackupStatus.RETRY_WAIT.value, now_iso),
            ).fetchone()
            if row is None:
                return None
            result = connection.execute(
                "UPDATE backups SET status = ?, error_code = NULL, retry_at = NULL, claim_id = ? "
                "WHERE sha256 = ? AND status = ? AND attempt_count = ? "
                "AND NOT EXISTS (SELECT 1 FROM backups WHERE status IN (?, ?))",
                (
                    BackupStatus.UPLOADING.value,
                    claim_id,
                    row[4],
                    row[5],
                    row[6],
                    BackupStatus.UPLOADING.value,
                    BackupStatus.CONFIRMING.value,
                ),
            )
            if result.rowcount != 1:
                return None
            backup = StableBackup(Path(row[0]), row[1], row[2], row[3], row[4])
            return BackupClaim(backup, claim_id, row[6])

    def schedule_claim_retry(
        self,
        claim: BackupClaim,
        *,
        error_code: str,
        retry_at: datetime,
        increment_attempt: bool,
    ) -> None:
        self._validate_claim(claim)
        self._validate_error_code(error_code)
        with self._transaction() as connection:
            # CONFIRMING is accepted as well: every new attempt reconciles with
            # the final remote folder before uploading, so a failed or
            # cancelled upload may safely return to the retry queue.
            result = connection.execute(
                "UPDATE backups SET status = ?, error_code = ?, retry_at = ?, "
                "attempt_count = attempt_count + ?, claim_id = NULL "
                "WHERE sha256 = ? AND status IN (?, ?) AND claim_id = ? AND attempt_count = ?",
                (
                    BackupStatus.RETRY_WAIT.value,
                    error_code,
                    _as_utc_iso(retry_at),
                    1 if increment_attempt else 0,
                    claim.backup.sha256,
                    BackupStatus.UPLOADING.value,
                    BackupStatus.CONFIRMING.value,
                    claim.claim_id,
                    claim.attempt_count,
                ),
            )
            if result.rowcount != 1:
                raise ClaimLostError("upload claim is no longer owned")

    def release_claim(
        self,
        claim: BackupClaim,
        status: BackupStatus,
        *,
        error_code: str | None = None,
    ) -> None:
        self._validate_claim(claim)
        self._validate_error_code(error_code)
        if status not in {
            BackupStatus.READY,
            BackupStatus.AUTH_REQUIRED,
            BackupStatus.REMOTE_AMBIGUOUS,
        }:
            raise ValueError("invalid claim release status")
        with self._transaction() as connection:
            result = connection.execute(
                "UPDATE backups SET status = ?, error_code = ?, retry_at = NULL, claim_id = NULL "
                "WHERE sha256 = ? AND status IN (?, ?) AND claim_id = ? AND attempt_count = ?",
                (
                    status.value,
                    error_code,
                    claim.backup.sha256,
                    BackupStatus.UPLOADING.value,
                    BackupStatus.CONFIRMING.value,
                    claim.claim_id,
                    claim.attempt_count,
                ),
            )
            if result.rowcount != 1:
                raise ClaimLostError("upload claim is no longer owned")

    def mark_claim_confirming(self, claim: BackupClaim) -> None:
        self._validate_claim(claim)
        with self._transaction() as connection:
            result = connection.execute(
                "UPDATE backups SET status = ? WHERE sha256 = ? AND status = ? "
                "AND claim_id = ? AND attempt_count = ?",
                (
                    BackupStatus.CONFIRMING.value,
                    claim.backup.sha256,
                    BackupStatus.UPLOADING.value,
                    claim.claim_id,
                    claim.attempt_count,
                ),
            )
            if result.rowcount != 1:
                raise ClaimLostError("upload claim is no longer owned")

    def complete_claim(
        self,
        claim: BackupClaim,
        remote: RemoteFile,
        uploaded_at: datetime,
    ) -> None:
        self._validate_claim(claim)
        if type(remote) is not RemoteFile:
            raise ValueError("invalid confirmed remote file")
        uploaded_iso = _as_utc_iso(uploaded_at)
        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT sha256 FROM remote_files WHERE uid = ?", (remote.uid,)
            ).fetchone()
            if existing is not None and existing[0] != claim.backup.sha256:
                raise ValueError("remote UID is already associated with another backup")
            result = connection.execute(
                "UPDATE backups SET status = ?, uploaded_at = ?, retry_at = NULL, "
                "error_code = NULL, claim_id = NULL WHERE sha256 = ? AND status = ? "
                "AND claim_id = ? AND attempt_count = ?",
                (
                    BackupStatus.UPLOADED.value,
                    uploaded_iso,
                    claim.backup.sha256,
                    BackupStatus.CONFIRMING.value,
                    claim.claim_id,
                    claim.attempt_count,
                ),
            )
            if result.rowcount != 1:
                exact = self._exact_remote_row(connection, claim.backup.sha256, remote)
                if exact:
                    return
                raise ClaimLostError("upload claim is no longer owned")
            connection.execute(
                "INSERT INTO remote_files(uid, sha256, name, path, size, modified_at, uploaded_at) VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(uid) DO UPDATE SET name = excluded.name, path = excluded.path, size = excluded.size, "
                "modified_at = excluded.modified_at, uploaded_at = excluded.uploaded_at",
                (remote.uid, claim.backup.sha256, remote.name, remote.path, remote.size, _as_utc_iso(remote.modified_at) if remote.modified_at else None, uploaded_iso),
            )

    def confirmed_upload(self, sha256: str) -> RemoteFile | None:
        row = self._db.execute(
            "SELECT r.uid, r.name, r.path, r.size, r.modified_at FROM backups b "
            "JOIN remote_files r ON r.sha256 = b.sha256 WHERE b.sha256 = ? AND b.status = ?",
            (sha256, BackupStatus.UPLOADED.value),
        ).fetchone()
        return None if row is None else RemoteFile(row[0], row[1], row[2], row[3], _from_utc_iso(row[4]))

    @staticmethod
    def _exact_remote_row(
        connection: sqlite3.Connection, sha256: str, remote: RemoteFile
    ) -> bool:
        row = connection.execute(
            "SELECT r.uid, r.name, r.path, r.size, r.modified_at "
            "FROM backups b JOIN remote_files r ON r.sha256 = b.sha256 "
            "WHERE b.sha256 = ? AND b.status = ?",
            (sha256, BackupStatus.UPLOADED.value),
        ).fetchone()
        return row == (
            remote.uid,
            remote.name,
            remote.path,
            remote.size,
            _as_utc_iso(remote.modified_at) if remote.modified_at else None,
        )

    @staticmethod
    def _validate_claim(claim: BackupClaim) -> None:
        if (
            type(claim) is not BackupClaim
            or type(claim.backup) is not StableBackup
            or not isinstance(claim.claim_id, str)
            or _CLAIM_ID.fullmatch(claim.claim_id) is None
            or isinstance(claim.attempt_count, bool)
            or not isinstance(claim.attempt_count, int)
            or claim.attempt_count < 0
        ):
            raise ValueError("invalid upload claim")

    @staticmethod
    def _validate_error_code(error_code: str | None) -> None:
        if error_code is not None and (
            not isinstance(error_code, str)
            or _ERROR_CODE.fullmatch(error_code) is None
        ):
            raise ValueError("invalid safe error code")

    def mark_status(self, sha256: str, status: BackupStatus, *, error_code: str | None = None, retry_at: datetime | None = None) -> None:
        if status not in {
            BackupStatus.READY,
            BackupStatus.RETRY_WAIT,
            BackupStatus.AUTH_REQUIRED,
        }:
            raise ValueError("status transition requires a durable claim")
        self._validate_error_code(error_code)
        if (status == BackupStatus.RETRY_WAIT) != (retry_at is not None):
            raise ValueError("retry status requires one retry deadline")
        with self._transaction() as connection:
            result = connection.execute(
                "UPDATE backups SET status = ?, error_code = ?, retry_at = ?, claim_id = NULL "
                "WHERE sha256 = ? AND status IN (?, ?, ?)",
                (
                    status.value,
                    error_code,
                    _as_utc_iso(retry_at) if retry_at else None,
                    sha256,
                    BackupStatus.READY.value,
                    BackupStatus.RETRY_WAIT.value,
                    BackupStatus.AUTH_REQUIRED.value,
                ),
            )
            if result.rowcount != 1:
                raise KeyError(sha256)

    def mark_uploaded(self, sha256: str, remote: RemoteFile, uploaded_at: datetime) -> None:
        raise RuntimeError("upload completion requires a durable claim")

    def confirmed_remote_files(self) -> dict[str, RemoteFile]:
        rows = self._db.execute("SELECT uid, name, path, size, modified_at FROM remote_files ORDER BY uid").fetchall()
        return {row[0]: RemoteFile(row[0], row[1], row[2], row[3], _from_utc_iso(row[4])) for row in rows}

    def queue_snapshot(self) -> QueueSnapshot:
        queue_size = self._db.execute(
            "SELECT COUNT(*) FROM backups WHERE status != ?",
            (BackupStatus.UPLOADED.value,),
        ).fetchone()[0]
        row = self._db.execute(
            "SELECT sha256, retry_at FROM backups WHERE status = ? "
            "ORDER BY retry_at, sha256 LIMIT 1",
            (BackupStatus.RETRY_WAIT.value,),
        ).fetchone()
        remote_files = tuple(self.confirmed_remote_files().values())
        return QueueSnapshot(
            queue_size,
            _from_utc_iso(row[1]) if row and row[1] is not None else None,
            remote_files,
            row[0] if row is not None else None,
        )

    def forget_confirmed_remote_files(self, deleted: list[RemoteFile]) -> None:
        with self._transaction() as connection:
            for remote in deleted:
                if type(remote) is not RemoteFile:
                    raise ValueError("invalid confirmed remote file")
                result = connection.execute(
                    "DELETE FROM remote_files WHERE uid = ? AND name = ? AND path = ? "
                    "AND size = ? AND modified_at = ?",
                    (
                        remote.uid,
                        remote.name,
                        remote.path,
                        remote.size,
                        _as_utc_iso(remote.modified_at) if remote.modified_at else None,
                    ),
                )
                if result.rowcount != 1:
                    raise ValueError("confirmed remote file changed")

    def observed_paths(self) -> set[Path]:
        return {Path(row[0]) for row in self._db.execute("SELECT path FROM observations")}

    def status(self, sha256: str) -> BackupStatus | None:
        row = self._db.execute("SELECT status FROM backups WHERE sha256 = ?", (sha256,)).fetchone()
        return None if row is None else BackupStatus(row[0])

    def retry_now(self, sha256: str) -> None:
        with self._transaction() as connection:
            result = connection.execute(
                "UPDATE backups SET status = ?, error_code = NULL, retry_at = NULL, "
                "attempt_count = 0, claim_id = NULL WHERE sha256 = ? AND status = ?",
                (
                    BackupStatus.READY.value,
                    sha256,
                    BackupStatus.RETRY_WAIT.value,
                ),
            )
            if result.rowcount != 1:
                raise ValueError("backup cannot be retried")

    def recover_transient(self) -> int:
        """Make interrupted and parked rows claimable again at startup.

        UPLOADING/CONFIRMING rows were interrupted by a restart. REMOTE_AMBIGUOUS
        and AUTH_REQUIRED rows are re-evaluated once per start: the worker's
        preflight reconciles against the final folder (and re-checks the
        session) before any upload, so an existing final is never adopted solely by name.
        """
        with self._transaction() as connection:
            result = connection.execute(
                "UPDATE backups SET status = ?, retry_at = NULL, error_code = NULL, claim_id = NULL "
                "WHERE status IN (?, ?, ?, ?)",
                (
                    BackupStatus.READY.value,
                    BackupStatus.UPLOADING.value,
                    BackupStatus.CONFIRMING.value,
                    BackupStatus.REMOTE_AMBIGUOUS.value,
                    BackupStatus.AUTH_REQUIRED.value,
                ),
            )
            return result.rowcount

    def release_auth_required(self) -> int:
        """Requeue backups parked while no Proton session was available."""
        with self._transaction() as connection:
            result = connection.execute(
                "UPDATE backups SET status = ?, retry_at = NULL, error_code = NULL, claim_id = NULL "
                "WHERE status = ?",
                (BackupStatus.READY.value, BackupStatus.AUTH_REQUIRED.value),
            )
            return result.rowcount

    def close(self) -> None:
        self._assert_owner()
        if self._connection is not None:
            self._connection.close()
            self._connection = None
