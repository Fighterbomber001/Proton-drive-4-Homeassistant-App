from __future__ import annotations

import math
import random
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from threading import Event, Lock, RLock

from .config import PROCESS_TIMEOUT_SECONDS
from .models import BackupStatus, RemoteFile
from .native_history import NativeHistoryEntry, NativeHistoryState
from .proton_cli import (
    ProtonAuthenticationRequired,
    ProtonCliCancelled,
    ProtonCliError,
    ProtonNetworkError,
    ProtonProcessTimeout,
    ProtonRemoteConflict,
    RemoteLayout,
    TransferControl,
    validate_upload_result,
)
from .retention import RetentionResult
from .state import BackupClaim, QueueSnapshot


_MAX_RETRY_SECONDS = 60 * 60
_JITTER_FRACTION = 0.25
MAX_RETRY_REVISION = 9_007_199_254_740_991
_PROCESS_TRANSFER_GUARD = Lock()
_SAFE_RETENTION_ERROR_CODES = frozenset(
    {
        "invalid_retention_scope",
        "state_read_failed",
        "remote_listing_failed",
        "remote_listing_incomplete",
        "ambiguous_remote_metadata",
        "ambiguous_remote_listing",
        "remote_delete_failed",
    }
)


@dataclass(frozen=True)
class ServiceSnapshot:
    web_ready: bool
    connected: bool
    scanner_state: str
    active_sha256: str | None
    active_name: str | None
    active_started_at: datetime | None
    queue_size: int
    next_retry_at: datetime | None
    last_success_at: datetime | None
    last_error_code: str | None
    remote_files: tuple[RemoteFile, ...]
    retry_sha256: str | None = None
    retry_revision: int = 0
    native_mode: bool = False
    native_operation: str | None = None
    native_history_state: NativeHistoryState | None = None
    native_history: tuple[NativeHistoryEntry, ...] = ()


class ExternalPhase(StrEnum):
    PREFLIGHT = "preflight"
    UPLOAD = "upload"
    RETENTION = "retention"


class ExternalStatus(StrEnum):
    SUCCESS = "success"
    AUTH_REQUIRED = "auth_required"
    NETWORK_UNAVAILABLE = "network_unavailable"
    PROCESS_TIMEOUT = "process_timeout"
    CANCELLED = "cancelled"
    UPLOAD_FAILED = "upload_failed"
    REMOTE_AMBIGUOUS = "remote_ambiguous"


@dataclass(frozen=True)
class ExternalWork:
    generation: int
    phase: ExternalPhase
    claim: BackupClaim
    control: TransferControl
    lifetime_cancel: Event
    installation_id: str
    layout: RemoteLayout | None = None
    confirmed_remote_files: tuple[RemoteFile, ...] = ()


@dataclass(frozen=True)
class ExternalResult:
    work: ExternalWork
    status: ExternalStatus
    value: object | None = None


class BackupWorker:
    """Own one durable upload claim and serialize transfers process-wide."""

    def __init__(
        self,
        store,
        client,
        retention,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        monotonic: Callable[[], float] = time.monotonic,
        jitter: Callable[[float], float] = lambda window: random.uniform(0.0, window),
        claim_id_factory: Callable[[], str] = lambda: uuid.uuid4().hex,
        upload_validator: Callable[[object, object, object], RemoteFile] = validate_upload_result,
        event_log=None,
    ) -> None:
        self._store = store
        self._event_log = event_log
        self._client = client
        self._retention = retention
        self._clock = clock
        self._monotonic = monotonic
        self._jitter = jitter
        self._claim_id_factory = claim_id_factory
        self._upload_validator = upload_validator
        self._run_lock = Lock()
        self._state_lock = RLock()
        self._cancel: TransferControl | None = None
        self._lifetime_cancel: Event | None = None
        self._cancel_reason: str | None = None
        self._run_active = False
        self._restart_requested = False
        self._active_sha256: str | None = None
        self._active_name: str | None = None
        self._active_started_at: datetime | None = None
        self._active_started_monotonic: float | None = None
        self._connected = False
        self._queue_size = 0
        self._next_retry_at: datetime | None = None
        self._last_success_at: datetime | None = None
        self._last_error_code: str | None = None
        self._remote_files: tuple[RemoteFile, ...] = ()
        self._retry_sha256: str | None = None
        self._retry_revision = 0
        self._external_generation = 0
        self._external_work: ExternalWork | None = None
        self._authoritative_retry_identity: tuple[str | None, datetime | None] = (
            None,
            None,
        )
        self._refresh_queue_cache()

    def run_once(self, now: datetime) -> None:
        """Synchronous compatibility wrapper for the split external contract."""
        work = self.prepare_external(now)
        while work is not None:
            work = self.apply_external(self.execute_external(work))

    def prepare_external(self, now: datetime) -> ExternalWork | None:
        """Claim and prepare immutable work on the StateStore owner thread."""
        now = _as_utc(now)
        with self._state_lock:
            if self._external_work is not None:
                return None
        if not _PROCESS_TRANSFER_GUARD.acquire(blocking=False):
            return None
        if not self._run_lock.acquire(blocking=False):
            _PROCESS_TRANSFER_GUARD.release()
            return None
        claim: BackupClaim | None = None
        try:
            with self._state_lock:
                self._run_active = True
                self._restart_requested = False
            claim = self._store.claim_next(now, self._claim_id_factory())
            if claim is None:
                self._finish_external()
                return None
            control = TransferControl()
            lifetime_cancel = Event()
            with self._state_lock:
                if self._restart_requested:
                    self._store.release_claim(claim, BackupStatus.READY)
                    self._finish_external()
                    return None
                self._cancel = control
                self._lifetime_cancel = lifetime_cancel
                self._cancel_reason = None
                self._active_sha256 = claim.backup.sha256
                self._active_name = claim.backup.display_name
                self._active_started_at = self._utc_clock()
                self._active_started_monotonic = self._monotonic()
            installation_id = self._store.installation_id()
            self._external_generation += 1
            work = ExternalWork(
                self._external_generation,
                ExternalPhase.PREFLIGHT,
                claim,
                control,
                lifetime_cancel,
                installation_id,
            )
            with self._state_lock:
                self._external_work = work
            return work
        except BaseException:
            if claim is not None:
                try:
                    self._store.release_claim(claim, BackupStatus.READY)
                except Exception:
                    pass
            self._finish_external()
            raise

    def execute_external(self, work: ExternalWork) -> ExternalResult:
        """Run only Proton/retention I/O; never access StateStore."""
        if type(work) is not ExternalWork:
            raise ValueError("invalid external worker job")
        if work.phase is ExternalPhase.PREFLIGHT:
            return self._execute_preflight(work)
        if work.phase is ExternalPhase.UPLOAD:
            return self._execute_upload(work)
        if work.phase is ExternalPhase.RETENTION:
            return self._execute_retention(work)
        raise ValueError("invalid external worker phase")

    def apply_external(self, result: ExternalResult) -> ExternalWork | None:
        """Validate and commit one typed external result on the store owner."""
        if type(result) is not ExternalResult:
            raise ValueError("invalid external worker result")
        work = result.work
        with self._state_lock:
            current = self._external_work
        if current is None or current != work:
            raise RuntimeError("stale external worker result")
        if work.phase is ExternalPhase.PREFLIGHT:
            return self._apply_preflight(result)
        if work.phase is ExternalPhase.UPLOAD:
            return self._apply_upload(result)
        if work.phase is ExternalPhase.RETENTION:
            return self._apply_retention(result)
        raise ValueError("invalid external worker phase")

    def cancel_current(self) -> bool:
        """Signal the current Proton operation without touching StateStore."""
        with self._state_lock:
            current = self._external_work
            requested = self._cancel is not None and self._cancel.request_cancel()
            if (
                self._lifetime_cancel is not None
                and not self._lifetime_cancel.is_set()
                and (
                    requested
                    or current is not None
                    and current.phase in {ExternalPhase.PREFLIGHT, ExternalPhase.RETENTION}
                )
            ):
                self._lifetime_cancel.set()
                requested = True
            if requested:
                self._cancel_reason = "cancelled"
            return requested

    def abort_external(self) -> None:
        """Release one active split operation fail-closed on the store owner."""
        with self._state_lock:
            work = self._external_work
        if work is None:
            return
        try:
            if work.phase is ExternalPhase.PREFLIGHT:
                self._store.release_claim(
                    work.claim, BackupStatus.READY, error_code="cancelled"
                )
            elif work.phase is ExternalPhase.UPLOAD:
                self._store.release_claim(
                    work.claim, BackupStatus.READY, error_code="cancelled"
                )
        finally:
            self._finish_external()

    def retry_now(self, sha256: str, retry_revision: int) -> None:
        if (
            type(retry_revision) is not int
            or retry_revision < 0
            or retry_revision > MAX_RETRY_REVISION
        ):
            raise ValueError("invalid retry revision")
        if not _PROCESS_TRANSFER_GUARD.acquire(blocking=False):
            raise ValueError("worker is active")
        try:
            with self._state_lock:
                if (
                    self._retry_sha256 != sha256
                    or self._retry_revision != retry_revision
                ):
                    raise ValueError("retry generation changed")
            self._store.retry_now(sha256)
            with self._state_lock:
                self._last_error_code = None
            self._refresh_queue_cache()
        finally:
            _PROCESS_TRANSFER_GUARD.release()

    def resume_after_authentication(self) -> int:
        """Requeue backups parked while no session existed (store owner only)."""
        released = self._store.release_auth_required()
        if released:
            with self._state_lock:
                if self._last_error_code == "authentication_required":
                    self._last_error_code = None
        self._refresh_queue_cache()
        return released

    def recover_startup(self) -> bool:
        """Recover stale claims only at an explicitly serialized boundary."""
        if not _PROCESS_TRANSFER_GUARD.acquire(blocking=False):
            return False
        if not self._run_lock.acquire(blocking=False):
            _PROCESS_TRANSFER_GUARD.release()
            return False
        try:
            self._store.recover_transient()
            with self._state_lock:
                self._reset_runtime_state()
            self._refresh_queue_cache()
            return True
        finally:
            self._run_lock.release()
            _PROCESS_TRANSFER_GUARD.release()

    def restart(self) -> None:
        """Cancel only this worker's active claim; startup recovery is explicit."""
        with self._state_lock:
            if not self._run_active:
                return
            if self._cancel is None:
                self._restart_requested = True
                return
            requested = self._cancel.request_cancel()
            if self._lifetime_cancel is not None:
                self._lifetime_cancel.set()
                requested = True
            if requested:
                self._cancel_reason = "restart"

    def watchdog(self) -> bool:
        """Cancel this worker's transfer at the 7,200-second monotonic boundary."""
        with self._state_lock:
            if (
                self._cancel is None
                or not self._cancel.accepting_cancel
                or self._active_started_monotonic is None
                or self._monotonic() - self._active_started_monotonic
                < PROCESS_TIMEOUT_SECONDS
                or not self._cancel.request_cancel()
            ):
                return False
            if self._lifetime_cancel is not None:
                self._lifetime_cancel.set()
            self._cancel_reason = "process_timeout"
            return True

    def snapshot(self) -> ServiceSnapshot:
        with self._state_lock:
            return ServiceSnapshot(
                web_ready=False,
                connected=self._connected,
                scanner_state="idle",
                active_sha256=self._active_sha256,
                active_name=self._active_name,
                active_started_at=self._active_started_at,
                queue_size=self._queue_size,
                next_retry_at=self._next_retry_at,
                last_success_at=self._last_success_at,
                last_error_code=self._last_error_code,
                remote_files=self._remote_files,
                retry_sha256=self._retry_sha256,
                retry_revision=self._retry_revision,
            )

    def _execute_preflight(self, work: ExternalWork) -> ExternalResult:
        try:
            if work.lifetime_cancel.is_set():
                raise ProtonCliCancelled("Proton Drive command was cancelled")
            authenticated = self._client.is_authenticated(cancel=work.lifetime_cancel)
            if authenticated is not True:
                return ExternalResult(work, ExternalStatus.AUTH_REQUIRED)
            layout = self._client.ensure_layout(
                work.installation_id, cancel=work.lifetime_cancel
            )
            if type(layout) is not RemoteLayout:
                return ExternalResult(work, ExternalStatus.NETWORK_UNAVAILABLE)
            # A canonical name contains only a short SHA prefix; it is not UID proof.
            existing = self._client.find_final(
                work.claim.backup, layout, cancel=work.lifetime_cancel
            )
            if existing is not None:
                return ExternalResult(work, ExternalStatus.REMOTE_AMBIGUOUS)
            return ExternalResult(work, ExternalStatus.SUCCESS, layout)
        except ProtonRemoteConflict:
            return ExternalResult(work, ExternalStatus.REMOTE_AMBIGUOUS)
        except ProtonAuthenticationRequired:
            return ExternalResult(work, ExternalStatus.AUTH_REQUIRED)
        except ProtonProcessTimeout:
            return ExternalResult(work, ExternalStatus.PROCESS_TIMEOUT)
        except ProtonCliCancelled:
            return ExternalResult(work, ExternalStatus.CANCELLED)
        except Exception:
            return ExternalResult(work, ExternalStatus.NETWORK_UNAVAILABLE)

    def _apply_preflight(self, result: ExternalResult) -> ExternalWork | None:
        work = result.work
        if result.status is ExternalStatus.SUCCESS and type(result.value) is RemoteLayout:
            with self._state_lock:
                self._connected = True
            try:
                self._store.mark_claim_confirming(work.claim)
            except Exception:
                self._park_ambiguous(work.claim)
                self._finish_external()
                return None
            upload = ExternalWork(
                work.generation,
                ExternalPhase.UPLOAD,
                work.claim,
                work.control,
                work.lifetime_cancel,
                work.installation_id,
                result.value,
            )
            with self._state_lock:
                self._external_work = upload
            self._record_event("upload_started", work.claim.backup.display_name)
            return upload
        if result.status is ExternalStatus.AUTH_REQUIRED:
            self._park_authentication(work.claim)
        else:
            with self._state_lock:
                reason = self._cancel_reason if work.control.is_set() else None
            if reason is not None:
                self._finish_cancel_reason(work.claim, reason)
            elif result.status is ExternalStatus.REMOTE_AMBIGUOUS:
                self._park_ambiguous(work.claim)
            elif result.status is ExternalStatus.PROCESS_TIMEOUT:
                self._schedule_retry(work.claim, "process_timeout")
            elif result.status is ExternalStatus.CANCELLED:
                self._schedule_retry(work.claim, "cancelled", user_cancel=True)
            else:
                self._schedule_retry(work.claim, "network_unavailable")
            with self._state_lock:
                self._connected = False
        self._finish_external()
        return None

    def _execute_upload(self, work: ExternalWork) -> ExternalResult:
        if type(work.layout) is not RemoteLayout:
            return ExternalResult(work, ExternalStatus.REMOTE_AMBIGUOUS)
        try:
            remote = self._client.upload_and_finalize(
                work.claim.backup, work.layout, work.control
            )
        except ProtonProcessTimeout:
            return ExternalResult(work, ExternalStatus.PROCESS_TIMEOUT)
        except ProtonAuthenticationRequired:
            return ExternalResult(work, ExternalStatus.AUTH_REQUIRED)
        except ProtonNetworkError:
            return ExternalResult(work, ExternalStatus.NETWORK_UNAVAILABLE)
        except ProtonCliCancelled:
            return ExternalResult(work, ExternalStatus.CANCELLED)
        except ProtonCliError:
            try:
                authenticated = self._client.is_authenticated(cancel=work.control)
            except ProtonAuthenticationRequired:
                authenticated = False
            except Exception:
                authenticated = True
            return ExternalResult(
                work,
                ExternalStatus.AUTH_REQUIRED
                if authenticated is not True
                else ExternalStatus.UPLOAD_FAILED,
            )
        except Exception:
            return ExternalResult(work, ExternalStatus.UPLOAD_FAILED)
        try:
            validated = self._upload_validator(remote, work.claim.backup, work.layout)
        except Exception:
            return ExternalResult(work, ExternalStatus.REMOTE_AMBIGUOUS)
        if type(validated) is not RemoteFile:
            return ExternalResult(work, ExternalStatus.REMOTE_AMBIGUOUS)
        return ExternalResult(work, ExternalStatus.SUCCESS, validated)

    def _apply_upload(self, result: ExternalResult) -> ExternalWork | None:
        work = result.work
        with self._state_lock:
            reason = self._cancel_reason if work.control.is_set() else None
            if result.status is ExternalStatus.SUCCESS and reason is None:
                if work.control.accepting_cancel:
                    work.control.mark_success()
                self._cancel = None
                self._cancel_reason = None
        if reason is not None:
            self._finish_cancel_reason(work.claim, reason)
            self._finish_external()
            return None
        if result.status is not ExternalStatus.SUCCESS or type(result.value) is not RemoteFile:
            self._handle_upload_status(work.claim, result.status)
            self._finish_external()
            return None
        return self._complete_upload(work, result.value, work.layout)

    def _handle_upload_status(self, claim: BackupClaim, status: ExternalStatus) -> None:
        """Map a failed upload attempt; retries are safe (preflight reconciles)."""
        if status is ExternalStatus.AUTH_REQUIRED:
            self._park_authentication(claim)
        elif status is ExternalStatus.PROCESS_TIMEOUT:
            self._schedule_retry(claim, "process_timeout")
        elif status is ExternalStatus.CANCELLED:
            self._schedule_retry(claim, "cancelled")
        elif status is ExternalStatus.NETWORK_UNAVAILABLE:
            self._schedule_retry(claim, "network_unavailable")
        elif status is ExternalStatus.UPLOAD_FAILED:
            self._schedule_retry(claim, "upload_failed")
        else:
            # The CLI reported success but the result failed verification.
            self._park_ambiguous(claim)

    def _complete_upload(
        self, work: ExternalWork, remote: RemoteFile, layout: RemoteLayout | None
    ) -> ExternalWork | None:
        completed_at = self._utc_clock()
        if not self._persist_or_reconcile_success(work.claim, remote, completed_at):
            self._finish_external()
            return None
        with self._state_lock:
            self._connected = True
            self._last_success_at = completed_at
            self._last_error_code = None
        self._refresh_queue_cache()
        self._record_event("upload_succeeded", work.claim.backup.display_name)
        try:
            confirmed = tuple(self._store.confirmed_remote_files().values())
        except Exception:
            self._set_retention_error("retention_failed")
            self._finish_external()
            return None
        retention = ExternalWork(
            work.generation,
            ExternalPhase.RETENTION,
            work.claim,
            work.control,
            work.lifetime_cancel,
            work.installation_id,
            layout,
            confirmed,
        )
        with self._state_lock:
            self._external_work = retention
        return retention

    def _execute_retention(self, work: ExternalWork) -> ExternalResult:
        if type(work.layout) is not RemoteLayout:
            return ExternalResult(
                work,
                ExternalStatus.SUCCESS,
                RetentionResult([], "retention_failed"),
            )
        try:
            result = self._retention.reconcile_external(
                work.layout,
                work.installation_id,
                work.confirmed_remote_files,
                cancel=work.lifetime_cancel,
            )
        except Exception:
            result = RetentionResult([], "retention_failed")
        return ExternalResult(work, ExternalStatus.SUCCESS, result)

    def _apply_retention(self, result: ExternalResult) -> None:
        value = result.value
        if type(value) is not RetentionResult:
            self._set_retention_error("retention_failed")
            self._finish_external()
            return None
        if value.error_code is not None:
            self._set_retention_error(
                value.error_code
                if isinstance(value.error_code, str)
                and value.error_code in _SAFE_RETENTION_ERROR_CODES
                else "retention_failed"
            )
            self._finish_external()
            return None
        if value.deleted:
            try:
                self._store.forget_confirmed_remote_files(value.deleted)
            except Exception:
                self._set_retention_error("retention_failed")
                self._finish_external()
                return None
            self._refresh_queue_cache()
        self._finish_external()
        return None

    def _finish_external(self) -> None:
        with self._state_lock:
            self._external_work = None
            self._cancel = None
            self._lifetime_cancel = None
            self._cancel_reason = None
            self._run_active = False
            self._restart_requested = False
            self._active_sha256 = None
            self._active_name = None
            self._active_started_at = None
            self._active_started_monotonic = None
        self._refresh_queue_cache()
        self._run_lock.release()
        _PROCESS_TRANSFER_GUARD.release()

    def _finish_cancel_reason(self, claim: BackupClaim, reason: str) -> None:
        if reason == "restart":
            self._store.release_claim(
                claim, BackupStatus.READY, error_code="cancelled"
            )
            with self._state_lock:
                self._last_error_code = "cancelled"
            return
        if reason == "cancelled":
            self._schedule_retry(claim, "cancelled", user_cancel=True)
            return
        if reason == "process_timeout":
            self._schedule_retry(claim, "process_timeout")
            with self._state_lock:
                self._connected = False
            return
        self._park_ambiguous(claim)

    def _persist_or_reconcile_success(
        self, claim: BackupClaim, remote: RemoteFile, completed_at: datetime
    ) -> bool:
        try:
            self._store.complete_claim(claim, remote, completed_at)
            return True
        except Exception:
            pass
        try:
            confirmed = self._store.confirmed_upload(claim.backup.sha256)
        except Exception:
            confirmed = None
        if type(confirmed) is RemoteFile and confirmed == remote:
            return True
        try:
            self._store.release_claim(
                claim,
                BackupStatus.REMOTE_AMBIGUOUS,
                error_code="remote_ambiguous",
            )
        except Exception:
            try:
                confirmed = self._store.confirmed_upload(claim.backup.sha256)
            except Exception:
                confirmed = None
            if type(confirmed) is RemoteFile and confirmed == remote:
                return True
        with self._state_lock:
            self._connected = False
            self._last_error_code = "remote_ambiguous"
        self._refresh_queue_cache()
        return False

    def _park_authentication(self, claim: BackupClaim) -> None:
        self._record_event("authentication_required", claim.backup.display_name)
        self._store.release_claim(
            claim,
            BackupStatus.AUTH_REQUIRED,
            error_code="authentication_required",
        )
        with self._state_lock:
            self._connected = False
            self._last_error_code = "authentication_required"
        self._refresh_queue_cache()

    def _park_ambiguous(self, claim: BackupClaim) -> None:
        self._record_event("remote_ambiguous", claim.backup.display_name)
        self._store.release_claim(
            claim,
            BackupStatus.REMOTE_AMBIGUOUS,
            error_code="remote_ambiguous",
        )
        with self._state_lock:
            self._connected = False
            self._last_error_code = "remote_ambiguous"
        self._refresh_queue_cache()

    def _schedule_retry(
        self, claim: BackupClaim, error_code: str, *, user_cancel: bool = False
    ) -> None:
        failed_at = self._utc_clock()
        self._record_event(error_code, claim.backup.display_name)
        delay = 60.0 if user_cancel else self._retry_delay(claim.attempt_count + 1)
        self._store.schedule_claim_retry(
            claim,
            error_code=error_code,
            retry_at=failed_at + timedelta(seconds=delay),
            increment_attempt=not user_cancel,
        )
        with self._state_lock:
            self._last_error_code = error_code
            if error_code in {"network_unavailable", "process_timeout"}:
                self._connected = False
        self._refresh_queue_cache()

    def _retry_delay(self, attempt: int) -> float:
        base = _MAX_RETRY_SECONDS if attempt >= 7 else 60 * (2 ** (attempt - 1))
        window = min(base * _JITTER_FRACTION, _MAX_RETRY_SECONDS - base)
        if window <= 0:
            return float(base)
        try:
            candidate = self._jitter(float(window))
        except Exception:
            candidate = 0.0
        if (
            isinstance(candidate, bool)
            or not isinstance(candidate, (int, float))
            or not math.isfinite(candidate)
        ):
            candidate = 0.0
        return float(base) + min(max(float(candidate), 0.0), float(window))

    def _set_retention_error(self, error_code: str) -> None:
        self._record_event("retention_failed")
        with self._state_lock:
            self._last_error_code = error_code

    def _record_event(self, code: str, backup_name: str | None = None) -> None:
        if self._event_log is not None:
            try:
                self._event_log.record(code, backup_name=backup_name)
            except Exception:
                pass

    def _refresh_queue_cache(self) -> None:
        try:
            summary = self._store.queue_snapshot()
        except Exception:
            with self._state_lock:
                self._retry_sha256 = None
            return
        if type(summary) is not QueueSnapshot:
            with self._state_lock:
                self._retry_sha256 = None
            return
        retry_identity = (summary.retry_sha256, summary.next_retry_at)
        with self._state_lock:
            self._queue_size = summary.queue_size
            self._next_retry_at = summary.next_retry_at
            self._remote_files = tuple(summary.remote_files)
            if retry_identity != self._authoritative_retry_identity:
                if self._retry_revision >= MAX_RETRY_REVISION:
                    self._retry_sha256 = None
                    return
                self._retry_revision += 1
                self._authoritative_retry_identity = retry_identity
            self._retry_sha256 = summary.retry_sha256

    def _reset_runtime_state(self) -> None:
        self._cancel = None
        self._lifetime_cancel = None
        self._cancel_reason = None
        self._run_active = False
        self._restart_requested = False
        self._active_sha256 = None
        self._active_name = None
        self._active_started_at = None
        self._active_started_monotonic = None
        self._next_retry_at = None

    def _utc_clock(self) -> datetime:
        return _as_utc(self._clock())


def _as_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("worker time must be timezone-aware")
    return value.astimezone(UTC)
