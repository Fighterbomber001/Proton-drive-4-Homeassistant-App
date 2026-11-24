from __future__ import annotations

from collections import deque
from concurrent.futures import Future
from contextlib import nullcontext
from dataclasses import dataclass, replace
from datetime import UTC, datetime
import math
from queue import Empty, Full, Queue
from threading import Event, RLock, Thread, current_thread
from time import monotonic
from typing import Callable

from .config import SCAN_INTERVAL_SECONDS
from .native_history import NativeHistory, project_backup, project_inventory
from .native_storage import NativeAuthenticationRequired, NativeStorageError
from .process import active_process_reader_threads
from .web import CommandQueue, ControlAction, ControlCommand, LoginUrlBroker
from .worker import ServiceSnapshot


_MAX_PROTON_PENDING = 65
_MAX_COMMANDS_PER_TICK = 8
_RUNTIME_TICK_SECONDS = 0.1
_CLAIM_POLL_SECONDS = 5.0
_CLEANUP_RETRY_WINDOW_SECONDS = 5.0

class ShutdownTimeoutError(TimeoutError):
    """A dependency ignored cooperative shutdown through the service deadline."""

    def __init__(self, pending_threads: tuple[str, ...]) -> None:
        self.pending_threads = pending_threads
        super().__init__("backup service shutdown timed out")


class ShutdownFailureError(RuntimeError):
    """A cooperative shutdown action failed before cleanup was complete."""

    def __init__(self, component_codes: tuple[str, ...] = ()) -> None:
        self.component_codes = component_codes
        super().__init__("backup service shutdown failed")


@dataclass(frozen=True)
class RuntimeComponents:
    store: object
    scanner: object
    worker: object
    auth_client: object | None = None
    native_storage: object | None = None


@dataclass(frozen=True)
class _NativeWork:
    operation: str
    backup_id: str | None
    metadata: object | None
    path: object | None
    cancel: Event
    future: Future


@dataclass(frozen=True)
class _HistoryWork:
    auth_revision: int
    cancel: Event


@dataclass(frozen=True)
class _ScanJob:
    generation: int
    baseline: object
    cancel: Event


@dataclass(frozen=True)
class _ScanOutcome:
    generation: int
    evidence: object | None
    error: BaseException | None
    ack: Event | None = None
    prepared: bool = False
    source: object | None = None


@dataclass(frozen=True)
class _ProtonJob:
    generation: int
    kind: str
    work: object


@dataclass(frozen=True)
class _ProtonOutcome:
    generation: int
    kind: str
    result: object | None
    error: BaseException | None
    source: object | None = None


@dataclass(frozen=True)
class _AuthWork:
    action: ControlAction | str
    user_id: str
    command_id: str
    callback: object | None
    cancel: Event
    login_deadline: float | None = None
    revision: int = 0


@dataclass(frozen=True)
class _AuthResult:
    work: _AuthWork
    succeeded: bool
    connected: bool | None
    cancelled: bool = False


def _empty_snapshot() -> ServiceSnapshot:
    return ServiceSnapshot(
        web_ready=False,
        connected=False,
        scanner_state="idle",
        active_sha256=None,
        active_name=None,
        active_started_at=None,
        queue_size=0,
        next_retry_at=None,
        last_success_at=None,
        last_error_code=None,
        remote_files=(),
    )


class BackupService:
    def __init__(
        self,
        *,
        runtime_factory: Callable[[], RuntimeComponents],
        web_server_factory: Callable[[Callable[[], ServiceSnapshot], Queue[ControlCommand]], object],
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        login_url_broker: LoginUrlBroker | None = None,
        event_log=None,
        native_mode: bool = False,
        native_api_factory=None,
    ) -> None:
        if login_url_broker is not None and type(login_url_broker) is not LoginUrlBroker:
            raise ValueError("invalid login URL broker")
        self._runtime_factory = runtime_factory
        self._event_log = event_log
        self._native_mode = native_mode
        self._native_api_factory = native_api_factory
        self._native_api = None
        self._native_requests: Queue[_NativeWork] = Queue(maxsize=64)
        self._native_calls: dict[Future, _NativeWork] = {}
        self._native_active: _NativeWork | None = None
        self._native_active_auth_revision = 0
        self._native_started_at: datetime | None = None
        self._native_last_success: datetime | None = None
        self._native_last_error: str | None = None
        self._native_history = NativeHistory()
        self._history_requested = False
        self._history_work: _HistoryWork | None = None
        self._history_auth_pending: int | None = None
        self._web_server_factory = web_server_factory
        self._clock = clock
        self._login_url_broker = login_url_broker
        self._commands = CommandQueue(maxsize=64)
        self._scan_jobs: Queue[_ScanJob | None] = Queue(maxsize=1)
        self._scan_results: Queue[_ScanOutcome] = Queue()
        self._proton_jobs: Queue[_ProtonJob | None] = Queue(maxsize=1)
        self._proton_results: Queue[_ProtonOutcome] = Queue()
        self._proton_pending: deque[tuple[str, object]] = deque()
        self._scan_lane_source = object()
        self._proton_lane_source = object()
        self._stop = Event()
        self._wake = Event()
        self._claim_hint = True
        self._next_claim_check = 0.0
        self._scan_requested = Event()
        self._run_gate = Event()
        self._runtime_ready = Event()
        self._web_started = Event()
        self._web_failure: BaseException | None = None
        self._runtime_failure: BaseException | None = None
        self._shutdown_failure: BaseException | None = None
        self._shutdown_failure_codes: set[str] = set()
        self._shutdown_deadline: float | None = None
        self._cleanup_failed = Event()
        self._cleanup_retry = Event()
        self._cleanup_failure_reported = False
        self._runtime: RuntimeComponents | None = None
        self._runtime_thread: Thread | None = None
        self._web_thread: Thread | None = None
        self._control_thread: Thread | None = None
        self._auth_thread: Thread | None = None
        self._scan_thread: Thread | None = None
        self._proton_thread: Thread | None = None
        self._scan_cancel: Event | None = None
        self._scan_generation = 0
        self._scan_inflight: int | None = None
        self._scan_pending = False
        self._scanner_state = "starting"
        self._proton_generation = 0
        self._proton_inflight: int | None = None
        self._proton_inflight_kind: str | None = None
        self._auth_cancel: Event | None = None
        self._auth_user_id: str | None = None
        self._auth_command_id: str | None = None
        self._auth_revision = 0
        self._connected_override: bool | None = None
        self._server: object | None = None
        self._web_ready = False
        self._service_error_code: str | None = None
        self._stop_complete = False
        self._lock = RLock()

    def start(self) -> None:
        with self._lock:
            if self._runtime_thread is not None:
                return
            self._runtime_thread = Thread(
                target=self._run_runtime,
                name="proton-backup-runtime",
            )
            self._runtime_thread.start()
        self._wait_startup(self._runtime_ready)
        if self._runtime_failure is not None:
            raise RuntimeError("backup service startup failed") from self._runtime_failure
        if self._stop.is_set():
            raise RuntimeError("backup service startup was cancelled")
        native_api_starting = False
        try:
            self._record_event("startup_web_started")
            self._server = self._web_server_factory(self.dashboard_snapshot, self._commands)
            self._web_thread = Thread(
                target=self._serve_web,
                name="proton-backup-web",
            )
            self._web_thread.start()
            self._wait_startup(self._web_started)
            if self._web_failure is not None:
                raise RuntimeError("web server failed during startup") from self._web_failure
            if self._stop.is_set() or not self.snapshot().web_ready:
                raise RuntimeError("web server failed during startup")
            self._record_event("startup_web_ready")
            if self._native_mode and self._native_api_factory is not None:
                native_api_starting = True
                self._record_event("startup_native_api_started")
                self._native_api = self._native_api_factory(self, self._runtime)
                self._native_api.start()
                self._record_event("startup_native_api_ready")
            self._run_gate.set()
            self._record_event("service_started")
        except BaseException as error:
            if native_api_starting:
                self._record_event("startup_native_api_failed")
            else:
                self._record_event("startup_web_failed")
            self.request_stop()
            raise RuntimeError("backup service startup failed") from error

    def _wait_startup(self, ready: Event) -> None:
        while not ready.wait(0.05):
            if self._stop.is_set():
                raise RuntimeError("backup service startup was cancelled")

    def snapshot(self) -> ServiceSnapshot:
        return self._snapshot(dashboard=False)

    def _snapshot(self, *, dashboard: bool) -> ServiceSnapshot:
        with self._lock:
            runtime = self._runtime
            web_ready = self._web_ready
            service_error_code = self._service_error_code
            scanner_state = self._scanner_state
            native_active = self._native_active
            native_started = self._native_started_at
            native_success = self._native_last_success
            native_error = self._native_last_error
            native_queued = max(0, len(self._native_calls) - (native_active is not None))
        snapshot = runtime.worker.snapshot() if runtime is not None else _empty_snapshot()
        dashboard_native = dashboard and self._native_mode
        # The owner takes this same lease from dequeue through auth admission.
        # Observe both stages as one, without holding it through worker reads.
        admission = self._commands.execution_lease() if dashboard_native else nullcontext()
        with admission, self._lock:
            connected_override = self._connected_override
            connected = snapshot.connected if connected_override is None else connected_override
            if dashboard_native and (self._history_auth_pending is not None
                                     or self._commands.has_pending_auth_command()):
                # Never show prior-account history or hide the handoff link
                # from acceptance through completion of a credential change.
                connected = False
            history_visible = self._native_mode and connected and self._history_session_stable()
            history_state = self._native_history.state if history_visible else "unavailable"
            native_history = self._native_history.entries if history_visible else ()
        if self._native_mode:
            active_name = None
            if native_active is not None:
                if isinstance(native_active.metadata, dict):
                    active_name = native_active.metadata.get("name")
                if not isinstance(active_name, str):
                    active_name = native_active.backup_id
            snapshot = replace(
                snapshot, native_mode=True,
                native_operation=native_active.operation if native_active is not None else None,
                active_sha256=None, active_name=active_name, active_started_at=native_started,
                queue_size=native_queued, next_retry_at=None, last_success_at=native_success,
                last_error_code=native_error, retry_sha256=None, retry_revision=0,
                remote_files=(),
                native_history_state=history_state,
                native_history=native_history,
            )
        return replace(
            snapshot,
            web_ready=web_ready,
            connected=connected,
            scanner_state=scanner_state,
            last_error_code=service_error_code or snapshot.last_error_code,
        )

    def dashboard_snapshot(self) -> ServiceSnapshot:
        """Return cached status immediately; only the dashboard can ask for a refresh."""
        snapshot = self._snapshot(dashboard=True)
        if snapshot.native_mode and snapshot.web_ready and snapshot.connected:
            with self._lock:
                if (self._history_session_stable() and self._connected_override is not False
                        and not self._native_calls and self._history_work is None
                        and not self._history_requested and self._native_history.due(monotonic())):
                    self._history_requested = True
                    self._wake.set()
        return snapshot

    def _history_session_stable(self, auth_revision: int | None = None) -> bool:
        # Native jobs ahead of an auth command can still use the old account
        # after that command has advanced the revision. The revision alone
        # cannot establish which account their metadata belongs to.
        return (
            not self._stop.is_set()
            and self._history_auth_pending is None
            and (auth_revision is None or auth_revision == self._auth_revision)
        )

    def _clear_native_history(self) -> None:
        # Called under the lock at a credential/session boundary.
        self._native_history = NativeHistory()
        self._history_requested = False
        if self._history_work is not None:
            self._history_work.cancel.set()

    def request_scan(self) -> None:
        self._scan_requested.set()
        self._wake.set()

    def submit_native(self, operation, backup_id=None, metadata=None, path=None, cancel=None):
        """Admit only a fixed storage operation; the owner dispatches CLI I/O."""
        if operation not in {"list", "get", "upload", "download", "delete"}:
            raise ValueError("invalid native operation")
        with self._commands.admission() as admitted:
            with self._lock:
                if (not admitted or not self._native_mode or self._stop.is_set()
                        or not self._runtime_ready.is_set() or self._runtime is None
                        or self._runtime.native_storage is None):
                    raise RuntimeError("native service unavailable")
                if len(self._native_calls) >= 64:
                    raise RuntimeError("native service busy")
                future = Future()
                work = _NativeWork(operation, backup_id, metadata, path,
                                   cancel if cancel is not None else Event(), future)
                self._native_requests.put_nowait(work)
                self._native_calls[future] = work
                future.add_done_callback(self._forget_native_call)
                if self._history_work is not None:
                    self._history_work.cancel.set()
        self._wake.set()
        return future

    def _forget_native_call(self, future):
        with self._lock:
            self._native_calls.pop(future, None)

    def _cancel_native_calls(self):
        with self._lock:
            calls = tuple(self._native_calls.values())
        for work in calls:
            work.cancel.set()
            # A running future must stay incomplete until its CLI releases the
            # spool. API completion callbacks can unlink that file.
            work.future.cancel()

    def request_stop(self) -> None:
        """Request cooperative shutdown; safe for signal handlers."""
        self._commands.close_admission()
        self._cancel_native_calls()
        with self._lock:
            if self._shutdown_deadline is None:
                self._shutdown_deadline = monotonic() + 20
        self._stop.set()
        self._wake.set()
        self._run_gate.set()
        with self._lock:
            self._web_ready = False
            self._connected_override = False
            scan_cancel = self._scan_cancel
            auth_cancel = self._auth_cancel
            self._clear_native_history()
            runtime = self._runtime
            pending_auth = tuple(self._proton_pending)
        if scan_cancel is not None:
            scan_cancel.set()
        if auth_cancel is not None:
            auth_cancel.set()
        for kind, work in pending_auth:
            if kind == "auth" and type(work) is _AuthWork:
                work.cancel.set()
                if self._login_url_broker is not None:
                    self._login_url_broker.cancel(
                        work.user_id, work.command_id
                    )
        if (
            self._login_url_broker is not None
            and self._auth_user_id is not None
            and self._auth_command_id is not None
        ):
            self._login_url_broker.cancel(
                self._auth_user_id, self._auth_command_id
            )
        if runtime is not None:
            try:
                runtime.worker.cancel_current()
            except BaseException as error:
                self._record_shutdown_failure("worker_cancel", error)

    def wait(self, timeout: float | None = None) -> bool:
        return self._stop.wait(timeout)

    def stop(self, timeout: float = 20) -> None:
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
            or timeout > 20
        ):
            raise ValueError("invalid stop timeout")
        deadline = monotonic() + timeout
        with self._lock:
            retry_cleanup = self._cleanup_failed.is_set() and self._cleanup_failure_reported
            self._shutdown_deadline = (
                deadline
                if retry_cleanup
                else min(
                    deadline,
                    self._shutdown_deadline
                    if self._shutdown_deadline is not None
                    else deadline,
                )
            )
            if retry_cleanup:
                self._cleanup_failed.clear()
                self._cleanup_retry.set()
        self.request_stop()
        with self._lock:
            if self._stop_complete:
                return
        if self._native_api is not None:
            try:
                self._native_api.stop(timeout=self._remaining_shutdown())
            except BaseException as error:
                self._record_shutdown_failure("native_api", error)
        for thread in (
            self._runtime_thread,
            self._web_thread,
            self._scan_thread,
            self._proton_thread,
        ):
            if thread is not None and thread is not current_thread():
                while thread.is_alive() and monotonic() < deadline:
                    thread.join(min(0.05, max(0.0, deadline - monotonic())))
                    if thread is self._runtime_thread and self._cleanup_failed.is_set():
                        break
        for reader in active_process_reader_threads():
            if reader is not current_thread():
                reader.join(max(0.0, deadline - monotonic()))
        pending = tuple(
            thread.name
            for thread in (
                self._runtime_thread,
                self._web_thread,
                self._scan_thread,
                self._proton_thread,
            )
            if thread is not None
            and thread.is_alive()
            and not (thread is self._runtime_thread and self._cleanup_failed.is_set())
        ) + tuple(
            reader.name
            for reader in active_process_reader_threads()
            if reader.is_alive()
        )
        if pending:
            with self._lock:
                self._service_error_code = "stop_failed"
                self._web_ready = False
                self._connected_override = False
            raise ShutdownTimeoutError(pending)
        with self._lock:
            shutdown_failure = self._shutdown_failure
            failure_codes = tuple(sorted(self._shutdown_failure_codes))
            if shutdown_failure is None and not self._cleanup_failed.is_set():
                self._stop_complete = True
            self._scanner_state = "stopped"
            if shutdown_failure is not None or self._cleanup_failed.is_set():
                self._cleanup_failure_reported = True
        if shutdown_failure is not None or self._cleanup_failed.is_set():
            self._record_event("stop_failed")
            raise ShutdownFailureError(failure_codes) from shutdown_failure
        self._record_event("service_stopped")

    def _run_runtime(self) -> None:
        runtime: RuntimeComponents | None = None
        startup_complete = False
        recovering = False
        try:
            self._record_event("startup_runtime_started")
            runtime = self._runtime_factory()
            with self._lock:
                self._runtime = runtime
            if self._native_mode and runtime.native_storage is None:
                raise RuntimeError("native storage unavailable")
            if self._stop.is_set():
                raise RuntimeError("startup was cancelled")
            recovering = True
            self._record_event("startup_recovery_started")
            if runtime.worker.recover_startup() is not True:
                raise RuntimeError("startup recovery was not serialized")
            self._record_event("startup_recovery_ready")
            recovering = False
            if self._stop.is_set():
                raise RuntimeError("startup was cancelled")
            self._scan_thread = Thread(
                target=self._run_scan_lane,
                args=(runtime.scanner,),
                name="proton-backup-scanner",
            )
            self._scan_thread.start()
            self._start_scan(runtime, self._clock())
            while self._scan_inflight is not None:
                if self._stop.is_set():
                    with self._lock:
                        cancel = self._scan_cancel
                    if cancel is not None:
                        cancel.set()
                self._finish_scan(
                    runtime,
                    wait=0.05,
                    allow_apply=not self._stop.is_set(),
                )
            if self._stop.is_set():
                raise RuntimeError("startup scan was cancelled")
            next_scan = monotonic() + SCAN_INTERVAL_SECONDS
            self._proton_thread = Thread(
                target=self._run_proton_lane,
                args=(runtime,),
                name="proton-backup-proton-io",
            )
            self._proton_thread.start()
            if runtime.auth_client is not None:
                self._enqueue_proton_pending(
                    "auth",
                    _AuthWork(
                        "probe",
                        "system",
                        "0" * 32,
                        None,
                        Event(),
                        revision=0,
                    ),
                )
            startup_complete = True
            self._record_event("startup_runtime_ready")
            self._runtime_ready.set()
            self._run_gate.wait()
            while not self._stop.is_set():
                self._wake.clear()
                self._finish_scan(runtime)
                self._finish_proton_work(runtime)
                self._run_runtime_commands(runtime)
                self._pump_native_requests()
                scan_now = monotonic()
                if (
                    self._scan_requested.is_set()
                    or scan_now >= next_scan
                ):
                    self._scan_requested.clear()
                    self._request_owner_scan(runtime, self._clock())
                    next_scan = scan_now + SCAN_INTERVAL_SECONDS
                self._request_proton_work(runtime)
                if not self._native_mode:
                    runtime.worker.watchdog()
                self._wake.wait(_RUNTIME_TICK_SECONDS)
        except BaseException as error:
            if not startup_complete:
                if recovering:
                    self._record_event("startup_recovery_failed")
                else:
                    self._record_event("startup_runtime_failed")
            with self._lock:
                self._web_ready = False
                self._connected_override = False
                if not self._stop.is_set():
                    self._service_error_code = "worker_failed"
                    self._record_event("service_failed")
            if not startup_complete:
                self._runtime_failure = error
            self.request_stop()
        finally:
            if runtime is not None:
                try:
                    self._drain_runtime(runtime)
                except BaseException as error:
                    self._record_shutdown_failure("runtime_drain", error)
                while True:
                    try:
                        runtime.store.close()
                    except BaseException as error:
                        self._record_shutdown_failure("store_close", error)
                        self._cleanup_failed.set()
                        self._runtime_ready.set()
                        if not self._cleanup_retry.wait(_CLEANUP_RETRY_WINDOW_SECONDS):
                            break
                        self._cleanup_retry.clear()
                        continue
                    with self._lock:
                        self._shutdown_failure_codes.discard("store_close")
                        if not self._shutdown_failure_codes:
                            self._shutdown_failure = None
                    self._cleanup_failed.clear()
                    break
            with self._lock:
                self._runtime = None
                self._scanner_state = "stopped"
            self._runtime_ready.set()

    def _drain_runtime(self, runtime: RuntimeComponents) -> None:
        errors: list[str] = []
        with self._lock:
            scan_cancel = self._scan_cancel
            auth_cancel = self._auth_cancel
            pending_auth = tuple(self._proton_pending)
            self._proton_pending.clear()
            self._scan_pending = False
        if scan_cancel is not None:
            scan_cancel.set()
        if auth_cancel is not None:
            auth_cancel.set()
        for kind, work in pending_auth:
            if kind == "auth" and type(work) is _AuthWork:
                work.cancel.set()
        try:
            runtime.worker.cancel_current()
        except BaseException:
            errors.append("worker_cancel")
        while self._scan_inflight is not None or self._proton_inflight is not None:
            if self._remaining_shutdown() <= 0:
                errors.append("lane_pending")
                break
            if self._scan_inflight is not None:
                try:
                    self._finish_scan(runtime, wait=0.05, allow_apply=False)
                except BaseException:
                    errors.append("scanner_outcome")
            if self._proton_inflight is not None:
                try:
                    self._finish_proton_work(runtime, wait=0.05, abort=True)
                except BaseException:
                    errors.append("proton_outcome")
        if self._scan_thread is not None:
            try:
                self._scan_jobs.put_nowait(None)
            except Full:
                errors.append("scanner_sentinel")
            while self._scan_thread.is_alive() and self._remaining_shutdown() > 0:
                self._scan_thread.join(min(0.05, self._remaining_shutdown()))
            if self._scan_thread.is_alive():
                errors.append("scanner_lane")
        if self._proton_thread is not None:
            try:
                self._proton_jobs.put_nowait(None)
            except Full:
                errors.append("proton_sentinel")
            while self._proton_thread.is_alive() and self._remaining_shutdown() > 0:
                self._proton_thread.join(min(0.05, self._remaining_shutdown()))
            if self._proton_thread.is_alive():
                errors.append("proton_lane")
        if errors:
            raise ShutdownFailureError(tuple(sorted(set(errors))))

    def _remaining_shutdown(self) -> float:
        with self._lock:
            deadline = self._shutdown_deadline
        if deadline is None:
            return 0.05
        return max(0.0, deadline - monotonic())

    def _record_shutdown_failure(self, code: str, error: BaseException) -> None:
        with self._lock:
            self._shutdown_failure = error
            self._shutdown_failure_codes.add(code)
            self._service_error_code = "stop_failed"
            self._web_ready = False
            self._connected_override = False

    def _run_scan_lane(self, scanner: object) -> None:
        while True:
            job = self._scan_jobs.get()
            if job is None:
                return
            validation = None
            ack: Event | None = None
            try:
                evidence = scanner.collect_scan(job.baseline, job.cancel)
                validate = getattr(scanner, "validate_scan", None)
                if callable(validate):
                    validation = validate(evidence, job.cancel)
                    evidence = validation.evidence
                    ack = Event()
            except BaseException as error:
                outcome = _ScanOutcome(
                    job.generation,
                    None,
                    error,
                    source=self._scan_lane_source,
                )
            else:
                outcome = _ScanOutcome(
                    job.generation,
                    evidence,
                    None,
                    ack,
                    validation is not None,
                    self._scan_lane_source,
                )
            self._scan_results.put(outcome)
            self._wake.set()
            if ack is not None:
                ack.wait()
                try:
                    finish = getattr(validation, "finish", None)
                    if callable(finish):
                        final_evidence = finish(job.cancel)
                    else:
                        close_succeeded = validation.close()
                        final_evidence = validation.evidence
                        if not close_succeeded:
                            raise RuntimeError("scan validation close failed")
                except BaseException as error:
                    final_outcome = _ScanOutcome(
                        job.generation,
                        None,
                        error,
                        source=self._scan_lane_source,
                    )
                else:
                    final_outcome = _ScanOutcome(
                        job.generation,
                        final_evidence,
                        None,
                        source=self._scan_lane_source,
                    )
                self._scan_results.put(final_outcome)
                self._wake.set()

    def _run_proton_lane(self, runtime: RuntimeComponents) -> None:
        while True:
            job = self._proton_jobs.get()
            if job is None:
                return
            try:
                if job.kind == "worker":
                    result = runtime.worker.execute_external(job.work)
                elif job.kind == "auth":
                    result = self._execute_auth_work(runtime, job.work)
                elif job.kind == "native":
                    result = self._execute_native_work(runtime, job.work)
                elif job.kind == "history":
                    result = self._execute_native_history(runtime, job.work)
                else:
                    raise RuntimeError("invalid Proton work kind")
            except BaseException as error:
                outcome = _ProtonOutcome(
                    job.generation,
                    job.kind,
                    None,
                    error,
                    self._proton_lane_source,
                )
            else:
                outcome = _ProtonOutcome(
                    job.generation,
                    job.kind,
                    result,
                    None,
                    self._proton_lane_source,
                )
            self._proton_results.put(outcome)
            self._wake.set()

    def _dispatch_proton_work(self, kind: str, work: object) -> None:
        if self._proton_inflight is not None:
            raise RuntimeError("Proton work already active")
        self._proton_generation += 1
        generation = self._proton_generation
        self._proton_inflight = generation
        self._proton_inflight_kind = kind
        if kind == "auth":
            if type(work) is not _AuthWork:
                raise RuntimeError("invalid auth work")
            with self._lock:
                self._auth_cancel = work.cancel
                self._auth_user_id = work.user_id
                self._auth_command_id = work.command_id
        elif kind == "native":
            with self._lock:
                self._native_active = work
                self._native_active_auth_revision = self._auth_revision
                self._native_started_at = self._clock()
            if work.operation == "upload":
                self._record_event("upload_started")
        self._proton_jobs.put_nowait(_ProtonJob(generation, kind, work))

    def _pump_native_requests(self):
        for _ in range(_MAX_COMMANDS_PER_TICK):
            with self._commands.execution_lease() as admitted:
                if not admitted or len(self._proton_pending) >= _MAX_PROTON_PENDING:
                    return
                try:
                    work = self._native_requests.get_nowait()
                except Empty:
                    return
                if not work.future.cancelled():
                    self._enqueue_proton_pending("native", work)

    def _execute_native_work(self, runtime, work):
        if type(work) is not _NativeWork or runtime.native_storage is None or work.cancel.is_set():
            raise NativeStorageError()
        storage = runtime.native_storage
        if work.operation == "list":
            return storage.list_backups(work.cancel)
        if work.operation == "get":
            return storage.get_backup(work.backup_id, work.cancel)
        if work.operation == "upload":
            return storage.upload_backup(work.backup_id, work.metadata, work.path, work.cancel)
        if work.operation == "download":
            return storage.download_backup(work.backup_id, work.cancel)
        if work.operation == "delete":
            return storage.delete_backup(work.backup_id, work.cancel)
        raise NativeStorageError()

    def _execute_native_history(self, runtime: RuntimeComponents, work: object):
        if type(work) is not _HistoryWork or runtime.native_storage is None or work.cancel.is_set():
            raise NativeStorageError()
        return project_inventory(runtime.native_storage.list_backups(work.cancel))

    def _enqueue_proton_pending(self, kind: str, work: object) -> None:
        if len(self._proton_pending) >= _MAX_PROTON_PENDING:
            raise RuntimeError("Proton work queue is full")
        self._proton_pending.append((kind, work))

    def _request_proton_work(self, runtime: RuntimeComponents) -> None:
        if self._proton_inflight is not None:
            return
        if self._proton_pending:
            with self._commands.execution_lease() as admitted:
                if not admitted:
                    return
                kind, work = self._proton_pending.popleft()
                if kind == "native":
                    if work.cancel.is_set():
                        work.future.cancel()
                        return
                    if not work.future.set_running_or_notify_cancel():
                        return
                self._dispatch_proton_work(kind, work)
            return
        if self._native_mode:
            self._request_native_history()
            return
        if self._stop.is_set():
            return
        now = monotonic()
        if not self._claim_hint and now < self._next_claim_check:
            return
        self._claim_hint = False
        self._next_claim_check = now + _CLAIM_POLL_SECONDS
        work = runtime.worker.prepare_external(self._clock())
        if work is not None:
            self._dispatch_proton_work("worker", work)

    def _request_native_history(self) -> None:
        # Runtime owner, at the end of the usual command/native dispatch order.
        # The lease linearizes this against new native admissions and shutdown.
        with self._commands.execution_lease() as admitted:
            with self._lock:
                if not self._history_requested:
                    return
                self._history_requested = False
                now = monotonic()
                if (not admitted or not self._history_session_stable()
                        or self._connected_override is False
                        or self._native_calls or not self._commands.empty()
                        or not self._native_history.due(now)):
                    return
                work = _HistoryWork(self._auth_revision, Event())
                self._history_work = work
                self._native_history.defer_refresh(now)
                self._dispatch_proton_work("history", work)

    def _finish_native_history(self, outcome: _ProtonOutcome, *, abort: bool) -> None:
        with self._lock:
            work = self._history_work
            self._history_work = None
            if work is None or abort or not self._history_session_stable(work.auth_revision):
                return
            now = monotonic()
            if work.cancel.is_set() or outcome.kind != "history":
                self._native_history.listing_failed(now)
            elif isinstance(outcome.error, NativeAuthenticationRequired):
                self._connected_override = False
                self._clear_native_history()
            elif outcome.error is not None:
                self._native_history.listing_failed(now)
            else:
                self._native_history.listed(outcome.result, now)

    def _cache_native_success(self, operation: str, result: object, auth_revision: int) -> None:
        if operation not in {"list", "upload"}:
            return
        try:
            projection = project_inventory(result) if operation == "list" else project_backup(result)
        except (NativeStorageError, ValueError, OverflowError, TypeError):
            # Do not change the native API result or verified upload bookkeeping.
            if operation == "list":
                with self._lock:
                    if self._history_session_stable(auth_revision):
                        self._native_history.listing_failed(monotonic())
            return
        with self._lock:
            if not self._history_session_stable(auth_revision):
                return
            if operation == "list":
                self._native_history.listed(projection, monotonic())
            else:
                self._native_history.uploaded(projection)

    def _finish_proton_work(
        self,
        runtime: RuntimeComponents,
        *,
        wait: float | None = None,
        abort: bool = False,
    ) -> bool:
        try:
            outcome = (
                self._proton_results.get(timeout=wait)
                if wait is not None
                else self._proton_results.get_nowait()
            )
        except Empty:
            return False
        if (
            type(outcome) is not _ProtonOutcome
            or outcome.source is not self._proton_lane_source
        ):
            self._record_command_error()
            return True
        if outcome.generation != self._proton_inflight:
            self._record_command_error()
            return True
        expected_kind = self._proton_inflight_kind
        self._claim_hint = True
        self._proton_inflight = None
        self._proton_inflight_kind = None
        if expected_kind == "history":
            self._finish_native_history(outcome, abort=abort)
            return True
        if expected_kind == "native":
            with self._lock:
                work = self._native_active
                auth_revision = self._native_active_auth_revision
                self._native_active = None
                self._native_started_at = None
            if work is None:
                self._record_command_error()
                return True
            if outcome.kind != "native" or outcome.error is not None:
                error = outcome.error if isinstance(outcome.error, NativeStorageError) else NativeStorageError()
                code = getattr(error, "code", "storage_failed")
                if code not in {"storage_failed", "authentication_required", "backup_not_found", "delete_not_supported"}:
                    code = "storage_failed"
                with self._lock:
                    self._native_last_error = "cancelled" if work.cancel.is_set() else code
                    if code == "authentication_required":
                        self._connected_override = False
                        self._clear_native_history()
                    elif (work.operation == "list" and not work.cancel.is_set()
                          and not abort and self._history_session_stable(auth_revision)):
                        self._native_history.listing_failed(monotonic())
                self._record_event("native_cancelled" if work.cancel.is_set() else
                                   "authentication_required" if code == "authentication_required" else
                                   "native_transfer_failed")
                work.future.set_exception(error)
            else:
                with self._lock:
                    self._native_last_error = None
                    self._connected_override = True
                    if work.operation == "upload":
                        self._native_last_success = self._clock()
                if not abort and not work.cancel.is_set():
                    self._cache_native_success(work.operation, outcome.result, auth_revision)
                if work.operation == "upload":
                    self._record_event("upload_succeeded")
                work.future.set_result(outcome.result)
            return True
        if outcome.kind != expected_kind:
            if expected_kind == "worker":
                runtime.worker.abort_external()
            self._record_command_error()
            return True
        if outcome.error is not None:
            if outcome.kind == "worker":
                runtime.worker.abort_external()
            if abort:
                return True
            raise RuntimeError("external Proton I/O failed") from outcome.error
        if outcome.kind == "worker":
            if abort:
                runtime.worker.abort_external()
                return True
            try:
                next_work = runtime.worker.apply_external(outcome.result)
            except BaseException:
                runtime.worker.abort_external()
                raise
            with self._lock:
                self._connected_override = bool(
                    runtime.worker.snapshot().connected
                )
            if next_work is not None:
                self._enqueue_proton_pending("worker", next_work)
                self._request_proton_work(runtime)
        elif outcome.kind == "auth":
            if abort:
                with self._lock:
                    self._auth_cancel = None
                    self._auth_user_id = None
                    self._connected_override = False
            else:
                self._apply_auth_result(outcome.result, runtime)
        else:
            raise RuntimeError("invalid Proton result kind")
        return True

    def _start_scan(self, runtime: RuntimeComponents, now: datetime) -> None:
        if self._native_mode:
            with self._lock:
                self._scanner_state = "idle"
            return
        if self._scan_inflight is not None or self._stop.is_set():
            raise RuntimeError("scan already active")
        self._scan_generation += 1
        generation = self._scan_generation
        baseline = runtime.scanner.prepare_scan(generation, now)
        cancel = Event()
        if self._stop.is_set():
            cancel.set()
            raise RuntimeError("scan start was cancelled")
        with self._lock:
            self._scan_cancel = cancel
            self._scan_inflight = generation
            self._scanner_state = "scanning"
        self._scan_jobs.put_nowait(_ScanJob(generation, baseline, cancel))

    def _request_owner_scan(
        self, runtime: RuntimeComponents, now: datetime
    ) -> None:
        if self._scan_inflight is not None:
            self._scan_pending = True
            return
        self._start_scan(runtime, now)

    def _finish_scan(
        self,
        runtime: RuntimeComponents,
        *,
        wait: float | None = None,
        allow_apply: bool = True,
    ) -> bool:
        try:
            outcome = (
                self._scan_results.get(timeout=wait)
                if wait is not None
                else self._scan_results.get_nowait()
            )
        except Empty:
            return False
        if (
            type(outcome) is not _ScanOutcome
            or outcome.source is not self._scan_lane_source
        ):
            self._record_command_error()
            return True
        if outcome.generation != self._scan_inflight:
            if outcome.ack is not None:
                outcome.ack.set()
            self._record_command_error()
            return True
        if outcome.prepared:
            if outcome.ack is None:
                raise RuntimeError("invalid scanner validation handshake")
            outcome.ack.set()
            while True:
                try:
                    outcome = self._scan_results.get(timeout=0.05)
                    break
                except Empty:
                    with self._lock:
                        cancel = self._scan_cancel
                    if self._stop.is_set() and cancel is not None:
                        cancel.set()
            if (
                type(outcome) is not _ScanOutcome
                or outcome.source is not self._scan_lane_source
            ):
                self._record_command_error()
                return True
            if outcome.generation != self._scan_inflight or outcome.prepared:
                self._record_command_error()
                return True
        with self._lock:
            cancel = self._scan_cancel
        cancelled = self._stop.is_set() or cancel is not None and cancel.is_set()
        try:
            if outcome.error is not None and allow_apply and not cancelled:
                raise RuntimeError("scanner I/O failed") from outcome.error
            if allow_apply and not cancelled:
                ready = runtime.scanner.apply_scan(outcome.evidence, outcome.generation)
                for backup in ready:
                    self._record_event("backup_ready", getattr(backup, "display_name", None))
                self._claim_hint = True
        finally:
            with self._lock:
                self._scan_cancel = None
                self._scan_inflight = None
                self._scanner_state = "idle" if not self._stop.is_set() else "stopped"
        if allow_apply and self._scan_pending and not self._stop.is_set():
            self._scan_pending = False
            self._start_scan(runtime, self._clock())
        return True

    def _run_runtime_commands(self, runtime: RuntimeComponents) -> None:
        for _ in range(_MAX_COMMANDS_PER_TICK):
            with self._commands.execution_lease() as admitted:
                if not admitted:
                    return
                try:
                    command = self._commands.get_nowait()
                except Empty:
                    return
                if type(command) is not ControlCommand:
                    self._record_command_error()
                    continue
                self._claim_hint = True
                try:
                    if (
                        command.action is ControlAction.RETRY_UPLOAD
                        and command.sha256 is not None
                        and command.retry_revision is not None
                    ):
                        if self._native_mode:
                            raise ValueError("legacy retry unavailable in native mode")
                        runtime.worker.retry_now(
                            command.sha256, command.retry_revision
                        )
                    elif command.action is ControlAction.SCAN:
                        self.request_scan()
                    elif (command.action is ControlAction.CANCEL_UPLOAD
                          or self._native_mode and command.action is ControlAction.RESTART_WORKER):
                        if self._native_mode:
                            with self._lock:
                                active = self._native_active
                            if active is not None:
                                active.cancel.set()
                        else:
                            runtime.worker.cancel_current()
                    elif command.action is ControlAction.RESTART_WORKER:
                        runtime.worker.restart()
                    elif command.action in {
                        ControlAction.CONNECT,
                        ControlAction.RENEW,
                        ControlAction.DISCONNECT,
                    }:
                        self._queue_auth_command(runtime, command)
                    else:
                        self._record_command_error()
                except Exception:
                    self._record_command_error()

    def _serve_web(self) -> None:
        with self._lock:
            server = self._server
        try:
            if server is None or not callable(getattr(server, "handle_request", None)):
                raise RuntimeError("web server is unavailable")
            server.timeout = 0.0
            server.handle_request()
            server.timeout = 0.05
            with self._lock:
                self._web_ready = True
            self._web_started.set()
            while not self._stop.is_set():
                server.handle_request()
        except BaseException as error:
            with self._lock:
                self._web_failure = error
                self._web_ready = False
                self._connected_override = False
                self._service_error_code = "web_failed"
            self.request_stop()
        finally:
            with self._lock:
                self._web_ready = False
            self._web_started.set()
            if server is not None:
                try:
                    server.server_close()
                except BaseException as error:
                    with self._lock:
                        self._web_failure = error
                        self._shutdown_failure = error
                        self._service_error_code = "stop_failed"

    def _queue_auth_command(
        self, runtime: RuntimeComponents, command: ControlCommand
    ) -> None:
        if (
            runtime.auth_client is None
            or self._login_url_broker is None
        ):
            raise ValueError("authentication unavailable")
        with self._lock:
            self._auth_revision += 1
            revision = self._auth_revision
            self._connected_override = False
            self._clear_native_history()
        if (
            command.action in {ControlAction.CONNECT, ControlAction.RENEW}
            and command.login_deadline is not None
            and command.login_deadline <= monotonic()
        ):
            self._login_url_broker.cancel(command.user_id, command.command_id)
            with self._lock:
                self._connected_override = False
                self._service_error_code = "auth_failed"
            return
        with self._lock:
            active_cancel = self._auth_cancel
            active_user = self._auth_user_id
            active_command_id = self._auth_command_id
            pending = tuple(self._proton_pending)
        if active_cancel is not None:
            active_cancel.set()
        if active_user is not None and active_command_id is not None:
            self._login_url_broker.cancel(active_user, active_command_id)
        for kind, raw_work in pending:
            if kind == "auth" and type(raw_work) is _AuthWork:
                raw_work.cancel.set()

        callback = None
        if command.action is ControlAction.DISCONNECT:
            self._login_url_broker.cancel(command.user_id)
        else:
            try:
                callback = self._login_url_broker.begin(command)
            except ValueError:
                if (
                    command.login_deadline is not None
                    and command.login_deadline <= monotonic()
                ):
                    with self._lock:
                        self._service_error_code = "auth_failed"
                    return
                raise
        if command.action in {ControlAction.RENEW, ControlAction.DISCONNECT}:
            runtime.worker.cancel_current()
            with self._lock:
                self._connected_override = False
        work = _AuthWork(
            command.action,
            command.user_id,
            command.command_id,
            callback,
            Event(),
            command.login_deadline
            if command.login_deadline is not None
            else monotonic() + 120,
            revision,
        )
        try:
            with self._lock:
                self._enqueue_proton_pending("auth", work)
                self._history_auth_pending = revision
        except BaseException:
            self._login_url_broker.cancel(
                command.user_id, command.command_id
            )
            raise

    def _execute_auth_work(
        self, runtime: RuntimeComponents, raw_work: object
    ) -> _AuthResult:
        if type(raw_work) is not _AuthWork or runtime.auth_client is None:
            raise RuntimeError("invalid auth job")
        work = raw_work
        if work.action == "probe":
            try:
                if work.login_deadline is None:
                    connected = runtime.auth_client.is_authenticated(cancel=work.cancel)
                else:
                    connected = runtime.auth_client.is_authenticated(
                        cancel=work.cancel, deadline=work.login_deadline
                    )
            except Exception:
                return _AuthResult(work, False, False, work.cancel.is_set())
            return _AuthResult(work, True, connected is True)
        if work.action is ControlAction.DISCONNECT:
            try:
                runtime.auth_client.logout(
                    cancel=work.cancel, deadline=work.login_deadline
                )
            except Exception:
                return _AuthResult(work, False, False, work.cancel.is_set())
            return _AuthResult(work, True, False)
        if work.login_deadline is None or work.login_deadline <= monotonic():
            return _AuthResult(work, False, False, True)
        if work.action is ControlAction.RENEW:
            try:
                runtime.auth_client.logout(
                    cancel=work.cancel, deadline=work.login_deadline
                )
            except Exception:
                return _AuthResult(work, False, False, work.cancel.is_set())
            if work.cancel.is_set():
                return _AuthResult(work, False, False, True)
        try:
            if work.login_deadline <= monotonic():
                return _AuthResult(work, False, False, True)
            runtime.auth_client.start_login(
                work.callback,
                work.cancel,
                deadline=work.login_deadline,
            )
            authenticated = runtime.auth_client.is_authenticated(
                cancel=work.cancel, deadline=work.login_deadline
            )
        except Exception:
            return _AuthResult(work, False, False, work.cancel.is_set())
        return _AuthResult(work, authenticated is True, authenticated is True)

    def _apply_auth_result(
        self, raw_result: object, runtime: RuntimeComponents | None = None
    ) -> None:
        if type(raw_result) is not _AuthResult:
            raise RuntimeError("invalid auth result")
        result = raw_result
        work = result.work
        if self._login_url_broker is not None:
            self._login_url_broker.cancel(work.user_id, work.command_id)
        with self._lock:
            if self._history_auth_pending == work.revision:
                self._history_auth_pending = None
                self._clear_native_history()
            if work.revision != self._auth_revision:
                stale = True
            else:
                stale = False
            if stale:
                if self._auth_command_id == work.command_id:
                    self._auth_cancel = None
                    self._auth_user_id = None
                    self._auth_command_id = None
            else:
                self._auth_cancel = None
                self._auth_user_id = None
                self._auth_command_id = None
                self._connected_override = result.connected is True
                if result.succeeded:
                    if self._service_error_code == "auth_failed":
                        self._service_error_code = None
                elif work.action != "probe" or self._service_error_code is None:
                    self._service_error_code = "auth_failed"
        if (
            not stale
            and not result.cancelled
            and not work.cancel.is_set()
            and result.succeeded
            and result.connected is True
            and runtime is not None
        ):
            # Backups parked while no session existed would otherwise never be
            # claimed again (claim_next only selects READY/RETRY_WAIT rows).
            try:
                runtime.worker.resume_after_authentication()
            except Exception:
                self._record_command_error()
        if not stale:
            self._record_event("proton_connected" if result.connected is True else "proton_disconnected")

    def _record_command_error(self) -> None:
        self._record_event("command_rejected")
        with self._lock:
            self._service_error_code = "command_rejected"

    def _record_event(self, code: str, backup_name: str | None = None) -> None:
        if self._event_log is not None:
            try:
                self._event_log.record(code, backup_name=backup_name)
            except Exception:
                pass
