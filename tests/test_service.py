from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
import stat
from threading import Event, Lock, Thread, get_ident
from tempfile import TemporaryDirectory
from time import monotonic
import unittest
from unittest.mock import patch
from queue import Queue

from proton_backup.service import (
    BackupService,
    RuntimeComponents,
    ShutdownFailureError,
    ShutdownTimeoutError,
)
from proton_backup.web import ControlAction, ControlCommand
from proton_backup import web as web_module
from proton_backup.process import ProtonLoginSecretEvent
from proton_backup.worker import ServiceSnapshot
from proton_backup import __main__ as entrypoint
from proton_backup import service as service_module


NOW = datetime(2026, 8, 11, 10, 0, tzinfo=UTC)


def empty_snapshot() -> ServiceSnapshot:
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


class FakeStore:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.closed = False

    def close(self) -> None:
        self.events.append("close")
        self.closed = True


class FakeScanner:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.scan_count = 0
        self.scanned = Event()

    def scan(self, _now: datetime) -> list[object]:
        self.events.append("scan")
        self.scan_count += 1
        self.scanned.set()
        return []

    def prepare_scan(self, generation: int, now: datetime) -> tuple[int, datetime]:
        return generation, now

    def collect_scan(
        self, baseline: tuple[int, datetime], cancel: Event
    ) -> tuple[int, datetime]:
        if cancel.is_set():
            return baseline
        self.events.append("scan")
        self.scan_count += 1
        self.scanned.set()
        return baseline

    def apply_scan(
        self, evidence: tuple[int, datetime], generation: int
    ) -> list[object]:
        if evidence[0] != generation:
            raise AssertionError("stale fake scan evidence")
        return []

    def validate_scan(self, evidence, cancel: Event):
        class Validation:
            def __init__(self, value) -> None:
                self.evidence = value

            def close(self) -> bool:
                return True

        return Validation(evidence)


class FakeWorker:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.ran = Event()
        self.cancelled = False
        self.recover_thread: int | None = None
        self.retry_call: tuple[str, int, int] | None = None
        self.retry_called = Event()
        self.restart_count = 0
        self.run_threads: set[int] = set()
        self.cancel_threads: list[int] = []
        self.restart_threads: list[int] = []
        self.external_active = False
        self.external_generation = 0
        self.resume_threads: list[int] = []

    def recover_startup(self) -> bool:
        self.events.append("recover")
        self.recover_thread = get_ident()
        return True

    def run_once(self, _now: datetime) -> None:
        self.events.append("worker")
        self.run_threads.add(get_ident())
        self.ran.set()

    def prepare_external(self, now: datetime):
        if self.external_active:
            return None
        self.external_active = True
        self.external_generation += 1
        return self.external_generation, now

    def execute_external(self, work):
        self.run_once(work[1])
        return work

    def apply_external(self, result):
        self.external_active = False
        return None

    def abort_external(self) -> None:
        self.external_active = False

    def watchdog(self) -> bool:
        return False

    def snapshot(self) -> ServiceSnapshot:
        return empty_snapshot()

    def cancel_current(self) -> bool:
        self.events.append("cancel")
        self.cancelled = True
        self.cancel_threads.append(get_ident())
        return True

    def resume_after_authentication(self) -> int:
        self.events.append("resume")
        self.resume_threads.append(get_ident())
        return 0

    def retry_now(self, sha256: str, revision: int) -> None:
        self.retry_call = (sha256, revision, get_ident())
        self.retry_called.set()

    def restart(self) -> None:
        self.events.append("restart")
        self.restart_count += 1
        self.restart_threads.append(get_ident())


class FakeServer:
    def __init__(self) -> None:
        self.closed = Event()
        self.timeout = 0.01

    def handle_request(self) -> None:
        self.closed.wait(self.timeout)

    def serve_forever(self, poll_interval: float = 0.1) -> None:
        self.closed.wait()

    def shutdown(self) -> None:
        self.closed.set()

    def server_close(self) -> None:
        self.closed.set()


class BackupServiceTests(unittest.TestCase):
    @staticmethod
    def _capture_failure(
        failures: list[BaseException], operation
    ) -> None:
        try:
            operation()
        except BaseException as error:
            failures.append(error)

    def test_startup_scans_before_worker_and_serves_status(self) -> None:
        events: list[str] = []
        store = FakeStore(events)
        scanner = FakeScanner(events)
        worker = FakeWorker(events)
        server = FakeServer()
        service = BackupService(
            runtime_factory=lambda: RuntimeComponents(store, scanner, worker),
            web_server_factory=lambda _snapshot, _commands: server,
            clock=lambda: NOW,
        )
        self.addCleanup(service.stop)

        service.start()
        self.assertTrue(worker.ran.wait(1))

        self.assertLess(events.index("scan"), events.index("worker"))
        self.assertTrue(service.snapshot().web_ready)

    def test_shutdown_cancels_child_and_closes_database(self) -> None:
        events: list[str] = []
        store = FakeStore(events)
        worker = FakeWorker(events)
        service = BackupService(
            runtime_factory=lambda: RuntimeComponents(
                store, FakeScanner(events), worker
            ),
            web_server_factory=lambda _snapshot, _commands: FakeServer(),
            clock=lambda: NOW,
        )
        service.start()
        self.assertTrue(worker.ran.wait(1))

        service.stop(timeout=1)

        self.assertTrue(worker.cancelled)
        self.assertTrue(store.closed)

    def test_successful_authentication_requeues_parked_backups_on_owner(self) -> None:
        events: list[str] = []
        worker = FakeWorker(events)

        class AuthClient:
            def is_authenticated(self, *, cancel: Event) -> bool:
                return True

            def start_login(self, callback, cancel: Event, *, deadline=None) -> None:
                raise AssertionError("no login expected")

            def logout(self, *, cancel: Event) -> None:
                raise AssertionError("no logout expected")

        service = BackupService(
            runtime_factory=lambda: RuntimeComponents(
                FakeStore(events), FakeScanner(events), worker, AuthClient()
            ),
            web_server_factory=lambda _snapshot, _commands: FakeServer(),
            clock=lambda: NOW,
        )
        service.start()
        try:
            deadline = monotonic() + 2
            while not worker.resume_threads and monotonic() < deadline:
                Event().wait(0.01)
        finally:
            service.stop(timeout=5)

        self.assertEqual(worker.resume_threads, [worker.recover_thread])

    def test_idle_runtime_does_not_poll_for_claims_continuously(self) -> None:
        events: list[str] = []

        class IdleWorker(FakeWorker):
            def __init__(self, values: list[str]) -> None:
                super().__init__(values)
                self.prepare_calls = 0

            def prepare_external(self, now: datetime):
                self.prepare_calls += 1
                return None

        worker = IdleWorker(events)
        service = BackupService(
            runtime_factory=lambda: RuntimeComponents(
                FakeStore(events), FakeScanner(events), worker
            ),
            web_server_factory=lambda _snapshot, _commands: FakeServer(),
            clock=lambda: NOW,
        )
        service.start()
        try:
            Event().wait(1.0)
            calls = worker.prepare_calls
        finally:
            service.stop(timeout=5)

        # Previously ~100 claim transactions per second while idle.
        self.assertGreaterEqual(calls, 1)
        self.assertLessEqual(calls, 5)

    def test_failed_store_close_does_not_keep_owner_thread_alive(self) -> None:
        events: list[str] = []

        class AlwaysFailingCloseStore(FakeStore):
            def close(self) -> None:
                if not self.closed:
                    raise OSError("simulated persistent close failure")

        store = AlwaysFailingCloseStore(events)
        def cleanup():
            store.closed = True
            try:
                service.stop(timeout=1)
            except ShutdownFailureError:
                pass

        self.addCleanup(cleanup)
        service = BackupService(
            runtime_factory=lambda: RuntimeComponents(
                store, FakeScanner(events), FakeWorker(events)
            ),
            web_server_factory=lambda _snapshot, _commands: FakeServer(),
            clock=lambda: NOW,
        )
        with patch.object(service_module, "_CLEANUP_RETRY_WINDOW_SECONDS", 0.2, create=True):
            service.start()
            with self.assertRaises(ShutdownFailureError):
                service.stop(timeout=1)
            deadline = monotonic() + 3
            while monotonic() < deadline and any(
                thread.name == "proton-backup-runtime" and thread.is_alive()
                for thread in __import__("threading").enumerate()
            ):
                Event().wait(0.05)

        self.assertFalse(
            any(
                thread.name == "proton-backup-runtime" and thread.is_alive()
                for thread in __import__("threading").enumerate()
            )
        )
        self.assertEqual(service.snapshot().last_error_code, "stop_failed")

    def test_store_close_failure_makes_shutdown_fail_closed(self) -> None:
        events: list[str] = []

        class FailingCloseStore(FakeStore):
            def __init__(self, values: list[str]) -> None:
                super().__init__(values)
                self.fail_close = True

            def close(self) -> None:
                self.events.append("close")
                if self.fail_close:
                    raise OSError("simulated close failure")
                self.closed = True

        store = FailingCloseStore(events)
        service = BackupService(
            runtime_factory=lambda: RuntimeComponents(
                store, FakeScanner(events), FakeWorker(events)
            ),
            web_server_factory=lambda _snapshot, _commands: FakeServer(),
            clock=lambda: NOW,
        )
        service.start()

        failure_type = getattr(
            __import__("proton_backup.service", fromlist=["ShutdownFailureError"]),
            "ShutdownFailureError",
            RuntimeError,
        )
        with self.assertRaises(failure_type):
            service.stop(timeout=1)

        snapshot = service.snapshot()
        self.assertFalse(snapshot.web_ready)
        self.assertFalse(snapshot.connected)
        self.assertEqual(snapshot.last_error_code, "stop_failed")
        store.fail_close = False
        service.stop(timeout=1)

    def test_second_stop_retries_owner_store_close_after_transient_failure(self) -> None:
        events: list[str] = []

        class FailsOnceStore(FakeStore):
            def __init__(self, values: list[str]) -> None:
                super().__init__(values)
                self.close_calls = 0

            def close(self) -> None:
                self.close_calls += 1
                self.events.append("close")
                if self.close_calls == 1:
                    raise OSError("transient close failure")
                self.closed = True

        store = FailsOnceStore(events)
        service = BackupService(
            runtime_factory=lambda: RuntimeComponents(
                store, FakeScanner(events), FakeWorker(events)
            ),
            web_server_factory=lambda _snapshot, _commands: FakeServer(),
            clock=lambda: NOW,
        )
        service.start()

        with self.assertRaises(ShutdownFailureError):
            service.stop(timeout=1)
        service.stop(timeout=1)

        self.assertTrue(store.closed)
        self.assertEqual(store.close_calls, 2)

    def test_permanent_owner_store_close_failure_is_never_silently_suppressed(self) -> None:
        events: list[str] = []

        class AlwaysFailingStore(FakeStore):
            def __init__(self, values: list[str]) -> None:
                super().__init__(values)
                self.close_calls = 0

            def close(self) -> None:
                self.close_calls += 1
                self.events.append("close")
                if not self.closed:
                    raise OSError("permanent close failure")

        store = AlwaysFailingStore(events)
        service = BackupService(
            runtime_factory=lambda: RuntimeComponents(
                store, FakeScanner(events), FakeWorker(events)
            ),
            web_server_factory=lambda _snapshot, _commands: FakeServer(),
            clock=lambda: NOW,
        )
        service.start()

        with self.assertRaises(ShutdownFailureError):
            service.stop(timeout=1)
        with self.assertRaises(ShutdownFailureError):
            service.stop(timeout=1)

        self.assertEqual(store.close_calls, 2)
        store.closed = True
        service.stop(timeout=1)

    def test_abort_failure_still_stops_lanes_and_attempts_store_close(self) -> None:
        events: list[str] = []
        store = FakeStore(events)
        external_started = Event()
        external_release = Event()

        class AbortFailingWorker(FakeWorker):
            def execute_external(self, work):
                external_started.set()
                external_release.wait(2)
                return work

            def cancel_current(self) -> bool:
                external_release.set()
                return super().cancel_current()

            def abort_external(self) -> None:
                self.external_active = False
                raise RuntimeError("abort cleanup failed")

        service = BackupService(
            runtime_factory=lambda: RuntimeComponents(
                store, FakeScanner(events), AbortFailingWorker(events)
            ),
            web_server_factory=lambda _snapshot, _commands: FakeServer(),
            clock=lambda: NOW,
        )
        service.start()
        self.assertTrue(external_started.wait(1))

        with self.assertRaises(ShutdownFailureError):
            service.stop(timeout=1)

        self.assertTrue(store.closed)
        self.assertFalse(service._scan_thread.is_alive())
        self.assertFalse(service._proton_thread.is_alive())

    def test_cancel_failure_cannot_escape_request_stop_or_skip_cleanup(self) -> None:
        events: list[str] = []
        store = FakeStore(events)

        class CancelFailingWorker(FakeWorker):
            def cancel_current(self) -> bool:
                self.cancelled = True
                raise RuntimeError("unsafe cancel detail")

        service = BackupService(
            runtime_factory=lambda: RuntimeComponents(
                store, FakeScanner(events), CancelFailingWorker(events)
            ),
            web_server_factory=lambda _snapshot, _commands: FakeServer(),
            clock=lambda: NOW,
        )
        service.start()

        service.request_stop()
        with self.assertRaises(ShutdownFailureError) as raised:
            service.stop(timeout=1)

        self.assertIn("worker_cancel", raised.exception.component_codes)
        self.assertTrue(store.closed)
        self.assertFalse(service._scan_thread.is_alive())
        self.assertFalse(service._proton_thread.is_alive())

    def test_stop_timeout_is_positive_and_never_exceeds_twenty_seconds(self) -> None:
        for invalid in (True, 0, -1, 20.001, float("nan")):
            with self.subTest(timeout=invalid):
                service = BackupService(
                    runtime_factory=lambda: RuntimeComponents(
                        FakeStore([]), FakeScanner([]), FakeWorker([])
                    ),
                    web_server_factory=lambda _snapshot, _commands: FakeServer(),
                    clock=lambda: NOW,
                )
                with self.assertRaises(ValueError):
                    service.stop(timeout=invalid)

    def test_stop_remains_bounded_when_server_shutdown_blocks(self) -> None:
        events: list[str] = []

        class BlockingShutdownServer(FakeServer):
            def __init__(self) -> None:
                super().__init__()
                self.shutdown_started = Event()
                self.release_shutdown = Event()

            def server_close(self) -> None:
                self.shutdown_started.set()
                self.release_shutdown.wait()
                super().server_close()

        server = BlockingShutdownServer()
        service = BackupService(
            runtime_factory=lambda: RuntimeComponents(
                FakeStore(events), FakeScanner(events), FakeWorker(events)
            ),
            web_server_factory=lambda _snapshot, _commands: server,
            clock=lambda: NOW,
        )
        self.addCleanup(server.release_shutdown.set)
        service.start()

        started = monotonic()
        timeout_error = getattr(
            __import__("proton_backup.service", fromlist=["ShutdownTimeoutError"]),
            "ShutdownTimeoutError",
            RuntimeError,
        )
        with self.assertRaises(timeout_error):
            service.stop(timeout=0.1)
        elapsed = monotonic() - started

        self.assertTrue(server.shutdown_started.is_set())
        self.assertLess(elapsed, 0.5)
        self.assertFalse(service.snapshot().web_ready)
        self.assertEqual(service.snapshot().last_error_code, "stop_failed")
        server.release_shutdown.set()
        service.stop(timeout=1)

    def test_stop_never_claims_clean_with_a_tracked_process_reader(self) -> None:
        events: list[str] = []

        class StuckReader:
            name = "process-stdout"

            @staticmethod
            def join(_timeout: float) -> None:
                pass

            @staticmethod
            def is_alive() -> bool:
                return True

        service = BackupService(
            runtime_factory=lambda: RuntimeComponents(
                FakeStore(events), FakeScanner(events), FakeWorker(events)
            ),
            web_server_factory=lambda _snapshot, _commands: FakeServer(),
            clock=lambda: NOW,
        )
        service.start()

        timeout_error = getattr(
            __import__("proton_backup.service", fromlist=["ShutdownTimeoutError"]),
            "ShutdownTimeoutError",
            RuntimeError,
        )
        with patch(
            "proton_backup.service.active_process_reader_threads",
            return_value=(StuckReader(),),
        ):
            with self.assertRaises(timeout_error) as raised:
                service.stop(timeout=0.1)

        self.assertIn("process-stdout", raised.exception.pending_threads)
        self.assertEqual(service.snapshot().last_error_code, "stop_failed")
        service.stop(timeout=1)

    def test_server_close_failure_makes_shutdown_fail_closed(self) -> None:
        events: list[str] = []

        class FailingCloseServer(FakeServer):
            def server_close(self) -> None:
                raise OSError("simulated server close failure")

        service = BackupService(
            runtime_factory=lambda: RuntimeComponents(
                FakeStore(events), FakeScanner(events), FakeWorker(events)
            ),
            web_server_factory=lambda _snapshot, _commands: FailingCloseServer(),
            clock=lambda: NOW,
        )
        service.start()

        failure_type = getattr(
            __import__("proton_backup.service", fromlist=["ShutdownFailureError"]),
            "ShutdownFailureError",
            RuntimeError,
        )
        with self.assertRaises(failure_type):
            service.stop(timeout=1)

        snapshot = service.snapshot()
        self.assertFalse(snapshot.web_ready)
        self.assertFalse(snapshot.connected)
        self.assertEqual(snapshot.last_error_code, "stop_failed")

    def test_retry_command_preserves_revision_on_store_owner_thread(self) -> None:
        events: list[str] = []
        worker = FakeWorker(events)
        command_queue = []
        service = BackupService(
            runtime_factory=lambda: RuntimeComponents(
                FakeStore(events), FakeScanner(events), worker
            ),
            web_server_factory=lambda _snapshot, commands: (
                command_queue.append(commands) or FakeServer()
            ),
            clock=lambda: NOW,
        )
        self.addCleanup(service.stop)
        service.start()
        sha256 = "a" * 64

        command_queue[0].put_nowait(
            ControlCommand(
                "b" * 32,
                ControlAction.RETRY_UPLOAD,
                "operator",
                sha256,
                17,
            )
        )

        self.assertTrue(worker.retry_called.wait(1))
        self.assertEqual(worker.retry_call, (sha256, 17, worker.recover_thread))

    def test_immediate_scan_requests_are_coalesced(self) -> None:
        events: list[str] = []
        scanner = FakeScanner(events)
        service = BackupService(
            runtime_factory=lambda: RuntimeComponents(
                FakeStore(events), scanner, FakeWorker(events)
            ),
            web_server_factory=lambda _snapshot, _commands: FakeServer(),
            clock=lambda: NOW,
        )
        self.addCleanup(service.stop)
        service.start()

        for _ in range(100):
            getattr(service, "request_scan", lambda: None)()

        deadline = __import__("time").monotonic() + 1
        while scanner.scan_count < 2 and __import__("time").monotonic() < deadline:
            Event().wait(0.01)
        self.assertEqual(scanner.scan_count, 2)

    def test_periodic_scan_runs_at_exact_sixty_second_boundary(self) -> None:
        events: list[str] = []
        scanner = FakeScanner(events)
        monotonic_time = [100.0]

        class AdvancingWorker(FakeWorker):
            def run_once(self, now: datetime) -> None:
                super().run_once(now)
                monotonic_time[0] = 160.0

        service = BackupService(
            runtime_factory=lambda: RuntimeComponents(
                FakeStore(events), scanner, AdvancingWorker(events)
            ),
            web_server_factory=lambda _snapshot, _commands: FakeServer(),
            clock=lambda: NOW,
        )
        self.addCleanup(service.stop)
        with patch(
            "proton_backup.service.monotonic",
            side_effect=lambda: monotonic_time[0],
        ):
            service.start()
            deadline = __import__("time").monotonic() + 1
            while (
                scanner.scan_count < 2
                and __import__("time").monotonic() < deadline
            ):
                Event().wait(0.01)

        self.assertEqual(scanner.scan_count, 2)

    def test_blocking_transfer_keeps_owner_scheduler_live(self) -> None:
        """A transfer must not prevent the owner from running the next scan."""
        events: list[str] = []
        scanner = FakeScanner(events)
        release_transfer = Event()
        transfer_started = Event()
        monotonic_time = [100.0]

        class BlockingWorker(FakeWorker):
            def run_once(self, now: datetime) -> None:
                super().run_once(now)
                transfer_started.set()
                release_transfer.wait()

        service = BackupService(
            runtime_factory=lambda: RuntimeComponents(
                FakeStore(events), scanner, BlockingWorker(events)
            ),
            web_server_factory=lambda _snapshot, _commands: FakeServer(),
            clock=lambda: NOW,
        )
        self.addCleanup(service.stop)
        self.addCleanup(release_transfer.set)
        with patch(
            "proton_backup.service.monotonic",
            side_effect=lambda: monotonic_time[0],
        ):
            service.start()
            self.assertTrue(transfer_started.wait(1))
            monotonic_time[0] = 161.0
            deadline = __import__("time").monotonic() + 0.2
            while scanner.scan_count < 2 and __import__("time").monotonic() < deadline:
                Event().wait(0.01)

        self.assertEqual(scanner.scan_count, 2)

    def test_blocking_transfer_keeps_owner_watchdog_live(self) -> None:
        events: list[str] = []
        release_transfer = Event()
        transfer_started = Event()
        watchdog_ran = Event()

        class BlockingWorker(FakeWorker):
            def execute_external(self, work):
                transfer_started.set()
                release_transfer.wait(2)
                return work

            def watchdog(self) -> bool:
                if transfer_started.is_set():
                    watchdog_ran.set()
                return False

        service = BackupService(
            runtime_factory=lambda: RuntimeComponents(
                FakeStore(events), FakeScanner(events), BlockingWorker(events)
            ),
            web_server_factory=lambda _snapshot, _commands: FakeServer(),
            clock=lambda: NOW,
        )
        self.addCleanup(release_transfer.set)
        self.addCleanup(service.stop)
        service.start()

        self.assertTrue(transfer_started.wait(1))
        self.assertTrue(watchdog_ran.wait(1))

    def test_stale_proton_result_is_acknowledged_without_releasing_active_job(self) -> None:
        events: list[str] = []
        started = Event()
        release = Event()

        class BlockingWorker(FakeWorker):
            def execute_external(self, work):
                started.set()
                release.wait(2)
                return work

        worker = BlockingWorker(events)
        service = BackupService(
            runtime_factory=lambda: RuntimeComponents(
                FakeStore(events), FakeScanner(events), worker
            ),
            web_server_factory=lambda _snapshot, _commands: FakeServer(),
            clock=lambda: NOW,
        )
        self.addCleanup(release.set)
        self.addCleanup(service.stop)
        service.start()
        self.assertTrue(started.wait(1))
        active_generation = service._proton_inflight
        service._proton_results.put_nowait(
            service_module._ProtonOutcome(
                active_generation - 1,
                "worker",
                object(),
                None,
                service._proton_lane_source,
            )
        )
        service._wake.set()
        deadline = monotonic() + 1
        while service.snapshot().last_error_code != "command_rejected" and monotonic() < deadline:
            Event().wait(0.005)
        self.assertEqual(service._proton_inflight, active_generation)
        self.assertEqual(service.snapshot().last_error_code, "command_rejected")
        release.set()

    def test_malformed_proton_result_cannot_clear_a_real_blocked_lane_guard(self) -> None:
        events: list[str] = []
        started = Event()
        release = Event()

        class BlockingWorker(FakeWorker):
            def execute_external(self, work):
                started.set()
                release.wait(2)
                return work

        service = BackupService(
            runtime_factory=lambda: RuntimeComponents(
                FakeStore(events), FakeScanner(events), BlockingWorker(events)
            ),
            web_server_factory=lambda _snapshot, _commands: FakeServer(),
            clock=lambda: NOW,
        )
        service.start()
        self.assertTrue(started.wait(1))
        active_generation = service._proton_inflight
        service._proton_results.put_nowait(object())

        try:
            service.request_stop()
            with self.assertRaises(ShutdownTimeoutError):
                service.stop(timeout=0.1)
            self.assertEqual(service._proton_inflight, active_generation)
        finally:
            release.set()
            deadline = monotonic() + 1
            while service._proton_thread.is_alive() and monotonic() < deadline:
                Event().wait(0.01)
            try:
                service.stop(timeout=1)
            except ShutdownFailureError:
                pass

    def test_malformed_scan_final_result_keeps_guard_until_authentic_lane_result(self) -> None:
        events: list[str] = []
        service = BackupService(
            runtime_factory=lambda: None,
            web_server_factory=lambda _snapshot, _commands: FakeServer(),
            clock=lambda: NOW,
        )
        runtime = RuntimeComponents(FakeStore(events), FakeScanner(events), FakeWorker(events))
        service._scan_inflight = 1
        service._scan_cancel = Event()
        ack = Event()
        service._scan_results.put_nowait(
            service_module._ScanOutcome(
                1, (1, NOW), None, ack, True, service._scan_lane_source
            )
        )
        completed: list[object] = []

        owner = Thread(
            target=lambda: completed.append(service._finish_scan(runtime, wait=0.1))
        )
        owner.start()
        self.assertTrue(ack.wait(1))
        service._scan_results.put_nowait(object())
        owner.join(1)

        self.assertFalse(owner.is_alive())
        self.assertEqual(completed, [True])
        self.assertEqual(service._scan_inflight, 1)
        self.assertEqual(service.snapshot().last_error_code, "command_rejected")

        service._scan_results.put_nowait(
            service_module._ScanOutcome(
                0, (0, NOW), None, source=service._scan_lane_source
            )
        )
        self.assertTrue(service._finish_scan(runtime))
        self.assertEqual(service._scan_inflight, 1)

        service._scan_results.put_nowait(
            service_module._ScanOutcome(
                1, (1, NOW), None, source=service._scan_lane_source
            )
        )
        self.assertTrue(service._finish_scan(runtime))
        self.assertIsNone(service._scan_inflight)

    def test_scanner_collects_off_owner_and_applies_on_store_owner(self) -> None:
        events: list[str] = []
        worker = FakeWorker(events)

        class ThreadRecordingScanner(FakeScanner):
            def __init__(self) -> None:
                super().__init__(events)
                self.prepare_threads: list[int] = []
                self.collect_threads: list[int] = []
                self.validate_threads: list[int] = []
                self.apply_threads: list[int] = []

            def prepare_scan(self, generation: int, now: datetime):
                self.prepare_threads.append(get_ident())
                return super().prepare_scan(generation, now)

            def collect_scan(self, baseline, cancel: Event):
                self.collect_threads.append(get_ident())
                return super().collect_scan(baseline, cancel)

            def apply_scan(self, evidence, generation: int):
                self.apply_threads.append(get_ident())
                return super().apply_scan(evidence, generation)

            def validate_scan(self, evidence, cancel: Event):
                self.validate_threads.append(get_ident())
                return super().validate_scan(evidence, cancel)

        scanner = ThreadRecordingScanner()
        service = BackupService(
            runtime_factory=lambda: RuntimeComponents(
                FakeStore(events), scanner, worker
            ),
            web_server_factory=lambda _snapshot, _commands: FakeServer(),
            clock=lambda: NOW,
        )
        self.addCleanup(service.stop)

        service.start()
        self.assertTrue(worker.ran.wait(1))

        self.assertEqual(scanner.prepare_threads, [worker.recover_thread])
        self.assertEqual(scanner.apply_threads, [worker.recover_thread])
        self.assertEqual(len(scanner.collect_threads), 1)
        self.assertNotEqual(scanner.collect_threads[0], worker.recover_thread)
        self.assertEqual(scanner.validate_threads, scanner.collect_threads)

    def test_stop_cancels_blocked_initial_scan_and_releases_startup(self) -> None:
        events: list[str] = []

        class BlockingInitialScanner(FakeScanner):
            def __init__(self) -> None:
                super().__init__(events)
                self.started = Event()
                self.cancel_seen = Event()
                self.release_legacy_scan = Event()

            def scan(self, _now: datetime) -> list[object]:
                self.started.set()
                self.release_legacy_scan.wait()
                return []

            def collect_scan(self, baseline, cancel: Event):
                self.started.set()
                cancel.wait(2)
                if cancel.is_set():
                    self.cancel_seen.set()
                return baseline

        scanner = BlockingInitialScanner()
        store = FakeStore(events)
        service = BackupService(
            runtime_factory=lambda: RuntimeComponents(
                store, scanner, FakeWorker(events)
            ),
            web_server_factory=lambda _snapshot, _commands: FakeServer(),
            clock=lambda: NOW,
        )
        failures: list[BaseException] = []
        starter = Thread(
            target=lambda: self._capture_failure(failures, service.start)
        )
        starter.start()
        self.assertTrue(scanner.started.wait(1))

        try:
            service.stop(timeout=0.5)
            starter.join(1)
            self.assertTrue(scanner.cancel_seen.is_set())
            self.assertFalse(starter.is_alive())
            self.assertTrue(store.closed)
            self.assertFalse(service.snapshot().web_ready)
            self.assertIsNotNone(service._scan_thread)
            self.assertFalse(service._scan_thread.is_alive())
        finally:
            scanner.release_legacy_scan.set()
            starter.join(2)

    def test_cancel_after_collection_before_owner_apply_is_a_true_noop(self) -> None:
        events: list[str] = []

        class AckBlockingScanner(FakeScanner):
            def __init__(self) -> None:
                super().__init__(events)
                self.validation_started = Event()
                self.apply_count = 0

            def validate_scan(self, evidence, cancel: Event):
                outer = self

                class Validation:
                    def __init__(self) -> None:
                        self.evidence = evidence

                    def finish(self, finish_cancel: Event):
                        outer.validation_started.set()
                        finish_cancel.wait(2)
                        return self.evidence

                return Validation()

            def apply_scan(self, evidence, generation: int):
                self.apply_count += 1
                return super().apply_scan(evidence, generation)

        scanner = AckBlockingScanner()
        service = BackupService(
            runtime_factory=lambda: RuntimeComponents(
                FakeStore(events), scanner, FakeWorker(events)
            ),
            web_server_factory=lambda _snapshot, _commands: FakeServer(),
            clock=lambda: NOW,
        )
        failures: list[BaseException] = []
        starter = Thread(
            target=lambda: self._capture_failure(failures, service.start)
        )
        starter.start()
        self.assertTrue(scanner.validation_started.wait(1))

        service.stop(timeout=1)
        starter.join(1)

        self.assertFalse(starter.is_alive())
        self.assertEqual(scanner.apply_count, 0)
        self.assertIsNotNone(service._scan_thread)
        self.assertFalse(service._scan_thread.is_alive())

    def test_scan_requests_coalesce_to_one_followup_while_collection_is_active(self) -> None:
        events: list[str] = []
        release_second = Event()
        second_started = Event()
        third_applied = Event()
        active_lock = Lock()

        class CoalescingScanner(FakeScanner):
            def __init__(self) -> None:
                super().__init__(events)
                self.generations: list[int] = []
                self.applied: list[int] = []
                self.active = 0
                self.max_active = 0

            def scan(self, _now: datetime) -> list[object]:
                return []

            def collect_scan(self, baseline, cancel: Event):
                generation = baseline[0]
                with active_lock:
                    self.active += 1
                    self.max_active = max(self.max_active, self.active)
                    self.generations.append(generation)
                try:
                    if generation == 2:
                        second_started.set()
                        while not cancel.is_set() and not release_second.is_set():
                            release_second.wait(0.01)
                    return baseline
                finally:
                    with active_lock:
                        self.active -= 1

            def apply_scan(self, evidence, generation: int):
                self.applied.append(generation)
                if generation == 3:
                    third_applied.set()
                return []

        scanner = CoalescingScanner()
        service = BackupService(
            runtime_factory=lambda: RuntimeComponents(
                FakeStore(events), scanner, FakeWorker(events)
            ),
            web_server_factory=lambda _snapshot, _commands: FakeServer(),
            clock=lambda: NOW,
        )
        self.addCleanup(service.stop)
        self.addCleanup(release_second.set)
        service.start()

        service.request_scan()
        self.assertTrue(second_started.wait(1))
        for _ in range(100):
            service.request_scan()
        release_second.set()
        self.assertTrue(third_applied.wait(1))
        Event().wait(0.05)

        self.assertEqual(scanner.generations, [1, 2, 3])
        self.assertEqual(scanner.applied, [1, 2, 3])
        self.assertEqual(scanner.max_active, 1)

    def test_commands_are_serialized_without_replacing_worker_loop(self) -> None:
        events: list[str] = []
        scanner = FakeScanner(events)
        worker = FakeWorker(events)
        factory_calls = [0]
        command_queue = []

        def runtime_factory() -> RuntimeComponents:
            factory_calls[0] += 1
            return RuntimeComponents(FakeStore(events), scanner, worker)

        service = BackupService(
            runtime_factory=runtime_factory,
            web_server_factory=lambda _snapshot, commands: (
                command_queue.append(commands) or FakeServer()
            ),
            clock=lambda: NOW,
        )
        self.addCleanup(service.stop)
        service.start()
        commands = command_queue[0]
        actions = (
            ControlAction.SCAN,
            ControlAction.SCAN,
            ControlAction.CANCEL_UPLOAD,
            ControlAction.RESTART_WORKER,
            ControlAction.RESTART_WORKER,
        )
        for index, action in enumerate(actions):
            commands.put_nowait(
                ControlCommand(f"{index:032x}", action, "operator")
            )

        deadline = __import__("time").monotonic() + 1
        while (
            worker.restart_count < 2
            and __import__("time").monotonic() < deadline
        ):
            Event().wait(0.01)

        self.assertEqual(factory_calls, [1])
        self.assertEqual(worker.restart_count, 2)
        self.assertTrue(worker.cancelled)
        self.assertEqual(set(worker.cancel_threads), {worker.recover_thread})
        self.assertEqual(set(worker.restart_threads), {worker.recover_thread})
        self.assertEqual(len(worker.run_threads), 1)
        scan_deadline = __import__("time").monotonic() + 1
        while (
            scanner.scan_count < 2
            and __import__("time").monotonic() < scan_deadline
        ):
            Event().wait(0.01)
        self.assertEqual(scanner.scan_count, 2)

    def test_startup_failure_closes_store_and_never_starts_web(self) -> None:
        events: list[str] = []
        store = FakeStore(events)
        web_created = []

        class FailingRecoveryWorker(FakeWorker):
            def recover_startup(self) -> bool:
                self.events.append("recover")
                raise RuntimeError("database is corrupt")

        service = BackupService(
            runtime_factory=lambda: RuntimeComponents(
                store, FakeScanner(events), FailingRecoveryWorker(events)
            ),
            web_server_factory=lambda _snapshot, _commands: (
                web_created.append(True) or FakeServer()
            ),
            clock=lambda: NOW,
        )

        with self.assertRaisesRegex(RuntimeError, "startup failed"):
            service.start()

        self.assertTrue(store.closed)
        self.assertEqual(web_created, [])
        self.assertFalse(service.snapshot().web_ready)

    def test_web_bind_failure_releases_runtime_and_closes_store(self) -> None:
        events: list[str] = []
        store = FakeStore(events)
        service = BackupService(
            runtime_factory=lambda: RuntimeComponents(
                store, FakeScanner(events), FakeWorker(events)
            ),
            web_server_factory=lambda _snapshot, _commands: (_ for _ in ()).throw(
                OSError("private bind detail")
            ),
            clock=lambda: NOW,
        )

        try:
            failure: BaseException | None = None
            try:
                service.start()
            except BaseException as error:
                failure = error
            self.assertIsInstance(failure, RuntimeError)
            self.assertIn("startup failed", str(failure))
            deadline = __import__("time").monotonic() + 1
            while not store.closed and __import__("time").monotonic() < deadline:
                Event().wait(0.01)
            self.assertTrue(store.closed)
            self.assertFalse(service.snapshot().web_ready)
        finally:
            service.stop(timeout=1)

    def test_web_loop_exception_rejects_startup_and_stops_runtime(self) -> None:
        events: list[str] = []
        store = FakeStore(events)

        class FailingServer(FakeServer):
            def handle_request(self) -> None:
                raise RuntimeError("private listener detail")

        service = BackupService(
            runtime_factory=lambda: RuntimeComponents(
                store, FakeScanner(events), FakeWorker(events)
            ),
            web_server_factory=lambda _snapshot, _commands: FailingServer(),
            clock=lambda: NOW,
        )
        self.addCleanup(service.stop)
        with self.assertRaisesRegex(RuntimeError, "startup failed"):
            service.start()
        deadline = __import__("time").monotonic() + 1
        while not store.closed and __import__("time").monotonic() < deadline:
            Event().wait(0.01)

        snapshot = service.snapshot()
        self.assertTrue(store.closed)
        self.assertFalse(snapshot.web_ready)
        self.assertEqual(snapshot.last_error_code, "web_failed")

    def test_request_stop_releases_start_while_web_probe_is_blocked(self) -> None:
        events: list[str] = []

        class BlockingProbeServer(FakeServer):
            def __init__(self) -> None:
                super().__init__()
                self.probe_started = Event()
                self.release_probe = Event()

            def handle_request(self) -> None:
                self.probe_started.set()
                self.release_probe.wait(2)

        server = BlockingProbeServer()
        service = BackupService(
            runtime_factory=lambda: RuntimeComponents(
                FakeStore(events), FakeScanner(events), FakeWorker(events)
            ),
            web_server_factory=lambda _snapshot, _commands: server,
            clock=lambda: NOW,
        )
        failures: list[BaseException] = []
        starter = Thread(
            target=lambda: self._capture_failure(failures, service.start)
        )
        starter.start()
        self.assertTrue(server.probe_started.wait(1))

        service.request_stop()
        starter.join(0.25)

        try:
            self.assertFalse(starter.is_alive())
            self.assertTrue(failures)
        finally:
            server.release_probe.set()
            starter.join(1)
            service.stop(timeout=1)

    def test_worker_exception_stops_service_fail_closed(self) -> None:
        events: list[str] = []
        store = FakeStore(events)

        class FailingWorker(FakeWorker):
            def run_once(self, _now: datetime) -> None:
                raise RuntimeError("secret child detail")

        service = BackupService(
            runtime_factory=lambda: RuntimeComponents(
                store, FakeScanner(events), FailingWorker(events)
            ),
            web_server_factory=lambda _snapshot, _commands: FakeServer(),
            clock=lambda: NOW,
        )
        self.addCleanup(service.stop)
        service.start()
        deadline = __import__("time").monotonic() + 1
        while not store.closed and __import__("time").monotonic() < deadline:
            Event().wait(0.01)

        snapshot = service.snapshot()
        self.assertTrue(store.closed)
        self.assertFalse(snapshot.web_ready)
        self.assertEqual(snapshot.last_error_code, "worker_failed")

    def test_entrypoint_prepares_data_modes_and_requires_local_origin(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            private_root = root / "private"
            state_root = root / "state"
            options_path = root / "options.json"
            options_path.write_text(
                json.dumps(
                    {"home_assistant_origin": "https://ha.example.invalid"}
                ),
                encoding="utf-8",
            )
            prepare = getattr(entrypoint, "prepare_data_directories", lambda *_: None)
            load_origin = getattr(entrypoint, "load_home_assistant_origin", lambda *_: None)

            prepare(private_root, state_root)
            origin = load_origin(options_path)

            self.assertTrue(private_root.is_dir())
            self.assertTrue(state_root.is_dir())
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(private_root.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(state_root.stat().st_mode), 0o750)
            self.assertEqual(origin, "https://ha.example.invalid")

            options_path.write_text("{}", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_origin(options_path)

    def test_runtime_composition_bootstraps_before_opening_state(self) -> None:
        events: list[str] = []
        ready = [False]

        class Credentials:
            def __init__(self, root: Path) -> None:
                self.root = root

            def bootstrap(self) -> None:
                ready[0] = True
                events.append("bootstrap")

            def environment(self) -> dict[str, str]:
                return {"HOME": "/private/home"}

        class Store:
            def __init__(self, path: Path) -> None:
                if not ready[0]:
                    raise AssertionError("state opened before credentials")
                self.path = path
                events.append("store")

        class Runner:
            def __init__(self, environment: dict[str, str]) -> None:
                self.environment = environment

        class Client:
            def __init__(self, **kwargs: object) -> None:
                self.kwargs = kwargs

        class Retention:
            def __init__(self, client: object, state: object) -> None:
                self.client = client
                self.state = state

        class Scanner:
            def __init__(self, root: Path, store: object) -> None:
                self.root = root
                self.store = store

        class Worker:
            def __init__(self, store: object, client: object, retention: object) -> None:
                self.store = store
                self.client = client
                self.retention = retention

        compose = getattr(entrypoint, "compose_runtime", lambda **_: None)
        runtime = compose(
            private_root=Path("/private"),
            state_db=Path("/state/state.sqlite"),
            backup_root=Path("/backup"),
            credential_store_factory=Credentials,
            state_store_factory=Store,
            process_runner_factory=Runner,
            client_factory=Client,
            retention_factory=Retention,
            scanner_factory=Scanner,
            worker_factory=Worker,
        )

        self.assertIsInstance(runtime, RuntimeComponents)
        self.assertEqual(events, ["bootstrap", "store"])
        self.assertIs(runtime.scanner.store, runtime.store)
        self.assertIs(runtime.worker.store, runtime.store)
        self.assertIs(runtime.worker.retention.state, runtime.store)
        self.assertIs(runtime.auth_client, runtime.worker.client)
        self.assertEqual(
            runtime.worker.client.kwargs["runner"].environment["HOME"],
            "/private/home",
        )
        self.assertIsInstance(
            runtime.worker.client.kwargs["credential_store"],
            Credentials,
        )

    def test_web_composition_uses_only_immutable_local_origin(self) -> None:
        class Server:
            def __init__(self, host: str, port: int, controller: object) -> None:
                self.host = host
                self.port = port
                self.controller = controller

        compose = getattr(entrypoint, "compose_web_server", lambda **_: None)
        commands = Queue(maxsize=4)
        server = compose(
            snapshot_provider=lambda: replace(empty_snapshot(), web_ready=True),
            command_queue=commands,
            home_assistant_origin="https://ha.example.invalid",
            server_factory=Server,
        )
        self.assertIsNotNone(server)
        status = server.controller.handle(
            method="GET",
            target="/api/status",
            peer="172.30.32.2",
            headers={"X-Remote-User-Id": "operator"},
        )
        token = status.json()["csrf_token"]
        common = {
            "X-Remote-User-Id": "operator",
            "X-CSRF-Token": token,
            "Content-Type": "application/json",
            "Content-Length": "2",
        }
        accepted = server.controller.handle(
            method="POST",
            target="/api/scan",
            peer="172.30.32.2",
            headers={**common, "Origin": "https://ha.example.invalid"},
            body=b"{}",
        )
        rejected = server.controller.handle(
            method="POST",
            target="/api/scan",
            peer="172.30.32.2",
            headers={
                **common,
                "Origin": "https://attacker.invalid",
                "X-Forwarded-Host": "ha.example.invalid",
                "X-Forwarded-Proto": "https",
            },
            body=b"{}",
        )

        self.assertEqual(accepted.status, 202)
        self.assertEqual(rejected.status, 403)
        self.assertEqual(rejected.json(), {"error": {"code": "origin_rejected"}})

    def test_signal_runner_stops_bounded_and_restores_handlers(self) -> None:
        previous_term = object()
        previous_int = object()

        class Signals:
            SIGTERM = 15
            SIGINT = 2

            def __init__(self) -> None:
                self.handlers = {
                    self.SIGTERM: previous_term,
                    self.SIGINT: previous_int,
                }
                self.installed = Event()

            def signal(self, number: int, handler: object) -> object:
                previous = self.handlers[number]
                self.handlers[number] = handler
                if all(
                    callable(self.handlers[value])
                    for value in (self.SIGTERM, self.SIGINT)
                ):
                    self.installed.set()
                return previous

        class Service:
            def __init__(self) -> None:
                self.started = False
                self.stop_timeouts: list[float] = []

            def start(self) -> None:
                self.started = True

            def wait(self, timeout: float) -> bool:
                Event().wait(timeout)
                return False

            def stop(self, timeout: float = 20) -> None:
                self.stop_timeouts.append(timeout)

        signals = Signals()
        service = Service()
        run_service = getattr(entrypoint, "run_service", lambda *_args, **_kwargs: 1)
        result: list[int] = []
        thread = Thread(
            target=lambda: result.append(
                run_service(service, signal_module=signals, stop_timeout=20)
            )
        )
        thread.start()
        self.assertTrue(signals.installed.wait(1))

        signals.handlers[signals.SIGTERM](signals.SIGTERM, None)
        thread.join(1)

        self.assertFalse(thread.is_alive())
        self.assertTrue(service.started)
        self.assertEqual(service.stop_timeouts, [20])
        self.assertEqual(result, [0])
        self.assertIs(signals.handlers[signals.SIGTERM], previous_term)
        self.assertIs(signals.handlers[signals.SIGINT], previous_int)

    def test_signal_runner_restores_handlers_and_returns_nonzero_when_stop_fails(self) -> None:
        previous_term = object()
        previous_int = object()

        class Signals:
            SIGTERM = 15
            SIGINT = 2

            def __init__(self) -> None:
                self.handlers = {
                    self.SIGTERM: previous_term,
                    self.SIGINT: previous_int,
                }

            def signal(self, number: int, handler: object) -> object:
                previous = self.handlers[number]
                self.handlers[number] = handler
                return previous

        class Service:
            def start(self) -> None:
                return

            def wait(self, timeout: float) -> bool:
                return True

            def stop(self, timeout: float = 20) -> None:
                raise RuntimeError("noncooperative dependency")

        signals = Signals()
        result = entrypoint.run_service(
            Service(), signal_module=signals, stop_timeout=0.1
        )

        self.assertEqual(result, 1)
        self.assertIs(signals.handlers[signals.SIGTERM], previous_term)
        self.assertIs(signals.handlers[signals.SIGINT], previous_int)

    def test_signal_shutdown_timeout_restores_handlers_before_forced_exit(self) -> None:
        previous_term = object()
        previous_int = object()
        events: list[object] = []

        class Signals:
            SIGTERM = 15
            SIGINT = 2

            def __init__(self) -> None:
                self.handlers = {
                    self.SIGTERM: previous_term,
                    self.SIGINT: previous_int,
                }

            def signal(self, number: int, handler: object) -> object:
                previous = self.handlers[number]
                self.handlers[number] = handler
                if handler in {previous_term, previous_int}:
                    events.append(("restore", number))
                return previous

        signals = Signals()

        class Service:
            def start(self) -> None:
                signals.handlers[signals.SIGTERM](signals.SIGTERM, None)

            def wait(self, timeout: float) -> bool:
                return False

            def request_stop(self) -> None:
                return

            def stop(self, timeout: float = 20) -> None:
                raise ShutdownTimeoutError(("noncooperative",))

        forced: list[int] = []

        def force_exit(code: int) -> None:
            self.assertIs(signals.handlers[signals.SIGTERM], previous_term)
            self.assertIs(signals.handlers[signals.SIGINT], previous_int)
            events.append(("force", code))
            forced.append(code)

        result = entrypoint.run_service(
            Service(),
            signal_module=signals,
            stop_timeout=0.1,
            force_exit=force_exit,
        )

        self.assertEqual(result, 1)
        self.assertEqual(forced, [1])
        self.assertEqual(events[-1], ("force", 1))

    def test_clean_signal_shutdown_never_forces_exit(self) -> None:
        class Signals:
            SIGTERM = 15
            SIGINT = 2

            def __init__(self) -> None:
                self.handlers = {self.SIGTERM: object(), self.SIGINT: object()}

            def signal(self, number: int, handler: object) -> object:
                previous = self.handlers[number]
                self.handlers[number] = handler
                return previous

        signals = Signals()

        class Service:
            def start(self) -> None:
                signals.handlers[signals.SIGINT](signals.SIGINT, None)

            def wait(self, timeout: float) -> bool:
                return False

            def request_stop(self) -> None:
                return

            def stop(self, timeout: float = 20) -> None:
                return

        forced: list[int] = []
        result = entrypoint.run_service(
            Service(), signal_module=signals, force_exit=forced.append
        )

        self.assertEqual(result, 0)
        self.assertEqual(forced, [])

    def test_startup_error_does_not_force_exit_without_signal(self) -> None:
        class Signals:
            SIGTERM = 15
            SIGINT = 2

            def __init__(self) -> None:
                self.handlers = {self.SIGTERM: object(), self.SIGINT: object()}

            def signal(self, number: int, handler: object) -> object:
                previous = self.handlers[number]
                self.handlers[number] = handler
                return previous

        class Service:
            def start(self) -> None:
                raise ValueError("invalid configuration")

            def stop(self, timeout: float = 20) -> None:
                raise ShutdownFailureError("cleanup failed")

        forced: list[int] = []
        result = entrypoint.run_service(
            Service(), signal_module=Signals(), force_exit=forced.append
        )

        self.assertEqual(result, 1)
        self.assertEqual(forced, [])

    def test_stop_before_initial_scan_dispatch_never_starts_scanner_lane(self) -> None:
        events: list[str] = []
        recovery_started = Event()
        allow_recovery = Event()
        scanner = FakeScanner(events)

        class BlockingRecovery(FakeWorker):
            def recover_startup(self) -> bool:
                self.recover_thread = get_ident()
                recovery_started.set()
                allow_recovery.wait(2)
                return True

        service = BackupService(
            runtime_factory=lambda: RuntimeComponents(
                FakeStore(events), scanner, BlockingRecovery(events)
            ),
            web_server_factory=lambda _snapshot, _commands: FakeServer(),
            clock=lambda: NOW,
        )
        failures: list[BaseException] = []
        starter = Thread(
            target=lambda: self._capture_failure(failures, service.start)
        )
        starter.start()
        self.assertTrue(recovery_started.wait(1))

        service.request_stop()
        allow_recovery.set()
        starter.join(1)
        service.stop(timeout=1)

        self.assertFalse(starter.is_alive())
        self.assertEqual(scanner.scan_count, 0)

    def test_login_url_broker_is_command_bound_user_bound_and_one_shot(self) -> None:
        clock = [10.0]
        broker_type = getattr(web_module, "LoginUrlBroker", None)
        self.assertIsNotNone(broker_type)
        broker = broker_type(monotonic=lambda: clock[0])
        command = ControlCommand(
            "c" * 32,
            ControlAction.CONNECT,
            "operator-a",
        )
        callback = broker.begin(command)
        secret_event = ProtonLoginSecretEvent(
            callback,
            expires_at=70.0,
            monotonic=lambda: clock[0],
        )
        url = "https://account.proton.me/login?token=fake-one-shot"

        secret_event.inspect(f"Open {url}")
        secret_event.finish()
        clock[0] = 40.0

        self.assertIsNone(broker.consume("operator-b"))
        handoff = broker.consume("operator-a")
        self.assertIsNotNone(handoff)
        self.assertEqual(handoff.url, url)
        self.assertEqual(handoff.command_id, command.command_id)
        self.assertEqual(handoff.remaining_ms, 90_000)
        self.assertIsNone(broker.consume("operator-a"))
        view = broker.view("operator-a")
        self.assertIsNotNone(view)
        self.assertTrue(view.active)
        self.assertEqual(view.command_id, command.command_id)
        self.assertEqual(view.remaining_ms, 90_000)
        self.assertIsNone(view.url)
        clock[0] = 130.0
        self.assertIsNone(broker.view("operator-a"))

    def test_login_url_appears_once_only_in_matching_browser_status(self) -> None:
        broker = web_module.LoginUrlBroker(monotonic=lambda: 10.0)
        command = ControlCommand(
            "d" * 32,
            ControlAction.CONNECT,
            "operator-a",
        )
        secret_event = ProtonLoginSecretEvent(
            broker.begin(command),
            expires_at=70.0,
            monotonic=lambda: 10.0,
        )
        url = "https://account.proton.me/login?token=fake-browser-status"
        secret_event.inspect(f"Open {url}")
        secret_event.finish()
        try:
            controller = web_module.WebController(
                snapshot_provider=empty_snapshot,
                command_queue=Queue(maxsize=4),
                login_url_broker=broker,
            )
        except TypeError:
            self.fail("WebController has no one-shot login handoff")

        other = controller.handle(
            method="GET",
            target="/api/status",
            peer="172.30.32.2",
            headers={"X-Remote-User-Id": "operator-b"},
        ).json()
        matching = controller.handle(
            method="GET",
            target="/api/status",
            peer="172.30.32.2",
            headers={"X-Remote-User-Id": "operator-a"},
        ).json()
        repeated = controller.handle(
            method="GET",
            target="/api/status",
            peer="172.30.32.2",
            headers={"X-Remote-User-Id": "operator-a"},
        ).json()

        self.assertNotIn("login_url", other)
        self.assertFalse(other["login_active"])
        self.assertEqual(matching["login_url"], url)
        self.assertTrue(matching["login_active"])
        self.assertEqual(matching["login_generation"], command.command_id)
        self.assertEqual(matching["login_remaining_ms"], 120_000)
        self.assertNotIn("login_url", repeated)
        self.assertTrue(repeated["login_active"])
        self.assertEqual(repeated["login_generation"], command.command_id)
        self.assertEqual(repeated["login_remaining_ms"], 120_000)

    def test_connected_status_never_consumes_or_exposes_login_secret(self) -> None:
        broker = web_module.LoginUrlBroker(monotonic=lambda: 10.0)
        command = ControlCommand("e" * 32, ControlAction.CONNECT, "operator")
        publish = broker.begin(command)
        url = "https://account.proton.me/login?token=not-after-success"
        publish(url)
        controller = web_module.WebController(
            snapshot_provider=lambda: replace(
                empty_snapshot(), web_ready=True, connected=True
            ),
            command_queue=Queue(maxsize=4),
            login_url_broker=broker,
        )

        payload = controller.handle(
            method="GET",
            target="/api/status",
            peer="172.30.32.2",
            headers={"X-Remote-User-Id": "operator"},
        ).json()

        self.assertFalse(payload["login_active"])
        self.assertNotIn("login_url", payload)
        self.assertEqual(broker.consume("operator").url, url)

    def test_login_broker_terminal_cancel_is_generation_bound(self) -> None:
        broker = web_module.LoginUrlBroker(monotonic=lambda: 10.0)
        first = ControlCommand("a" * 32, ControlAction.CONNECT, "operator")
        second = ControlCommand("b" * 32, ControlAction.CONNECT, "operator")
        publish_first = broker.begin(first)
        publish_second = broker.begin(second)

        with self.assertRaises(RuntimeError):
            publish_first("https://account.proton.me/login?token=stale")
        broker.cancel("operator", first.command_id)
        publish_second("https://account.proton.me/login?token=current")

        current = broker.consume("operator")
        self.assertIsNotNone(current)
        self.assertEqual(current.command_id, second.command_id)

    def test_login_broker_uses_command_absolute_deadline_without_extension(self) -> None:
        clock = [100.0]
        broker = web_module.LoginUrlBroker(monotonic=lambda: clock[0])
        command = ControlCommand(
            "a" * 32,
            ControlAction.CONNECT,
            "operator",
            login_deadline=220.0,
        )
        publish = broker.begin(command)
        clock[0] = 219.0
        publish("https://account.proton.me/login?token=remaining")

        handoff = broker.consume("operator")

        self.assertIsNotNone(handoff)
        self.assertLessEqual(handoff.remaining_ms, 1000)
        clock[0] = 220.0
        self.assertIsNone(broker.view("operator"))

    def test_auth_commands_are_serialized_through_one_shot_broker(self) -> None:
        events: list[str] = []
        broker = web_module.LoginUrlBroker(monotonic=lambda: 10.0)
        command_queue = []

        class AuthClient:
            def __init__(self) -> None:
                self.login_count = 0
                self.logout_count = 0
                self.connected = False
                self.thread_ids: list[int] = []
                self.published = (Event(), Event())
                self.release = (Event(), Event())

            def start_login(self, callback, cancel: Event, *, deadline=None) -> None:
                self.thread_ids.append(get_ident())
                self.login_count += 1
                events.append(f"login-{self.login_count}")
                event = ProtonLoginSecretEvent(
                    callback,
                    expires_at=70.0,
                    monotonic=lambda: 10.0,
                )
                event.inspect(
                    "Open https://account.proton.me/login?token="
                    f"fake-{self.login_count}"
                )
                event.finish()
                index = self.login_count - 1
                self.published[index].set()
                while not self.release[index].is_set() and not cancel.is_set():
                    cancel.wait(0.01)
                if cancel.is_set():
                    return
                self.connected = True

            def logout(self, *, cancel: Event, deadline=None) -> None:
                self.thread_ids.append(get_ident())
                self.logout_count += 1
                events.append(f"logout-{self.logout_count}")
                self.connected = False

            def is_authenticated(self, cancel: Event | None = None, deadline=None) -> bool:
                return self.connected

        auth = AuthClient()

        class AuthAwareWorker(FakeWorker):
            def snapshot(self) -> ServiceSnapshot:
                return replace(empty_snapshot(), connected=auth.connected)

        worker = AuthAwareWorker(events)
        try:
            service = BackupService(
                runtime_factory=lambda: RuntimeComponents(
                    FakeStore(events), FakeScanner(events), worker, auth
                ),
                web_server_factory=lambda _snapshot, commands: (
                    command_queue.append(commands) or FakeServer()
                ),
                login_url_broker=broker,
                clock=lambda: NOW,
            )
        except TypeError:
            self.fail("BackupService has no injected auth command boundary")
        self.addCleanup(service.stop)
        service.start()

        def send(action: ControlAction, identity: str) -> None:
            command_queue[0].put_nowait(
                ControlCommand(identity * 32, action, "operator")
            )

        send(ControlAction.CONNECT, "1")
        self.assertTrue(auth.published[0].wait(1))
        deadline = __import__("time").monotonic() + 1
        first_url = None
        while first_url is None and __import__("time").monotonic() < deadline:
            first_url = broker.consume("operator")
            Event().wait(0.01)
        self.assertEqual(
            None if first_url is None else first_url.url,
            "https://account.proton.me/login?token=fake-1",
        )
        auth.release[0].set()
        deadline = __import__("time").monotonic() + 1
        while not service.snapshot().connected and __import__("time").monotonic() < deadline:
            Event().wait(0.01)
        self.assertTrue(service.snapshot().connected)
        self.assertIsNone(broker.view("operator"))

        send(ControlAction.RENEW, "2")
        self.assertTrue(auth.published[1].wait(1))
        second_url = None
        deadline = __import__("time").monotonic() + 1
        while second_url is None and __import__("time").monotonic() < deadline:
            second_url = broker.consume("operator")
            Event().wait(0.01)
        self.assertEqual(
            None if second_url is None else second_url.url,
            "https://account.proton.me/login?token=fake-2",
        )
        auth.release[1].set()
        deadline = __import__("time").monotonic() + 1
        while (
            (
                not service.snapshot().connected
                or broker.view("operator") is not None
            )
            and __import__("time").monotonic() < deadline
        ):
            Event().wait(0.01)
        self.assertTrue(service.snapshot().connected)
        self.assertIsNone(broker.view("operator"))
        auth_events = [
            event
            for event in events
            if event.startswith("login-") or event.startswith("logout-")
        ]
        self.assertEqual(auth_events, ["login-1", "logout-1", "login-2"])

        send(ControlAction.DISCONNECT, "3")
        deadline = __import__("time").monotonic() + 1
        while (
            (
                auth.logout_count < 2
                or service.snapshot().connected
                or broker.view("operator") is not None
            )
            and __import__("time").monotonic() < deadline
        ):
            Event().wait(0.01)
        self.assertEqual(auth.logout_count, 2)
        self.assertIsNone(broker.consume("operator"))
        self.assertFalse(service.snapshot().connected)
        self.assertEqual(set(auth.thread_ids), worker.run_threads)

    def test_expired_queued_login_deadline_never_invokes_auth_client(self) -> None:
        events: list[str] = []
        commands: list[object] = []

        class Auth:
            def __init__(self) -> None:
                self.login_calls = 0
                self.probe_started = Event()
                self.release_probe = Event()

            def start_login(self, callback, cancel: Event, *, deadline=None) -> None:
                self.login_calls += 1

            def is_authenticated(self, *, cancel: Event) -> bool:
                self.probe_started.set()
                self.release_probe.wait(1)
                return False

            def logout(self, *, cancel: Event, deadline=None) -> None:
                return

        auth = Auth()
        broker = web_module.LoginUrlBroker()
        service = BackupService(
            runtime_factory=lambda: RuntimeComponents(
                FakeStore(events), FakeScanner(events), FakeWorker(events), auth
            ),
            web_server_factory=lambda _snapshot, queue: (
                commands.append(queue) or FakeServer()
            ),
            clock=lambda: NOW,
            login_url_broker=broker,
        )
        self.addCleanup(service.stop)
        service.start()
        self.assertTrue(auth.probe_started.wait(1))
        commands[0].put_nowait(
            ControlCommand(
                "e" * 32,
                ControlAction.CONNECT,
                "user-a",
                login_deadline=monotonic() - 1,
            )
        )
        deadline = monotonic() + 1
        while service.snapshot().last_error_code != "auth_failed" and monotonic() < deadline:
            Event().wait(0.01)
        auth.release_probe.set()
        Event().wait(0.1)

        self.assertEqual(auth.login_calls, 0)
        self.assertFalse(service.snapshot().connected)
        self.assertEqual(service.snapshot().last_error_code, "auth_failed")

    def test_renew_uses_one_deadline_for_logout_login_and_post_login_probe(self) -> None:
        calls: list[tuple[str, float | None]] = []

        class Auth:
            def logout(self, *, cancel: Event, deadline=None) -> None:
                calls.append(("logout", deadline))

            def start_login(self, _callback, cancel: Event, *, deadline=None) -> None:
                calls.append(("login", deadline))

            def is_authenticated(self, *, cancel: Event, deadline=None) -> bool:
                calls.append(("probe", deadline))
                return True

        service = BackupService(
            runtime_factory=lambda: None,
            web_server_factory=lambda _snapshot, _commands: FakeServer(),
            login_url_broker=web_module.LoginUrlBroker(monotonic=lambda: 100.0),
        )
        runtime = RuntimeComponents(FakeStore([]), FakeScanner([]), FakeWorker([]), Auth())
        work = service_module._AuthWork(
            ControlAction.RENEW,
            "operator",
            "a" * 32,
            lambda _url: None,
            Event(),
            login_deadline=101.0,
        )

        with patch.object(service_module, "monotonic", lambda: 100.0):
            result = service._execute_auth_work(runtime, work)

        self.assertTrue(result.succeeded)
        self.assertEqual(calls, [("logout", 101.0), ("login", 101.0), ("probe", 101.0)])

    def test_blocked_worker_keeps_auth_on_the_same_external_fifo(self) -> None:
        events: list[str] = []
        worker_started = Event()
        release_worker = Event()
        auth_started = Event()
        command_queue = []
        external_threads: list[int] = []

        class BlockingWorker(FakeWorker):
            def execute_external(self, work):
                external_threads.append(get_ident())
                worker_started.set()
                release_worker.wait(2)
                return work

        class AuthClient:
            def start_login(self, callback, cancel: Event, *, deadline=None) -> None:
                external_threads.append(get_ident())
                auth_started.set()

            def is_authenticated(self, *, cancel: Event) -> bool:
                return auth_started.is_set()

            def logout(self, *, cancel: Event) -> None:
                external_threads.append(get_ident())

        service = BackupService(
            runtime_factory=lambda: RuntimeComponents(
                FakeStore(events),
                FakeScanner(events),
                BlockingWorker(events),
                AuthClient(),
            ),
            web_server_factory=lambda _snapshot, commands: (
                command_queue.append(commands) or FakeServer()
            ),
            login_url_broker=web_module.LoginUrlBroker(),
            clock=lambda: NOW,
        )
        self.addCleanup(release_worker.set)
        self.addCleanup(service.stop)
        service.start()
        self.assertTrue(worker_started.wait(1))

        command_queue[0].put_nowait(
            ControlCommand("f" * 32, ControlAction.CONNECT, "operator")
        )
        self.assertFalse(auth_started.wait(0.1))
        release_worker.set()
        self.assertTrue(auth_started.wait(1))

        self.assertEqual(len(set(external_threads)), 1)

    def test_login_broker_capacity_error_does_not_kill_command_consumer(self) -> None:
        events: list[str] = []
        broker = web_module.LoginUrlBroker()
        for index in range(128):
            broker.begin(
                ControlCommand(
                    f"{index:032x}", ControlAction.CONNECT, f"user-{index}"
                )
            )
        command_queue = []

        class AuthClient:
            def is_authenticated(self, *, cancel: Event) -> bool:
                return False

            def start_login(self, callback, cancel: Event, *, deadline=None) -> None:
                raise AssertionError("capacity-rejected login must not start")

            def logout(self, *, cancel: Event) -> None:
                pass

        worker = FakeWorker(events)
        service = BackupService(
            runtime_factory=lambda: RuntimeComponents(
                FakeStore(events), FakeScanner(events), worker, AuthClient()
            ),
            web_server_factory=lambda _snapshot, commands: (
                command_queue.append(commands) or FakeServer()
            ),
            login_url_broker=broker,
            clock=lambda: NOW,
        )
        self.addCleanup(service.stop)
        service.start()

        command_queue[0].put_nowait(
            ControlCommand("a" * 32, ControlAction.CONNECT, "overflow")
        )
        command_queue[0].put_nowait(
            ControlCommand("b" * 32, ControlAction.RESTART_WORKER, "operator")
        )
        deadline = monotonic() + 1
        while worker.restart_count < 1 and monotonic() < deadline:
            Event().wait(0.01)

        self.assertEqual(worker.restart_count, 1)
        self.assertTrue(service.snapshot().web_ready)
        self.assertEqual(service.snapshot().last_error_code, "command_rejected")

    def test_owner_command_execution_lease_linearizes_all_mutations_with_stop(self) -> None:
        actions = (
            ControlAction.RETRY_UPLOAD,
            ControlAction.SCAN,
            ControlAction.CANCEL_UPLOAD,
            ControlAction.RESTART_WORKER,
            ControlAction.CONNECT,
        )

        for close_first in (True, False):
            for action in actions:
                with self.subTest(close_first=close_first, action=action):
                    effects: list[ControlAction] = []
                    started = Event()
                    release = Event()

                    def effect() -> None:
                        effects.append(action)
                        started.set()
                        release.wait(1)

                    class Worker(FakeWorker):
                        def retry_now(self, sha256: str, revision: int) -> None:
                            effect()

                        def cancel_current(self) -> bool:
                            effect()
                            return True

                        def restart(self) -> None:
                            effect()

                    class LeaseService(BackupService):
                        def request_scan(self) -> None:
                            effect()

                        def _queue_auth_command(self, runtime, command) -> None:
                            effect()

                    service = LeaseService(
                        runtime_factory=lambda: None,
                        web_server_factory=lambda _snapshot, _commands: FakeServer(),
                    )
                    worker = Worker([])
                    runtime = RuntimeComponents(
                        FakeStore([]), FakeScanner([]), worker, object()
                    )
                    command = ControlCommand(
                        "a" * 32,
                        action,
                        "operator",
                        "b" * 64 if action is ControlAction.RETRY_UPLOAD else None,
                        1 if action is ControlAction.RETRY_UPLOAD else None,
                    )
                    service._commands.put_nowait(command)

                    if close_first:
                        service.request_stop()
                        service._run_runtime_commands(runtime)
                        self.assertEqual(effects, [])
                        continue

                    owner = Thread(
                        target=service._run_runtime_commands,
                        args=(runtime,),
                    )
                    owner.start()
                    self.assertTrue(started.wait(1))
                    stopper = Thread(target=service.request_stop)
                    stopper.start()
                    Event().wait(0.05)
                    self.assertTrue(stopper.is_alive())
                    release.set()
                    owner.join(1)
                    stopper.join(1)

                    self.assertFalse(owner.is_alive())
                    self.assertFalse(stopper.is_alive())
                    self.assertEqual(effects, [action])
                    self.assertTrue(service._commands.admission_closed)
    def test_expected_command_error_does_not_kill_owner_consumer(self) -> None:
        events: list[str] = []
        command_queue = []

        class RejectingRetryWorker(FakeWorker):
            def retry_now(self, sha256: str, revision: int) -> None:
                raise ValueError("stale retry generation")

        worker = RejectingRetryWorker(events)
        service = BackupService(
            runtime_factory=lambda: RuntimeComponents(
                FakeStore(events), FakeScanner(events), worker
            ),
            web_server_factory=lambda _snapshot, commands: (
                command_queue.append(commands) or FakeServer()
            ),
            clock=lambda: NOW,
        )
        self.addCleanup(service.stop)
        service.start()

        command_queue[0].put_nowait(
            ControlCommand(
                "7" * 32,
                ControlAction.RETRY_UPLOAD,
                "operator",
                "a" * 64,
                1,
            )
        )
        command_queue[0].put_nowait(
            ControlCommand("8" * 32, ControlAction.RESTART_WORKER, "operator")
        )

        deadline = __import__("time").monotonic() + 1
        while worker.restart_count < 1 and __import__("time").monotonic() < deadline:
            Event().wait(0.01)
        self.assertEqual(worker.restart_count, 1)
        self.assertTrue(service.snapshot().web_ready)
        self.assertEqual(service.snapshot().last_error_code, "command_rejected")

    def test_renew_does_not_start_login_when_logout_fails(self) -> None:
        events: list[str] = []
        broker = web_module.LoginUrlBroker(monotonic=lambda: 10.0)
        command_queue = []

        class FailingLogoutAuth:
            def __init__(self) -> None:
                self.login_count = 0
                self.first_started = Event()
                self.first_cancelled = Event()
                self.second_started = Event()
                self.logout_called = Event()

            def start_login(self, _callback, cancel: Event, *, deadline=None) -> None:
                self.login_count += 1
                if self.login_count == 1:
                    self.first_started.set()
                    while not cancel.is_set():
                        cancel.wait(0.01)
                    self.first_cancelled.set()
                    return
                self.second_started.set()
                while not cancel.is_set():
                    cancel.wait(0.01)

            def logout(self, *, cancel: Event, deadline=None) -> None:
                self.logout_called.set()
                raise RuntimeError("logout unavailable")

        auth = FailingLogoutAuth()
        service = BackupService(
            runtime_factory=lambda: RuntimeComponents(
                FakeStore(events), FakeScanner(events), FakeWorker(events), auth
            ),
            web_server_factory=lambda _snapshot, commands: (
                command_queue.append(commands) or FakeServer()
            ),
            login_url_broker=broker,
            clock=lambda: NOW,
        )
        self.addCleanup(service.stop)
        service.start()
        command_queue[0].put_nowait(
            ControlCommand("5" * 32, ControlAction.CONNECT, "operator")
        )
        self.assertTrue(auth.first_started.wait(1))

        command_queue[0].put_nowait(
            ControlCommand("6" * 32, ControlAction.RENEW, "operator")
        )

        self.assertTrue(auth.logout_called.wait(1))
        self.assertTrue(auth.first_cancelled.wait(1))
        self.assertFalse(auth.second_started.wait(0.1))
        self.assertEqual(auth.login_count, 1)
        deadline = monotonic() + 1
        while service.snapshot().last_error_code != "auth_failed" and monotonic() < deadline:
            Event().wait(0.01)
        self.assertFalse(service.snapshot().connected)
        self.assertEqual(service.snapshot().last_error_code, "auth_failed")
        self.assertIsNone(broker.view("operator"))

    def test_stop_cancels_blocking_auth_process_without_thread_leak(self) -> None:
        events: list[str] = []
        broker = web_module.LoginUrlBroker(monotonic=lambda: 10.0)
        command_queue = []

        class BlockingAuth:
            def __init__(self) -> None:
                self.started = Event()
                self.returned = Event()
                self.cancel: Event | None = None

            def start_login(self, _callback, cancel: Event, *, deadline=None) -> None:
                self.cancel = cancel
                self.started.set()
                while not cancel.is_set() and not self.returned.is_set():
                    self.returned.wait(0.01)

            def logout(self, *, cancel: Event) -> None:
                pass

        auth = BlockingAuth()
        service = BackupService(
            runtime_factory=lambda: RuntimeComponents(
                FakeStore(events), FakeScanner(events), FakeWorker(events), auth
            ),
            web_server_factory=lambda _snapshot, commands: (
                command_queue.append(commands) or FakeServer()
            ),
            login_url_broker=broker,
            clock=lambda: NOW,
        )
        service.start()
        command_queue[0].put_nowait(
            ControlCommand(
                "4" * 32,
                ControlAction.CONNECT,
                "operator",
            )
        )
        self.assertTrue(auth.started.wait(1))

        try:
            service.stop(timeout=0.5)
            self.assertIsNotNone(auth.cancel)
            self.assertTrue(auth.cancel.is_set())
            leaked = [
                thread
                for thread in __import__("threading").enumerate()
                if thread.name == "proton-backup-auth" and thread.is_alive()
            ]
            self.assertEqual(leaked, [])
        finally:
            auth.returned.set()

    def test_main_builds_service_and_delegates_to_signal_runner(self) -> None:
        service = object()
        events: list[object] = []

        result = entrypoint.main(
            service_factory=lambda: events.append("build") or service,
            service_runner=lambda value: events.append(value) or 7,
        )

        self.assertEqual(result, 7)
        self.assertEqual(events, ["build", service])

    def test_run_script_rejects_unsafe_store_and_execs_module(self) -> None:
        if os.name == "nt":
            bash = Path(r"C:\Program Files\Git\bin\bash.exe")
            if not bash.is_file():
                self.skipTest("Git Bash is unavailable")
        else:
            found = shutil.which("bash")
            if found is None:
                self.skipTest("bash is unavailable")
            bash = Path(found)
        run_script = Path("proton_drive_backup/rootfs/app/run.sh").resolve()
        with TemporaryDirectory(dir=".") as temporary:
            root = Path(temporary).resolve()
            shell_root = (
                f"/{root.drive[0].lower()}{root.as_posix()[2:]}"
                if os.name == "nt" else root.as_posix()
            )
            for name in ("pass", "gnupg", "cache"):
                (root / name).mkdir()
            fake_python = root / "python3"
            output = root / "argv.txt"
            fake_python.write_text(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$FAKE_OUTPUT\"\n",
                encoding="utf-8",
                newline="\n",
            )
            if os.name == "nt":
                subprocess.run(
                    [
                        r"C:\Program Files\Git\usr\bin\chmod.exe",
                        "+x",
                        str(fake_python),
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
            else:
                fake_python.chmod(0o755)
            environment = {
                **os.environ,
                # If the fixture cannot execute (e.g. noexec tmpfs), fail closed
                # instead of finding and starting the real backup application.
                "PATH": shell_root,
                "BASH_ENV": "/dev/null",
                "FAKE_OUTPUT": f"{shell_root}/argv.txt",
                "PASSWORD_STORE_DIR": f"{shell_root}/pass",
                "GNUPGHOME": f"{shell_root}/gnupg",
                "PROTON_DRIVE_CACHE_DIR": f"{shell_root}/cache",
            }
            unsafe = subprocess.run(
                [str(bash), run_script.as_posix()],
                env={**environment, "PROTON_DRIVE_CREDENTIALS_STORE": "unsafe_file"},
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(unsafe.returncode, 64, unsafe.stderr)
            self.assertFalse(output.exists())

            safe = subprocess.run(
                [str(bash), run_script.as_posix()],
                env={**environment, "PROTON_DRIVE_CREDENTIALS_STORE": "pass"},
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(safe.returncode, 0, safe.stderr)
            self.assertEqual(output.read_text(encoding="utf-8").splitlines(), ["-m", "proton_backup"])


if __name__ == "__main__":
    unittest.main()
