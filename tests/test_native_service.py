import tests
from concurrent.futures import TimeoutError as FutureTimeout
from threading import Event, get_ident
from time import monotonic
import unittest

from proton_backup.native_storage import NativeStorageError
from proton_backup.service import BackupService, RuntimeComponents, ShutdownFailureError
from proton_backup.web import ControlAction, ControlCommand
from tests.test_service import FakeScanner, FakeServer, FakeStore, FakeWorker


class FakeNativeApi:
    def __init__(self):
        self.started = False
        self.stopped = False
    def start(self):
        self.started = True
    def stop(self, timeout=20):
        self.stopped = True


class NativeServiceTests(unittest.TestCase):
    def make_service(self, storage):
        self.events = []
        self.store = FakeStore(self.events)
        self.scanner = FakeScanner(self.events)
        self.worker = FakeWorker(self.events)
        self.api = FakeNativeApi()
        return BackupService(
            runtime_factory=lambda: RuntimeComponents(self.store, self.scanner, self.worker,
                                                       native_storage=storage),
            web_server_factory=lambda *_: FakeServer(),
            native_mode=True, native_api_factory=lambda service, runtime: self.api,
        )

    def test_native_mode_suppresses_legacy_scanning_and_serializes_proton_jobs(self):
        started, release = Event(), Event()
        threads = []
        class Storage:
            def list_backups(self, cancel):
                threads.append(get_ident())
                started.set()
                release.wait(2)
                return []
            def get_backup(self, backup_id, cancel):
                threads.append(get_ident())
                return {"backup_id": backup_id}
        service = self.make_service(Storage())
        service.start()
        try:
            first = service.submit_native("list")
            self.assertTrue(started.wait(1))
            second = service.submit_native("get", "abc12345")
            with self.assertRaises(FutureTimeout):
                second.result(timeout=0.05)
            release.set()
            self.assertEqual(first.result(timeout=1), [])
            self.assertEqual(second.result(timeout=1), {"backup_id": "abc12345"})
            self.assertEqual(len(set(threads)), 1)
            self.assertNotEqual(threads[0], get_ident())
            self.assertEqual(self.scanner.scan_count, 0)
            self.assertNotIn("worker", self.events)
        finally:
            release.set()
            service.stop(timeout=2)
        self.assertTrue(self.api.started and self.api.stopped)
        self.assertTrue(self.store.closed)

    def test_native_error_does_not_kill_owner_and_unknown_operation_is_rejected(self):
        class Storage:
            def list_backups(self, cancel):
                raise NativeStorageError()
            def get_backup(self, identity, cancel):
                return {"backup_id": identity}
        service = self.make_service(Storage())
        service.start()
        try:
            with self.assertRaises(NativeStorageError):
                service.submit_native("list").result(timeout=1)
            self.assertEqual(service.submit_native("get", "abc").result(timeout=1), {"backup_id": "abc"})
            self.assertTrue(service.snapshot().web_ready)
            with self.assertRaises(ValueError):
                service.submit_native("arbitrary_command")
        finally:
            service.stop(timeout=2)

    def test_stop_cancels_active_and_finishes_queued_native_futures(self):
        started = Event()
        class Storage:
            def list_backups(self, cancel):
                started.set()
                cancel.wait(2)
                raise NativeStorageError()
            def get_backup(self, identity, cancel):
                raise AssertionError("Queued work must not execute after stop")
        service = self.make_service(Storage())
        service.start()
        active = service.submit_native("list")
        self.assertTrue(started.wait(1))
        queued = service.submit_native("get", "abc")
        service.stop(timeout=2)
        self.assertTrue(active.done())
        self.assertTrue(queued.done())
        self.assertTrue(self.store.closed)
        with self.assertRaises(RuntimeError):
            service.submit_native("list")

    def test_cancel_button_cancels_native_job_without_completing_it_early(self):
        self.check_native_cancel(ControlAction.CANCEL_UPLOAD)

    def test_restart_button_cancels_native_job_without_reexecuting_it(self):
        self.check_native_cancel(ControlAction.RESTART_WORKER)

    def check_native_cancel(self, action):
        started, cancelled, release = Event(), Event(), Event()
        class Storage:
            def list_backups(self, cancel):
                started.set()
                cancel.wait(2)
                if cancel.is_set():
                    cancelled.set()
                release.wait(2)
                raise NativeStorageError()
        service = self.make_service(Storage())
        service.start()
        try:
            future = service.submit_native("list")
            self.assertTrue(started.wait(1))
            service._commands.put_nowait(ControlCommand("a" * 32, action, "user"))
            self.assertTrue(cancelled.wait(1))
            self.assertFalse(future.done(), "The CLI still owns its spool until it exits")
            release.set()
            with self.assertRaises(NativeStorageError):
                future.result(timeout=1)
        finally:
            release.set()
            service.stop(timeout=2)

    def test_native_mode_rejects_legacy_sha_retry_commands(self):
        class Storage:
            def list_backups(self, cancel):
                return []
        service = self.make_service(Storage())
        service.start()
        try:
            service._commands.put_nowait(ControlCommand("a" * 32, ControlAction.RETRY_UPLOAD,
                                                        "user", "b" * 64, 1))
            self.assertEqual(service.submit_native("list").result(timeout=1), [])
            self.assertIsNone(self.worker.retry_call)
            self.assertEqual(service.snapshot().last_error_code, "command_rejected")
        finally:
            service.stop(timeout=2)

    def test_cancelled_queued_future_never_executes_and_admission_is_bounded(self):
        started, release = Event(), Event()
        calls = []
        class Storage:
            def list_backups(self, cancel):
                started.set()
                release.wait(2)
                return []
            def get_backup(self, identity, cancel):
                calls.append(identity)
                return {"backup_id": identity}
        service = self.make_service(Storage())
        with self.assertRaises(RuntimeError):
            service.submit_native("list")
        service.start()
        try:
            active = service.submit_native("list")
            self.assertTrue(started.wait(1))
            queued = [service.submit_native("get", str(index)) for index in range(63)]
            with self.assertRaises(RuntimeError):
                service.submit_native("get", "overflow")
            self.assertTrue(queued[0].cancel())
            release.set()
            self.assertEqual(active.result(timeout=1), [])
            for future in queued[1:]:
                future.result(timeout=2)
            self.assertNotIn("0", calls)
            self.assertNotIn("overflow", calls)
            self.assertEqual(len(calls), 62)
        finally:
            release.set()
            service.stop(timeout=2)

    def test_unexpected_native_error_is_not_returned_verbatim(self):
        class Storage:
            def list_backups(self, cancel):
                raise RuntimeError("sensitive exception details")
        service = self.make_service(Storage())
        service.start()
        try:
            with self.assertRaises(NativeStorageError) as caught:
                service.submit_native("list").result(timeout=1)
            self.assertEqual(str(caught.exception), "storage_failed")
            self.assertTrue(service.snapshot().web_ready)
        finally:
            service.stop(timeout=2)

    def test_native_api_stop_failure_does_not_skip_store_close(self):
        service = self.make_service(object())
        def fail_stop(timeout=20):
            raise RuntimeError("sensitive teardown details")
        self.api.stop = fail_stop
        service.start()
        with self.assertRaises(ShutdownFailureError) as caught:
            service.stop(timeout=2)
        self.assertIn("native_api", caught.exception.component_codes)
        self.assertTrue(self.store.closed)

    def test_native_api_stop_uses_existing_service_deadline(self):
        service = self.make_service(object())
        timeouts = []
        self.api.stop = lambda timeout=20: timeouts.append(timeout)
        service.start()
        service.request_stop()
        service._shutdown_deadline = monotonic() + 0.25
        service.stop(timeout=2)
        self.assertEqual(len(timeouts), 1)
        self.assertLessEqual(timeouts[0], 0.25)

    def test_native_snapshot_tracks_active_upload_queue_and_confirmed_success(self):
        started, release = Event(), Event()
        class Storage:
            def upload_backup(self, identity, metadata, path, cancel):
                started.set()
                release.wait(2)
                return metadata
            def list_backups(self, cancel):
                return []
        service = self.make_service(Storage())
        service.start()
        try:
            metadata = {"name": "Native backup", "backup_id": "abc"}
            active = service.submit_native("upload", "abc", metadata, "unused-path")
            self.assertTrue(started.wait(1))
            queued = service.submit_native("list")
            snapshot = service.snapshot()
            self.assertTrue(snapshot.native_mode)
            self.assertEqual(snapshot.native_operation, "upload")
            self.assertEqual(snapshot.active_name, "Native backup")
            self.assertIsNotNone(snapshot.active_started_at)
            self.assertIsNone(snapshot.active_sha256)
            self.assertEqual(snapshot.queue_size, 1)
            self.assertIsNone(snapshot.last_success_at)
            release.set()
            self.assertEqual(active.result(timeout=1), metadata)
            queued.result(timeout=1)
            snapshot = service.snapshot()
            self.assertIsNone(snapshot.native_operation)
            self.assertIsNotNone(snapshot.last_success_at)
            self.assertEqual(snapshot.queue_size, 0)
        finally:
            release.set()
            service.stop(timeout=2)
