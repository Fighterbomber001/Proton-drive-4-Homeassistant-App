"""Real service, scanner, worker, retention and SQLite; only Proton is fake."""
import tests  # Activate the app path for bare unittest discovery too.
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
from time import monotonic
import unittest

from proton_backup.events import EventLog
from proton_backup.models import RemoteFile, StableBackup
from proton_backup.proton_cli import FinalListing, ProtonNetworkError, RemoteLayout
from proton_backup.retention import RetentionManager
from proton_backup.scanner import BackupScanner
from proton_backup.service import BackupService, RuntimeComponents
from proton_backup.state import StateStore
from proton_backup.web import ControlAction, ControlCommand, DiagnosticBuffer, LoginUrlBroker
from proton_backup.worker import BackupWorker
from tests.test_service import FakeServer


class RecoveryIntegrationTests(unittest.TestCase):
    def until(self, predicate):
        deadline = monotonic() + 3
        while not predicate() and monotonic() < deadline:
            Event().wait(0.005)
        self.assertTrue(predicate(), "Service did not reach the required state")

    def test_backup_before_login_retries_failure_and_confirms_without_duplicate(self):
        now = [datetime(2026, 8, 10, 12, 34, 56, tzinfo=UTC)]
        diagnostics = DiagnosticBuffer()
        events = EventLog(diagnostics=diagnostics)
        class Proton:
            connected = False
            attempts = 0
            files = ()
            def is_authenticated(self, **kwargs):
                return self.connected
            def start_login(self, callback, cancel, **kwargs):
                self.connected = True
            def ensure_layout(self, install, **kwargs):
                self.install = install
                root = "/my-files/HomeAssistant-Backups/" + install
                return RemoteLayout(root, root + "/incoming", root + "/backups")
            def find_final(self, backup, layout, **kwargs):
                return next(iter(self.files), None)
            def upload_and_finalize(self, backup, layout, cancel):
                self.attempts += 1
                if self.attempts == 1:
                    raise ProtonNetworkError("fake outage")
                name = f"ha-v1--{self.install}--20260810T123456Z--test--aaaaaaaaaaaa.tar"
                remote = RemoteFile("volume~confirmed", name, layout.final + "/" + name,
                                    backup.size, now[0])
                self.files = (remote,)
                cancel.mark_success()
                return remote
            def list_final(self, layout, **kwargs):
                return FinalListing(self.files, True)
            def permanently_delete_owned(self, *args, **kwargs):
                raise AssertionError("Only one backup; retention must not delete")
        proton = Proton()
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "backups").mkdir()
            def runtime():
                store = StateStore(root / "state.sqlite")
                store.enqueue(StableBackup(Path("/backup/test.tar"), "test.tar", 4096,
                                           1786365296000000000, "a" * 64))
                scanner = BackupScanner(root / "backups", store)
                worker = BackupWorker(store, proton, RetentionManager(proton, store),
                                      clock=lambda: now[0], jitter=lambda _: 0,
                                      event_log=events)
                return RuntimeComponents(store, scanner, worker, proton)
            commands = []
            service = BackupService(runtime_factory=runtime,
                                    web_server_factory=lambda snapshot, queue: (commands.append(queue) or FakeServer()),
                                    clock=lambda: now[0], login_url_broker=LoginUrlBroker(),
                                    event_log=events)
            try:
                service.start()
                self.until(lambda: service.snapshot().last_error_code == "authentication_required")
                self.assertEqual(proton.attempts, 0)
                commands[0].put_nowait(ControlCommand("a" * 32, ControlAction.CONNECT, "b" * 32))
                self.until(lambda: service.snapshot().next_retry_at is not None)
                self.assertEqual(proton.attempts, 1)
                now[0] = service.snapshot().next_retry_at + timedelta(seconds=1)
                service.request_scan()
                self.until(lambda: service.snapshot().last_success_at is not None)
                self.assertEqual(service.snapshot().queue_size, 0)
                self.assertEqual(proton.attempts, 2)
                self.assertEqual(len(proton.files), 1)
                codes = [event.code for event in diagnostics.snapshot()]
                for code in ("service_started", "authentication_required", "proton_connected",
                             "network_unavailable", "upload_started", "upload_succeeded"):
                    self.assertIn(code, codes)
            finally:
                service.stop(timeout=2)
            reopened = StateStore(root / "state.sqlite")
            try:
                self.assertEqual(len(reopened.confirmed_remote_files()), 1)
            finally:
                reopened.close()
