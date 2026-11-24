from dataclasses import asdict, replace
from datetime import UTC, datetime
from threading import Event, get_ident
from time import monotonic, sleep
import unittest
from unittest.mock import patch

from proton_backup.native_storage import NativeAuthenticationRequired, NativeStorageError
from proton_backup.service import BackupService, RuntimeComponents
from proton_backup.web import ControlAction, ControlCommand, LoginUrlBroker
from tests.test_service import FakeScanner, FakeServer, FakeStore, FakeWorker


def backup(identity, name, date, size):
    return {
        "addons": [], "backup_id": identity, "date": date,
        "database_included": True, "extra_metadata": {"secret": "do not expose"},
        "folders": ["ssl"], "homeassistant_included": True,
        "homeassistant_version": None, "name": name, "protected": True, "size": size,
    }


NEW = backup("private-a", "A new backup", "2026-11-23T09:00:00Z", 4096)


class ConnectedWorker(FakeWorker):
    def snapshot(self):
        return replace(super().snapshot(), connected=True)


class NativeHistoryTests(unittest.TestCase):
    def make_service(self, storage, auth_client=None):
        events = []
        runtime = RuntimeComponents(FakeStore(events), FakeScanner(events),
                                    ConnectedWorker(events), auth_client, native_storage=storage)

        def web_server(status, commands):
            self.dashboard = status
            self.commands = commands
            return FakeServer()

        service = BackupService(runtime_factory=lambda: runtime,
                                web_server_factory=web_server, native_mode=True,
                                login_url_broker=LoginUrlBroker() if auth_client else None)
        service.start()
        self.addCleanup(service.stop, 2)
        return service

    def history_state(self, service, wanted):
        deadline = monotonic() + 1
        while monotonic() < deadline:
            snapshot = service.snapshot()
            if getattr(snapshot, "native_history_state", None) == wanted:
                return snapshot
            sleep(0.005)
        self.fail(f"history state never became {wanted}")

    def test_only_dashboard_requests_nonblocking_coalesced_refresh(self):
        started, release = Event(), Event()
        calls = []

        class Storage:
            def list_backups(self, cancel):
                calls.append(get_ident())
                started.set()
                release.wait(2)
                return []

        service = self.make_service(Storage())
        self.addCleanup(release.set)
        for _ in range(8):
            self.assertTrue(service.snapshot().connected)
        self.assertFalse(started.wait(0.05))
        first = self.dashboard()
        self.assertEqual(getattr(first, "native_history_state", None), "loading")
        self.assertTrue(started.wait(1))
        for _ in range(8):
            snapshot = self.dashboard()
            self.assertEqual(snapshot.native_history_state, "loading")
            self.assertIsNone(snapshot.native_operation)
            self.assertEqual(snapshot.queue_size, 0)
        release.set()
        self.assertEqual(self.history_state(service, "ready").native_history, ())
        self.dashboard()
        self.assertEqual(calls, [calls[0]])
        self.assertNotEqual(calls[0], get_ident())

    def test_successful_native_list_projects_only_newest_14_metadata_entries(self):
        inventory = [backup(f"private-{day}", f"Day {day}",
                            f"2026-11-{day:02d}T20:00:00Z", day)
                     for day in range(1, 17)]
        # The displayed local date is earlier, but this is a later instant.
        inventory.insert(0, backup("private-offset", "Offset backup",
                                   "2026-11-16T18:00:00-04:00", 4096))

        class Storage:
            def list_backups(self, cancel):
                return inventory

        service = self.make_service(Storage())
        self.assertEqual(service.submit_native("list").result(timeout=1), inventory)
        snapshot = service.snapshot()
        self.assertEqual(getattr(snapshot, "native_history_state", None), "ready")
        self.assertEqual([item.name for item in snapshot.native_history],
                         ["Offset backup", "Day 16", "Day 15", "Day 14", "Day 13", "Day 12",
                          "Day 11", "Day 10", "Day 9", "Day 8", "Day 7", "Day 6", "Day 5",
                          "Day 4"])
        self.assertEqual(asdict(snapshot.native_history[0]),
                         {"name": "Offset backup", "size": 4096,
                          "date": datetime(2026, 11, 16, 22, tzinfo=UTC)})

    def test_background_refresh_failure_preserves_history_and_upload_status(self):
        attempted = Event()
        calls = []

        class Storage:
            def list_backups(self, cancel):
                calls.append(None)
                if len(calls) == 1:
                    return [NEW]
                attempted.set()
                raise NativeStorageError()

        service = self.make_service(Storage())
        with patch("proton_backup.service.monotonic") as tick:
            tick.return_value = 100.0
            service.submit_native("list").result(timeout=1)
            tick.return_value = 399.0
            self.dashboard()
            self.assertFalse(attempted.wait(0.05))
            tick.return_value = 401.0
            self.dashboard()
            self.assertTrue(attempted.wait(1))
            snapshot = self.history_state(service, "stale")
            self.assertEqual([item.name for item in snapshot.native_history], ["A new backup"])
            self.assertIsNone(snapshot.last_error_code)
            self.assertIsNone(snapshot.last_success_at)
            for _ in range(8):
                self.dashboard()
            self.assertEqual(len(calls), 2)

    def test_initial_refresh_failure_is_unavailable_not_confirmed_empty(self):
        class Storage:
            def list_backups(self, cancel):
                raise NativeStorageError()

        service = self.make_service(Storage())
        self.dashboard()
        snapshot = self.history_state(service, "unavailable")
        self.assertTrue(snapshot.connected)
        self.assertEqual(snapshot.native_history, ())

    def test_dashboard_detects_expired_proton_auth_without_changing_upload_status(self):
        listed = []

        class Storage:
            def list_backups(self, cancel):
                listed.append(None)
                if len(listed) == 2:
                    raise NativeAuthenticationRequired()
                return [NEW]

        service = self.make_service(Storage())
        with patch("proton_backup.service.monotonic") as tick:
            tick.return_value = 100.0
            service.submit_native("list").result(timeout=1)
            self.assertEqual(service.snapshot().native_history_state, "ready")
            tick.return_value = 401.0
            self.dashboard()
            expired = self.history_state(service, "unavailable")
            self.assertFalse(expired.connected)
            self.assertEqual(expired.native_history, ())
            self.assertIsNone(expired.last_error_code)
            self.assertIsNone(expired.last_success_at)
            tick.return_value = 800.0
            for _ in range(8):
                self.assertFalse(self.dashboard().connected)
            self.assertEqual(len(listed), 2)

    def test_verified_upload_updates_history_without_a_second_list(self):
        listed = []

        class Storage:
            def list_backups(self, cancel):
                listed.append(None)
                return []

            def upload_backup(self, identity, metadata, path, cancel):
                if identity == "failure":
                    raise NativeStorageError()
                return metadata

        service = self.make_service(Storage())
        service.submit_native("list").result(timeout=1)
        for _ in range(2):
            service.submit_native("upload", "private-a", NEW, "unused").result(timeout=1)
        with self.assertRaises(NativeStorageError):
            service.submit_native("upload", "failure", NEW, "unused").result(timeout=1)
        snapshot = self.dashboard()
        self.assertEqual(getattr(snapshot, "native_history_state", None), "ready")
        self.assertEqual([item.name for item in snapshot.native_history], ["A new backup"])
        self.assertEqual(len(listed), 1)

    def test_history_never_starts_a_refresh_ahead_of_queued_native_work(self):
        started, release, queued, release_queued, listed = (Event() for _ in range(5))

        class Storage:
            def get_backup(self, identity, cancel):
                if identity == "active":
                    started.set()
                    release.wait(2)
                else:
                    queued.set()
                    release_queued.wait(2)
                return NEW

            def list_backups(self, cancel):
                listed.set()
                return [NEW]

        service = self.make_service(Storage())
        self.addCleanup(release_queued.set)
        self.addCleanup(release.set)
        active = service.submit_native("get", "active")
        self.assertTrue(started.wait(1))
        second = service.submit_native("get", "queued")
        self.assertEqual(getattr(self.dashboard(), "native_history_state", None), "loading")
        self.assertFalse(listed.is_set())
        release.set()
        self.assertEqual(active.result(timeout=1), NEW)
        self.assertTrue(queued.wait(1))
        self.dashboard()
        self.assertFalse(listed.is_set())
        release_queued.set()
        self.assertEqual(second.result(timeout=1), NEW)
        self.dashboard()
        self.assertTrue(listed.wait(1))

    def test_new_native_request_cancels_refresh_without_competing_proton_work(self):
        started, cancelled, release, native_started = (Event() for _ in range(4))
        threads = []

        class Storage:
            def list_backups(self, cancel):
                threads.append(get_ident())
                started.set()
                if cancel.wait(2):
                    cancelled.set()
                release.wait(2)
                return [NEW]

            def get_backup(self, identity, cancel):
                threads.append(get_ident())
                native_started.set()
                return NEW

        service = self.make_service(Storage())
        self.addCleanup(release.set)
        self.dashboard()
        self.assertTrue(started.wait(1))
        native = service.submit_native("get", "native")
        self.assertTrue(cancelled.wait(1))
        self.assertFalse(native_started.is_set())
        release.set()
        self.assertEqual(native.result(timeout=1), NEW)
        self.assertEqual(len(set(threads)), 1)
        snapshot = service.snapshot()
        self.assertEqual(snapshot.native_history_state, "unavailable")
        self.assertEqual(snapshot.native_history, ())

    def test_verified_upload_before_any_list_is_visible_as_partial_history(self):
        class Storage:
            def upload_backup(self, identity, metadata, path, cancel):
                return metadata

        service = self.make_service(Storage())
        service.submit_native("upload", "private-a", NEW, "unused").result(timeout=1)
        snapshot = service.snapshot()
        self.assertEqual(snapshot.native_history_state, "stale")
        self.assertEqual([item.name for item in snapshot.native_history], ["A new backup"])

    def test_disconnect_hides_prior_account_names_after_reconnect(self):
        class Storage:
            def list_backups(self, cancel):
                return [NEW]

            def get_backup(self, identity, cancel):
                if identity == "disconnected":
                    raise NativeAuthenticationRequired()
                return NEW

        service = self.make_service(Storage())
        service.submit_native("list").result(timeout=1)
        self.assertEqual(getattr(service.snapshot(), "native_history_state", None), "ready")
        with self.assertRaises(NativeAuthenticationRequired):
            service.submit_native("get", "disconnected").result(timeout=1)
        self.assertFalse(self.dashboard().connected)
        self.assertEqual(self.dashboard().native_history, ())
        service.submit_native("get", "new-session").result(timeout=1)
        snapshot = service.snapshot()
        self.assertTrue(snapshot.connected)
        self.assertEqual(snapshot.native_history_state, "loading")
        self.assertEqual(snapshot.native_history, ())

    def test_dashboard_hides_history_as_soon_as_disconnect_is_admitted(self):
        disconnect_started = Event()

        class Storage:
            def list_backups(self, cancel):
                return [NEW]

        class Auth:
            def is_authenticated(self, *, cancel, deadline=None):
                return True

            def logout(self, *, cancel, deadline):
                disconnect_started.set()

        service = self.make_service(Storage(), Auth())
        self.assertEqual(service.submit_native("list").result(timeout=1), [NEW])
        # Hold the existing lease so the test samples after admission but
        # before the owner can consume the accepted command.
        with self.commands.admission() as admitted:
            self.assertTrue(admitted)
            self.commands.put_nowait(ControlCommand("a" * 32, ControlAction.SCAN, "owner"))
            self.assertTrue(self.dashboard().connected)
            self.commands.put_nowait(ControlCommand("b" * 32, ControlAction.DISCONNECT, "owner"))
            native = service.snapshot()
            self.assertTrue(native.connected)
            self.assertEqual(native.native_history_state, "ready")
            dashboard = self.dashboard()
            self.assertFalse(dashboard.connected)
            self.assertEqual(dashboard.native_history_state, "unavailable")
            self.assertEqual(dashboard.native_history, ())
        self.assertTrue(disconnect_started.wait(1))
        self.assertEqual(self.history_state(service, "unavailable").native_history, ())

    def test_queued_old_account_list_cannot_repopulate_history_during_renewal(self):
        active, release_active, renewing, release_renewal, changed = (Event() for _ in range(5))
        replacement = backup("private-b", "New account backup", "2026-11-23T10:00:00Z", 1)

        class Storage:
            def list_backups(self, cancel):
                return [replacement if changed.is_set() else NEW]

            def get_backup(self, identity, cancel):
                active.set()
                release_active.wait(2)
                return NEW

        class Auth:
            def is_authenticated(self, *, cancel, deadline=None):
                return True

            def logout(self, *, cancel, deadline):
                renewing.set()
                release_renewal.wait(2)

            def start_login(self, callback, cancel, *, deadline):
                changed.set()

        service = self.make_service(Storage(), Auth())
        self.addCleanup(release_renewal.set)
        self.addCleanup(release_active.set)
        self.assertEqual(service.submit_native("list").result(timeout=1), [NEW])
        current = service.submit_native("get", "active")
        self.assertTrue(active.wait(1))
        queued = service.submit_native("list")
        # Wait until the owner has moved this request ahead of the renewal in
        # the serialized lane's pending queue, with the get still holding it.
        deadline = monotonic() + 1
        while not service._native_requests.empty() and monotonic() < deadline:
            sleep(0.005)
        self.assertTrue(service._native_requests.empty())
        self.commands.put_nowait(ControlCommand("a" * 32, ControlAction.RENEW, "owner"))
        self.assertEqual(self.history_state(service, "unavailable").native_history, ())
        release_active.set()
        self.assertEqual(current.result(timeout=1), NEW)
        self.assertEqual(queued.result(timeout=1), [NEW])
        self.assertTrue(renewing.wait(1))
        self.assertTrue(service.snapshot().connected, "Existing native status semantics stay intact")
        during = self.dashboard()
        self.assertFalse(during.connected, "The dashboard must not hide the new login handoff")
        self.assertEqual(during.native_history_state, "unavailable")
        self.assertEqual(during.native_history, ())
        release_renewal.set()
        self.assertEqual(self.history_state(service, "loading").native_history, ())
        self.assertTrue(self.dashboard().connected)
        after = self.history_state(service, "ready")
        self.assertEqual([item.name for item in after.native_history], ["New account backup"])
