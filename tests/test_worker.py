from __future__ import annotations

import sys
import tempfile
import unittest
from unittest.mock import patch
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, Lock, Thread


APP_ROOT = Path(__file__).resolve().parents[1] / "proton_drive_backup" / "rootfs" / "app"
sys.path.insert(0, str(APP_ROOT))

from proton_backup.models import BackupStatus, RemoteFile, StableBackup
from proton_backup.proton_cli import (
    ProtonAuthenticationRequired,
    ProtonCliCancelled,
    ProtonCliError,
    ProtonNetworkError,
    ProtonProcessTimeout,
    RemoteLayout,
    TransferControl,
    validate_upload_result,
)
from proton_backup.retention import RetentionResult
from proton_backup.state import BackupClaim, QueueSnapshot, StateStore
from proton_backup.worker import (
    BackupWorker,
    ExternalResult,
    ExternalStatus,
    ServiceSnapshot,
)


INSTALLATION_ID = "0123456789abcdef0123456789abcdef"
ROOT = f"/my-files/HomeAssistant-Backups/{INSTALLATION_ID}"
LAYOUT = RemoteLayout(ROOT, f"{ROOT}/incoming", f"{ROOT}/backups")


class RecordingStore:
    def __init__(self, inner: StateStore, events: list[str]) -> None:
        self.inner = inner
        self.events = events
        self.complete_mode = "normal"
        self.queue_snapshot_error: Exception | None = None
        self.queue_snapshot_result: object | None = None

    def __getattr__(self, name: str):
        return getattr(self.inner, name)

    def complete_claim(
        self, claim: BackupClaim, remote: RemoteFile, uploaded_at: datetime
    ) -> None:
        self.events.append("mark_uploaded")
        if self.complete_mode == "precommit_error":
            raise RuntimeError("private state write details")
        self.inner.complete_claim(claim, remote, uploaded_at)
        if self.complete_mode == "postcommit_error":
            raise RuntimeError("private post-commit details")

    def queue_snapshot(self) -> QueueSnapshot:
        if self.queue_snapshot_error is not None:
            raise self.queue_snapshot_error
        if self.queue_snapshot_result is not None:
            return self.queue_snapshot_result  # type: ignore[return-value]
        return self.inner.queue_snapshot()

    def retry_record(self, sha256: str) -> tuple[str | None, datetime | None, int]:
        row = self.inner._db.execute(
            "SELECT error_code, retry_at, attempt_count FROM backups WHERE sha256 = ?",
            (sha256,),
        ).fetchone()
        if row is None:
            raise KeyError(sha256)
        retry_at = (
            None
            if row[1] is None
            else datetime.strptime(row[1], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
        )
        return row[0], retry_at, row[2]


class FakeClient:
    def __init__(self, events: list[str], remote: object) -> None:
        self.events = events
        self.remote = remote
        self.upload_error: Exception | None = None
        self.auth_results: list[object] = [True]
        self.upload_calls = 0
        self.on_upload = lambda: None
        self.final_lookup: object = None
        self.find_final_calls = 0

    def is_authenticated(self, cancel: Event | None = None) -> bool:
        if cancel is not None and cancel.is_set():
            raise ProtonCliCancelled("cancelled")
        result = self.auth_results.pop(0) if len(self.auth_results) > 1 else self.auth_results[0]
        if isinstance(result, Exception):
            raise result
        return result is True

    def ensure_layout(
        self, installation_id: str, cancel: Event | None = None
    ) -> RemoteLayout:
        if cancel is not None and cancel.is_set():
            raise ProtonCliCancelled("cancelled")
        if installation_id != INSTALLATION_ID:
            raise AssertionError("unexpected installation identity")
        return LAYOUT

    def find_final(
        self, backup: StableBackup, layout: RemoteLayout, cancel: Event | None = None
    ) -> object:
        if cancel is not None and cancel.is_set():
            raise ProtonCliCancelled("cancelled")
        self.find_final_calls += 1
        if isinstance(self.final_lookup, Exception):
            raise self.final_lookup
        return self.final_lookup

    def upload_and_finalize(
        self, backup: StableBackup, layout: RemoteLayout, cancel: Event
    ) -> object:
        self.events.append("upload")
        self.upload_calls += 1
        self.on_upload()
        if self.upload_error is not None:
            raise self.upload_error
        if isinstance(cancel, TransferControl):
            cancel.mark_success()
        return self.remote


class BlockingClient(FakeClient):
    def __init__(self, events: list[str], remote: RemoteFile) -> None:
        super().__init__(events, remote)
        self.started = Event()
        self.cancel_seen = Event()

    def upload_and_finalize(
        self, backup: StableBackup, layout: RemoteLayout, cancel: Event
    ) -> object:
        self.events.append("upload")
        self.upload_calls += 1
        self.started.set()
        if not cancel.wait(2):
            raise AssertionError("test did not cancel blocked upload")
        self.cancel_seen.set()
        raise ProtonCliCancelled("private cancellation details")


class FakeRetention:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.error: Exception | None = None
        self.result = RetentionResult([])

    def reconcile_after_success(
        self, layout: RemoteLayout, installation_id: str
    ) -> RetentionResult:
        self.events.append("retention")
        if self.error is not None:
            raise self.error
        return self.result

    def reconcile_external(
        self,
        layout: RemoteLayout,
        installation_id: str,
        confirmed_files: tuple[RemoteFile, ...],
        *,
        cancel: Event,
    ) -> RetentionResult:
        del confirmed_files, cancel
        return self.reconcile_after_success(layout, installation_id)


class MemoryClaimStore:
    """Independent thread-safe claim store used to prove the process guard."""

    def __init__(self, backup: StableBackup, remote: RemoteFile) -> None:
        self.backup = backup
        self.remote = remote
        self.status_value = BackupStatus.READY
        self.lock = Lock()

    def queue_snapshot(self):
        return QueueSnapshot(
            1 if self.status_value != BackupStatus.UPLOADED else 0, None, ()
        )

    def claim_next(self, now: datetime, claim_id: str) -> BackupClaim | None:
        with self.lock:
            if self.status_value != BackupStatus.READY:
                return None
            self.status_value = BackupStatus.UPLOADING
            return BackupClaim(self.backup, claim_id, 0)

    def installation_id(self) -> str:
        return INSTALLATION_ID

    def schedule_claim_retry(self, claim, **kwargs) -> None:
        with self.lock:
            self.status_value = BackupStatus.RETRY_WAIT

    def release_claim(self, claim, status, **kwargs) -> None:
        with self.lock:
            self.status_value = status

    def mark_claim_confirming(self, claim) -> None:
        with self.lock:
            self.status_value = BackupStatus.CONFIRMING

    def complete_claim(self, claim, remote, uploaded_at) -> None:
        with self.lock:
            self.status_value = BackupStatus.UPLOADED

    def confirmed_upload(self, sha256: str) -> RemoteFile | None:
        return self.remote if self.status_value == BackupStatus.UPLOADED else None

    def confirmed_remote_files(self) -> dict[str, RemoteFile]:
        return {}


class BackupWorkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "state.sqlite"
        self.events: list[str] = []
        self.store_inner = StateStore(self.db)
        self.addCleanup(self.store_inner.close)
        self.store_inner._db.execute(
            "INSERT INTO metadata(key, value) VALUES (?, ?)",
            ("installation_id", INSTALLATION_ID),
        )
        self.store = RecordingStore(self.store_inner, self.events)
        self.now = datetime(2026, 8, 11, 9, 0, tzinfo=UTC)
        self.clock_now = self.now
        self.monotonic = 100.0
        self.backup = StableBackup(
            Path("/backup/Home Assistant.tar"),
            "Home Assistant.tar",
            4096,
            1_786_435_200_000_000_000,
            "a" * 64,
        )
        final_name = (
            f"ha-v1--{INSTALLATION_ID}--20260811T080000Z--home-assistant--"
            f"{'a' * 12}.tar"
        )
        self.remote = RemoteFile(
            "remote-1", final_name, f"{LAYOUT.final}/{final_name}", 4096, self.now
        )
        self.store.enqueue(self.backup)
        self.client = FakeClient(self.events, self.remote)
        self.retention = FakeRetention(self.events)
        self.claim_counter = 0
        self.worker = self.make_worker()

    def make_worker(self, store=None, client=None, **kwargs) -> BackupWorker:
        def claim_id() -> str:
            self.claim_counter += 1
            return f"{self.claim_counter:032x}"

        jitter = kwargs.pop("jitter", lambda _window: 0.0)
        return BackupWorker(
            store or self.store,
            client or self.client,
            self.retention,
            clock=lambda: self.clock_now,
            monotonic=lambda: self.monotonic,
            jitter=jitter,
            claim_id_factory=claim_id,
            **kwargs,
        )

    def retry_record(self) -> tuple[str | None, datetime | None, int]:
        return self.store.retry_record(self.backup.sha256)

    def start_thread_worker(
        self,
        client: FakeClient,
        run_at: datetime,
        **worker_options,
    ) -> tuple[BackupWorker, Thread]:
        holder: dict[str, object] = {}
        created = Event()

        def run() -> None:
            inner = StateStore(self.db)
            try:
                threaded_store = RecordingStore(inner, self.events)
                worker = self.make_worker(
                    store=threaded_store, client=client, **worker_options
                )
                holder["worker"] = worker
                created.set()
                worker.run_once(run_at)
            finally:
                inner.close()

        thread = Thread(target=run)
        thread.start()
        self.assertTrue(created.wait(2))
        worker = holder["worker"]
        self.assertIsInstance(worker, BackupWorker)
        self.addCleanup(worker.cancel_current)  # type: ignore[union-attr]
        self.addCleanup(lambda: thread.join(2))
        return worker, thread  # type: ignore[return-value]

    def test_success_sequence_is_upload_confirm_state_then_retention(self) -> None:
        self.worker.run_once(self.now)

        self.assertEqual(self.events, ["upload", "mark_uploaded", "retention"])
        self.assertEqual(self.store.status(self.backup.sha256), BackupStatus.UPLOADED)

    def test_split_external_work_keeps_store_on_owner_and_confirms_before_upload(self) -> None:
        prepare = getattr(self.worker, "prepare_external", None)
        execute = getattr(self.worker, "execute_external", None)
        apply = getattr(self.worker, "apply_external", None)
        self.assertTrue(callable(prepare))
        self.assertTrue(callable(execute))
        self.assertTrue(callable(apply))

        preflight = prepare(self.now)
        self.assertIsNotNone(preflight)
        self.assertEqual(preflight.phase.value, "preflight")
        preflight_outcomes: list[object] = []
        preflight_thread = Thread(
            target=lambda: preflight_outcomes.append(execute(preflight))
        )
        preflight_thread.start()
        preflight_thread.join(2)
        self.assertFalse(preflight_thread.is_alive())

        upload = apply(preflight_outcomes[0])

        self.assertIsNotNone(upload)
        self.assertEqual(upload.phase.value, "upload")
        self.assertEqual(
            self.store.status(self.backup.sha256), BackupStatus.CONFIRMING
        )
        upload_outcomes: list[object] = []
        upload_thread = Thread(
            target=lambda: upload_outcomes.append(execute(upload))
        )
        upload_thread.start()
        upload_thread.join(2)
        self.assertFalse(upload_thread.is_alive())

        retention = apply(upload_outcomes[0])
        self.assertEqual(
            self.store.status(self.backup.sha256), BackupStatus.UPLOADED
        )
        self.assertIsNotNone(retention)
        self.assertEqual(retention.phase.value, "retention")
        retention_outcomes: list[object] = []
        retention_thread = Thread(
            target=lambda: retention_outcomes.append(execute(retention))
        )
        retention_thread.start()
        retention_thread.join(2)
        self.assertFalse(retention_thread.is_alive())
        self.assertIsNone(apply(retention_outcomes[0]))

        self.assertEqual(self.events, ["upload", "mark_uploaded", "retention"])

    def test_split_worker_never_prepares_a_second_claim_while_work_is_active(self) -> None:
        prepare = getattr(self.worker, "prepare_external", None)
        self.assertTrue(callable(prepare))

        first = prepare(self.now)

        self.assertIsNotNone(first)
        self.assertIsNone(prepare(self.now))
        self.assertEqual(self.store.status(self.backup.sha256), BackupStatus.UPLOADING)

        work = first
        while work is not None:
            work = self.worker.apply_external(self.worker.execute_external(work))

    def test_stale_external_result_is_rejected_and_can_be_aborted(self) -> None:
        work = self.worker.prepare_external(self.now)
        self.assertIsNotNone(work)
        stale_work = replace(work, generation=work.generation + 1)

        with self.assertRaises(RuntimeError):
            self.worker.apply_external(
                ExternalResult(stale_work, ExternalStatus.NETWORK_UNAVAILABLE)
            )
        self.worker.abort_external()

        self.assertEqual(
            self.store.status(self.backup.sha256), BackupStatus.READY
        )
        next_work = self.worker.prepare_external(self.now)
        self.assertIsNotNone(next_work)
        self.worker.abort_external()

    def test_two_worker_instances_have_one_process_wide_transfer_guard(self) -> None:
        first_store = MemoryClaimStore(self.backup, self.remote)
        second_backup = StableBackup(
            Path("/backup/second.tar"), "second.tar", 4096,
            self.backup.mtime_ns, "b" * 64,
        )
        second_store = MemoryClaimStore(second_backup, self.remote)
        blocking = BlockingClient(self.events, self.remote)
        first = self.make_worker(store=first_store, client=blocking)
        second = self.make_worker(store=second_store, client=blocking)
        thread = Thread(target=first.run_once, args=(self.now,))
        thread.start()
        self.addCleanup(first.cancel_current)
        self.addCleanup(lambda: thread.join(2))
        self.assertTrue(blocking.started.wait(2))

        second.run_once(self.now)

        self.assertEqual(blocking.upload_calls, 1)
        self.assertEqual(second_store.status_value, BackupStatus.READY)
        self.assertTrue(first.cancel_current())
        thread.join(2)

    def test_second_constructor_and_restart_do_not_recover_another_active_claim(self) -> None:
        claim = self.store.claim_next(self.now, "f" * 32)
        self.assertIsNotNone(claim)

        second = self.make_worker()
        second.restart()

        self.assertEqual(self.store.status(self.backup.sha256), BackupStatus.UPLOADING)

    def test_restart_during_upload_requeues_backup_as_ready(self) -> None:
        blocking = BlockingClient(self.events, self.remote)
        worker, thread = self.start_thread_worker(blocking, self.now)
        self.assertTrue(blocking.started.wait(2))

        worker.restart()
        thread.join(2)

        self.assertFalse(thread.is_alive())
        self.assertTrue(blocking.cancel_seen.is_set())
        self.assertEqual(blocking.upload_calls, 1)
        self.assertEqual(self.store.status(self.backup.sha256), BackupStatus.READY)
        self.assertEqual(self.retry_record(), ("cancelled", None, 0))

    def test_explicit_idle_restart_recovers_stale_claim(self) -> None:
        claim = self.store.claim_next(self.now, "f" * 32)
        self.assertIsNotNone(claim)
        worker = self.make_worker()

        self.assertTrue(worker.recover_startup())

        self.assertEqual(self.store.status(self.backup.sha256), BackupStatus.READY)

    def test_network_failure_during_upload_schedules_retry_from_fresh_clock(self) -> None:
        self.client.upload_error = ProtonNetworkError("private network details")
        self.client.on_upload = lambda: setattr(
            self, "clock_now", self.now + timedelta(hours=2)
        )

        self.worker.run_once(self.now)

        self.assertEqual(self.store.status(self.backup.sha256), BackupStatus.RETRY_WAIT)
        self.assertEqual(
            self.retry_record(),
            ("network_unavailable", self.now + timedelta(hours=2, minutes=1), 1),
        )
        self.assertNotIn("retention", self.events)

    def test_persistent_backoff_survives_worker_reconstruction(self) -> None:
        self.client.auth_results = [ProtonNetworkError("private network details")]
        self.worker.run_once(self.now)
        first_retry = self.retry_record()[1]
        self.assertIsNotNone(first_retry)
        self.clock_now = first_retry

        reconstructed = self.make_worker()
        reconstructed.run_once(first_retry)  # type: ignore[arg-type]

        self.assertEqual(
            self.retry_record(),
            ("network_unavailable", first_retry + timedelta(minutes=2), 2),
        )

    def test_persisted_backoff_is_one_two_four_eight_sixteen_thirty_two_sixty(self) -> None:
        self.client.auth_results = [ProtonNetworkError("private network details")]
        attempt_at = self.now
        delays: list[int] = []

        for _ in range(8):
            self.clock_now = attempt_at
            self.make_worker().run_once(attempt_at)
            retry_at = self.retry_record()[1]
            self.assertIsNotNone(retry_at)
            delays.append(int((retry_at - attempt_at).total_seconds() // 60))
            attempt_at = retry_at

        self.assertEqual(delays, [1, 2, 4, 8, 16, 32, 60, 60])

    def test_retry_jitter_is_deterministic_and_bounded_below_cap(self) -> None:
        windows: list[float] = []

        def excessive_jitter(window: float) -> float:
            windows.append(window)
            return window * 10

        self.client.auth_results = [ProtonNetworkError("private network details")]

        self.make_worker(jitter=excessive_jitter).run_once(self.now)

        self.assertEqual(windows, [15.0])
        self.assertEqual(self.retry_record()[1], self.now + timedelta(seconds=75))

    def test_production_default_jitter_is_random_and_bounded(self) -> None:
        self.client.auth_results = [ProtonNetworkError("private network details")]
        worker = BackupWorker(
            self.store,
            self.client,
            self.retention,
            clock=lambda: self.clock_now,
            monotonic=lambda: self.monotonic,
            claim_id_factory=lambda: "d" * 32,
        )

        with patch("proton_backup.worker.random.uniform", side_effect=lambda a, b: b / 2):
            worker.run_once(self.now)

        # attempt 1: 60 s base, 25 % window = 15 s, half of it from the RNG
        self.assertEqual(self.retry_record()[1], self.now + timedelta(seconds=67.5))

    def test_user_cancellation_is_one_minute_and_does_not_increment_attempt(self) -> None:
        self.client.auth_results = [ProtonNetworkError("private network details")]
        self.worker.run_once(self.now)
        due = self.retry_record()[1]
        self.assertIsNotNone(due)
        self.clock_now = due
        blocking = BlockingClient(self.events, self.remote)
        worker, thread = self.start_thread_worker(blocking, due)  # type: ignore[arg-type]
        self.assertTrue(blocking.started.wait(2))

        self.assertTrue(worker.cancel_current())
        thread.join(2)

        self.assertEqual(self.store.status(self.backup.sha256), BackupStatus.RETRY_WAIT)
        self.assertEqual(
            self.retry_record(), ("cancelled", due + timedelta(minutes=1), 1)
        )

    def test_watchdog_uses_monotonic_timeout_and_fresh_wall_clock_deadline(self) -> None:
        blocking = BlockingClient(self.events, self.remote)
        worker, thread = self.start_thread_worker(blocking, self.now)
        self.assertTrue(blocking.started.wait(2))
        self.clock_now = self.now + timedelta(hours=4)
        self.monotonic = 7299.9
        self.assertFalse(worker.watchdog())

        self.monotonic = 7300.0
        self.assertTrue(worker.watchdog())
        thread.join(2)

        self.assertEqual(
            self.retry_record(),
            ("process_timeout", self.now + timedelta(hours=4, minutes=1), 1),
        )

    def test_auth_loss_during_upload_parks_authentication_required(self) -> None:
        cases = (
            ProtonAuthenticationRequired("private auth details"),
            ProtonCliError("private generic details"),
        )
        for index, error in enumerate(cases):
            with self.subTest(error=type(error).__name__):
                if index == 0:
                    store = self.store
                    client = self.client
                else:
                    other_store_inner = StateStore(Path(self.temp.name) / "other.sqlite")
                    self.addCleanup(other_store_inner.close)
                    other_store_inner._db.execute(
                        "INSERT INTO metadata(key, value) VALUES (?, ?)",
                        ("installation_id", INSTALLATION_ID),
                    )
                    other_store_inner.enqueue(self.backup)
                    store = RecordingStore(other_store_inner, self.events)
                    client = FakeClient(self.events, self.remote)
                client.upload_error = error
                client.auth_results = [True, False]

                self.make_worker(store=store, client=client).run_once(self.now)

                self.assertEqual(
                    store.status(self.backup.sha256), BackupStatus.AUTH_REQUIRED
                )
                self.assertEqual(
                    store.retry_record(self.backup.sha256),
                    ("authentication_required", None, 0),
                )
                self.assertNotIn("retention", self.events)

    def test_generic_upload_error_with_live_auth_schedules_retry(self) -> None:
        self.client.upload_error = ProtonCliError("private ambiguous details")
        self.client.auth_results = [True, True]

        self.worker.run_once(self.now)

        self.assertEqual(self.store.status(self.backup.sha256), BackupStatus.RETRY_WAIT)
        self.assertEqual(
            self.retry_record(), ("upload_failed", self.now + timedelta(minutes=1), 1)
        )
        self.assertNotIn("retention", self.events)

    def test_retry_after_failed_upload_reconciles_instead_of_reuploading(self) -> None:
        self.client.upload_error = ProtonCliError("private ambiguous details")
        self.worker.run_once(self.now)
        due = self.retry_record()[1]
        self.assertIsNotNone(due)
        # The failed attempt had in fact finalized the file remotely.
        self.client.upload_error = None
        self.client.final_lookup = self.remote
        self.clock_now = due

        self.worker.run_once(due)  # type: ignore[arg-type]

        self.assertEqual(self.client.upload_calls, 1)
        self.assertEqual(self.store.status(self.backup.sha256), BackupStatus.REMOTE_AMBIGUOUS)
        self.assertEqual(self.store.confirmed_remote_files(), {})
        self.assertEqual(self.events, ["upload"])

    def test_preflight_never_adopts_existing_final_without_uid_evidence(self) -> None:
        self.client.final_lookup = self.remote

        self.worker.run_once(self.now)

        self.assertEqual(self.client.find_final_calls, 1)
        self.assertEqual(self.client.upload_calls, 0)
        self.assertEqual(self.store.status(self.backup.sha256), BackupStatus.REMOTE_AMBIGUOUS)
        self.assertEqual(self.events, [])

    def test_preflight_name_conflict_parks_ambiguous_without_upload(self) -> None:
        from proton_backup.proton_cli import ProtonRemoteConflict

        self.client.final_lookup = ProtonRemoteConflict("private conflict details")

        self.worker.run_once(self.now)

        self.assertEqual(self.client.upload_calls, 0)
        self.assertEqual(
            self.store.status(self.backup.sha256), BackupStatus.REMOTE_AMBIGUOUS
        )
        self.assertEqual(self.retry_record(), ("remote_ambiguous", None, 0))
        self.assertNotIn("retention", self.events)

    def test_preflight_lookup_failure_schedules_retry_without_upload(self) -> None:
        self.client.final_lookup = ProtonCliError("private listing details")

        self.worker.run_once(self.now)

        self.assertEqual(self.client.upload_calls, 0)
        self.assertEqual(
            self.retry_record(),
            ("network_unavailable", self.now + timedelta(minutes=1), 1),
        )

    def test_abort_during_upload_requeues_backup(self) -> None:
        preflight = self.worker.prepare_external(self.now)
        upload = self.worker.apply_external(self.worker.execute_external(preflight))
        self.assertEqual(upload.phase.value, "upload")  # type: ignore[union-attr]

        self.worker.abort_external()

        self.assertEqual(self.store.status(self.backup.sha256), BackupStatus.READY)
        self.assertEqual(self.client.upload_calls, 0)
        self.assertIsNotNone(self.worker.prepare_external(self.now))
        self.worker.abort_external()

    def test_authentication_resume_requeues_parked_backups(self) -> None:
        self.client.auth_results = [False]
        self.worker.run_once(self.now)
        self.assertEqual(
            self.store.status(self.backup.sha256), BackupStatus.AUTH_REQUIRED
        )
        self.client.auth_results = [True]

        self.assertEqual(self.worker.resume_after_authentication(), 1)
        self.worker.run_once(self.now)

        self.assertEqual(self.store.status(self.backup.sha256), BackupStatus.UPLOADED)

    def test_malformed_upload_result_is_parked_without_persistence_or_retention(self) -> None:
        self.client.remote = {"uid": "remote-1"}

        self.worker.run_once(self.now)

        self.assertEqual(
            self.store.status(self.backup.sha256), BackupStatus.REMOTE_AMBIGUOUS
        )
        self.assertEqual(self.store.confirmed_remote_files(), {})
        self.assertNotIn("retention", self.events)

    def test_postcommit_raise_is_reconciled_as_success_before_retention(self) -> None:
        self.store.complete_mode = "postcommit_error"

        self.worker.run_once(self.now)

        self.assertEqual(self.store.status(self.backup.sha256), BackupStatus.UPLOADED)
        self.assertEqual(self.events, ["upload", "mark_uploaded", "retention"])

    def test_precommit_state_failure_parks_ambiguous_without_auto_retry(self) -> None:
        self.store.complete_mode = "precommit_error"

        self.worker.run_once(self.now)

        self.assertEqual(
            self.store.status(self.backup.sha256), BackupStatus.REMOTE_AMBIGUOUS
        )
        self.assertEqual(self.retry_record(), ("remote_ambiguous", None, 0))
        self.assertNotIn("retention", self.events)

    def test_cancellation_is_detached_before_worker_revalidates_returned_result(self) -> None:
        validation_started = Event()
        allow_validation = Event()

        def blocked_validation(remote, backup, layout):
            validation_started.set()
            if not allow_validation.wait(2):
                raise AssertionError("test did not release validation")
            return validate_upload_result(remote, backup, layout)

        worker, thread = self.start_thread_worker(
            self.client, self.now, upload_validator=blocked_validation
        )
        self.addCleanup(lambda: allow_validation.set())
        self.assertTrue(validation_started.wait(2))

        self.assertFalse(worker.cancel_current())
        self.assertFalse(worker.watchdog())
        allow_validation.set()
        thread.join(2)

        self.assertEqual(self.store.status(self.backup.sha256), BackupStatus.UPLOADED)

    def test_retry_now_resets_persistent_attempt_but_rejects_ambiguous_upload(self) -> None:
        self.client.auth_results = [ProtonNetworkError("private network details")]
        self.worker.run_once(self.now)
        self.worker.retry_now(
            self.backup.sha256, self.worker.snapshot().retry_revision
        )
        claim = self.store.claim_next(self.now, "e" * 32)
        self.assertEqual(claim.attempt_count, 0)  # type: ignore[union-attr]
        self.store.release_claim(
            claim, BackupStatus.REMOTE_AMBIGUOUS, error_code="remote_ambiguous"  # type: ignore[arg-type]
        )

        with self.assertRaises(ValueError):
            self.worker.retry_now(
                self.backup.sha256, self.worker.snapshot().retry_revision
            )

    def test_retention_failure_preserves_uploaded_status_and_safe_snapshot(self) -> None:
        self.retention.error = RuntimeError("password=private-secret")

        self.worker.run_once(self.now)

        snapshot = self.worker.snapshot()
        self.assertEqual(self.store.status(self.backup.sha256), BackupStatus.UPLOADED)
        self.assertEqual(snapshot.last_error_code, "retention_failed")
        self.assertNotIn("private-secret", repr(snapshot))

    def test_retention_deletions_are_removed_from_cached_remote_snapshot(self) -> None:
        self.retention.result = RetentionResult([self.remote])

        self.worker.run_once(self.now)

        self.assertEqual(self.store.status(self.backup.sha256), BackupStatus.UPLOADED)
        self.assertEqual(self.worker.snapshot().remote_files, ())

    def test_snapshot_is_immutable_and_uses_cached_state(self) -> None:
        self.client.auth_results = [ProtonNetworkError("private network details")]
        self.worker.run_once(self.now)

        snapshot = self.worker.snapshot()

        self.assertIsInstance(snapshot, ServiceSnapshot)
        self.assertEqual(snapshot.queue_size, 1)
        self.assertEqual(snapshot.next_retry_at, self.retry_record()[1])
        self.assertEqual(snapshot.retry_sha256, self.backup.sha256)
        with self.assertRaises(FrozenInstanceError):
            snapshot.last_error_code = "changed"  # type: ignore[misc]

    def test_retry_target_clears_after_operator_retry(self) -> None:
        self.client.auth_results = [ProtonNetworkError("private network details")]
        self.worker.run_once(self.now)

        self.worker.retry_now(
            self.backup.sha256, self.worker.snapshot().retry_revision
        )

        self.assertIsNone(self.worker.snapshot().retry_sha256)

    def test_retry_revision_changes_only_after_authoritative_state_change(self) -> None:
        self.assertEqual(getattr(self.worker.snapshot(), "retry_revision", None), 0)
        self.client.auth_results = [ProtonNetworkError("private network details")]
        self.worker.run_once(self.now)

        failed = self.worker.snapshot()
        self.assertEqual(failed.retry_sha256, self.backup.sha256)
        self.assertEqual(failed.retry_revision, 1)

        self.worker._refresh_queue_cache()
        self.assertEqual(self.worker.snapshot().retry_revision, 1)

        self.store.queue_snapshot_error = RuntimeError("private state read details")
        self.worker._refresh_queue_cache()
        unavailable = self.worker.snapshot()
        self.assertIsNone(unavailable.retry_sha256)
        self.assertEqual(unavailable.retry_revision, 1)

        self.store.queue_snapshot_error = None
        self.worker._refresh_queue_cache()
        restored = self.worker.snapshot()
        self.assertEqual(restored.retry_sha256, self.backup.sha256)
        self.assertEqual(restored.retry_revision, 1)

        self.worker.retry_now(self.backup.sha256, restored.retry_revision)
        cleared = self.worker.snapshot()
        self.assertIsNone(cleared.retry_sha256)
        self.assertEqual(cleared.retry_revision, 2)
        with self.assertRaises(ValueError):
            self.worker.retry_now(self.backup.sha256, restored.retry_revision)

    def test_retry_target_fails_closed_when_cache_refresh_fails(self) -> None:
        self.client.auth_results = [ProtonNetworkError("private network details")]
        self.worker.run_once(self.now)
        self.assertEqual(self.worker.snapshot().retry_sha256, self.backup.sha256)
        retry_revision = self.worker.snapshot().retry_revision

        self.store.queue_snapshot_error = RuntimeError("private state read details")
        self.worker.retry_now(self.backup.sha256, retry_revision)

        self.assertEqual(self.store.status(self.backup.sha256), BackupStatus.READY)
        self.assertIsNone(self.worker.snapshot().retry_sha256)

    def test_retry_target_fails_closed_for_invalid_cache_snapshot(self) -> None:
        self.client.auth_results = [ProtonNetworkError("private network details")]
        self.worker.run_once(self.now)
        self.assertEqual(self.worker.snapshot().retry_sha256, self.backup.sha256)
        retry_revision = self.worker.snapshot().retry_revision

        self.store.queue_snapshot_result = object()
        self.worker.retry_now(self.backup.sha256, retry_revision)

        self.assertEqual(self.store.status(self.backup.sha256), BackupStatus.READY)
        self.assertIsNone(self.worker.snapshot().retry_sha256)

    def test_naive_wall_clock_is_rejected_without_claiming(self) -> None:
        with self.assertRaises(ValueError):
            self.worker.run_once(datetime(2026, 8, 11, 9, 0))
        self.assertEqual(self.store.status(self.backup.sha256), BackupStatus.READY)


if __name__ == "__main__":
    unittest.main()
