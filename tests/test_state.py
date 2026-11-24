from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier, Lock, Thread

APP_ROOT = Path(__file__).resolve().parents[1] / "proton_drive_backup" / "rootfs" / "app"
sys.path.insert(0, str(APP_ROOT))

from proton_backup.models import BackupStatus, RemoteFile, StableBackup
from proton_backup.state import BackupClaim, ClaimLostError, StateStore


class StateStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.db = Path(self.temporary_directory.name) / "state" / "state.sqlite"
        self.now = datetime(2026, 8, 10, 12, 0, tzinfo=UTC)
        self.backup = StableBackup(
            local_path=Path("/backup/safe.tar"), display_name="safe.tar", size=42,
            mtime_ns=123_456_789, sha256="a" * 64,
        )
        self.remote = RemoteFile(
            uid="remote-1", name="safe.tar", path="/final/safe.tar", size=42,
            modified_at=self.now,
        )
        self.stores: list[StateStore] = []

    def open_store(self) -> StateStore:
        store = StateStore(self.db)
        self.stores.append(store)
        return store

    def tearDown(self) -> None:
        for store in self.stores:
            store.close()
        self.temporary_directory.cleanup()

    def test_initializes_versioned_schema_and_wal_database(self) -> None:
        self.open_store().close()
        connection = sqlite3.connect(self.db)
        try:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)
            self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone()[0], "wal")
            self.assertEqual(
                {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")},
                {"metadata", "backups", "remote_files", "observations"},
            )
        finally:
            connection.close()

    def test_store_rejects_access_outside_its_owner_thread(self) -> None:
        store = self.open_store()
        failures: list[BaseException] = []

        def read_from_foreign_thread() -> None:
            try:
                store.queue_snapshot()
            except BaseException as error:
                failures.append(error)

        thread = Thread(target=read_from_foreign_thread)
        thread.start()
        thread.join(2)

        self.assertFalse(thread.is_alive())
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], RuntimeError)
        self.assertEqual(str(failures[0]), "state store used outside owner thread")

    def test_installation_id_is_stable(self) -> None:
        first = self.open_store().installation_id()
        second = self.open_store().installation_id()
        self.assertRegex(first, r"^[a-f0-9]{32}$")
        self.assertEqual(first, second)

    def test_duplicate_sha256_enqueue_keeps_original_queue_record(self) -> None:
        store = self.open_store()
        store.enqueue(self.backup)
        replacement = StableBackup(
            local_path=Path("/backup/renamed.tar"), display_name="renamed.tar", size=99,
            mtime_ns=999, sha256=self.backup.sha256,
        )
        store.enqueue(replacement)
        queued = store.next_ready(self.now)
        self.assertEqual(queued, self.backup)

    def test_retry_timestamp_prevents_selection_until_due(self) -> None:
        store = self.open_store()
        store.enqueue(self.backup)
        retry_at = self.now + timedelta(minutes=5)
        store.mark_status(self.backup.sha256, BackupStatus.RETRY_WAIT, error_code="network", retry_at=retry_at)
        self.assertIsNone(store.next_ready(self.now))
        self.assertEqual(store.queue_snapshot().retry_sha256, self.backup.sha256)
        self.assertEqual(store.next_ready(retry_at), self.backup)

    def test_fractional_retry_is_not_eligible_before_due_time(self) -> None:
        store = self.open_store()
        store.enqueue(self.backup)
        retry_at = self.now + timedelta(microseconds=500_000)
        store.mark_status(self.backup.sha256, BackupStatus.RETRY_WAIT, retry_at=retry_at)
        self.assertIsNone(store.next_ready(self.now))
        self.assertEqual(store.next_ready(retry_at), self.backup)

    def test_observation_requires_two_matching_scans_and_tracks_path(self) -> None:
        store = self.open_store()
        path = Path("/backup/safe.tar")
        self.assertFalse(store.observe(path, 42, 123_456_789, self.now))
        self.assertTrue(store.observe(path, 42, 123_456_789, self.now + timedelta(seconds=60)))
        self.assertFalse(store.observe(path, 43, 123_456_789, self.now + timedelta(seconds=120)))
        self.assertEqual(store.observed_paths(), {path})

    def test_invalidating_observation_requires_two_new_sightings(self) -> None:
        store = self.open_store()
        path = Path("/backup/recreated.tar")
        self.assertFalse(store.observe(path, 42, 123_456_789, self.now))
        self.assertTrue(store.observe(path, 42, 123_456_789, self.now + timedelta(seconds=60)))

        store.invalidate_observation(path)

        self.assertFalse(store.observe(path, 42, 123_456_789, self.now + timedelta(seconds=120)))
        self.assertTrue(store.observe(path, 42, 123_456_789, self.now + timedelta(seconds=180)))

    def test_retaining_successful_observations_removes_missing_paths(self) -> None:
        store = self.open_store()
        kept = Path("/backup/kept.tar")
        missing = Path("/backup/missing.tar")
        store.observe(kept, 1, 11, self.now)
        store.observe(missing, 2, 22, self.now)

        store.retain_observations({kept})

        self.assertEqual(store.observed_paths(), {kept})

    def test_opening_second_store_does_not_recover_live_claim(self) -> None:
        store = self.open_store()
        store.enqueue(self.backup)
        claim = store.claim_next(self.now, "1" * 32)
        self.assertIsInstance(claim, BackupClaim)

        second = self.open_store()

        self.assertEqual(second.status(self.backup.sha256), BackupStatus.UPLOADING)
        self.assertIsNone(second.claim_next(self.now, "2" * 32))

    def test_explicit_startup_recovery_resets_stale_claim(self) -> None:
        store = self.open_store()
        store.enqueue(self.backup)
        claim = store.claim_next(self.now, "1" * 32)
        self.assertIsNotNone(claim)
        store.close()
        restarted = self.open_store()

        recovered = restarted.recover_transient()

        self.assertEqual(recovered, 1)
        self.assertEqual(restarted.status(self.backup.sha256), BackupStatus.READY)

    def test_atomic_claim_blocks_different_ready_item_across_connections(self) -> None:
        first = self.open_store()
        second = self.open_store()
        first.enqueue(self.backup)
        other = StableBackup(Path("/backup/other.tar"), "other.tar", 7, 456, "b" * 64)
        first.enqueue(other)

        claimed = first.claim_next(self.now, "1" * 32)

        self.assertEqual(claimed.backup, self.backup)  # type: ignore[union-attr]
        self.assertIsNone(second.claim_next(self.now, "2" * 32))
        self.assertEqual(second.status(other.sha256), BackupStatus.READY)

    def test_concurrent_connections_atomically_select_only_one_global_claim(self) -> None:
        seed = self.open_store()
        seed.enqueue(self.backup)
        other = StableBackup(Path("/backup/other.tar"), "other.tar", 7, 456, "b" * 64)
        seed.enqueue(other)
        barrier = Barrier(3)
        result_lock = Lock()
        claims: list[BackupClaim | None] = []

        def claim(claim_id: str) -> None:
            store = StateStore(self.db)
            try:
                barrier.wait()
                result = store.claim_next(self.now, claim_id)
                with result_lock:
                    claims.append(result)
            finally:
                store.close()

        threads = [
            Thread(target=claim, args=("1" * 32,)),
            Thread(target=claim, args=("2" * 32,)),
        ]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(2)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(sum(item is not None for item in claims), 1)
        statuses = {seed.status(self.backup.sha256), seed.status(other.sha256)}
        self.assertEqual(statuses, {BackupStatus.UPLOADING, BackupStatus.READY})

    def test_recovery_requeues_confirming_claim_for_reconciliation(self) -> None:
        # A crash while CONFIRMING may or may not have finalized the upload.
        # The next attempt reconciles against the final folder before it
        # uploads, so the row must become claimable again instead of parked.
        store = self.open_store()
        store.enqueue(self.backup)
        claim = store.claim_next(self.now, "1" * 32)
        store.mark_claim_confirming(claim)  # type: ignore[arg-type]

        store.recover_transient()

        self.assertEqual(store.status(self.backup.sha256), BackupStatus.READY)

    def test_recovery_requeues_parked_ambiguous_and_auth_required_backups(self) -> None:
        store = self.open_store()
        other = StableBackup(
            local_path=Path("/backup/other.tar"), display_name="other.tar", size=7,
            mtime_ns=987_654_321, sha256="b" * 64,
        )
        store.enqueue(self.backup)
        store.enqueue(other)
        first = store.claim_next(self.now, "1" * 32)
        store.release_claim(  # type: ignore[arg-type]
            first, BackupStatus.REMOTE_AMBIGUOUS, error_code="remote_ambiguous"
        )
        second = store.claim_next(self.now, "2" * 32)
        store.release_claim(  # type: ignore[arg-type]
            second, BackupStatus.AUTH_REQUIRED, error_code="authentication_required"
        )

        recovered = store.recover_transient()

        self.assertEqual(recovered, 2)
        self.assertEqual(store.status(self.backup.sha256), BackupStatus.READY)
        self.assertEqual(store.status(other.sha256), BackupStatus.READY)

    def test_claim_retry_can_be_scheduled_after_confirming_began(self) -> None:
        store = self.open_store()
        store.enqueue(self.backup)
        claim = store.claim_next(self.now, "1" * 32)
        store.mark_claim_confirming(claim)  # type: ignore[arg-type]

        store.schedule_claim_retry(  # type: ignore[arg-type]
            claim,
            error_code="upload_failed",
            retry_at=self.now + timedelta(minutes=1),
            increment_attempt=True,
        )

        self.assertEqual(store.status(self.backup.sha256), BackupStatus.RETRY_WAIT)
        self.assertIsNone(store.next_ready(self.now))
        self.assertEqual(store.next_ready(self.now + timedelta(minutes=1)), self.backup)

    def test_release_auth_required_requeues_only_parked_backups(self) -> None:
        store = self.open_store()
        other = StableBackup(
            local_path=Path("/backup/other.tar"), display_name="other.tar", size=7,
            mtime_ns=987_654_321, sha256="b" * 64,
        )
        store.enqueue(self.backup)
        store.enqueue(other)
        parked = store.claim_next(self.now, "1" * 32)
        store.release_claim(  # type: ignore[arg-type]
            parked, BackupStatus.AUTH_REQUIRED, error_code="authentication_required"
        )
        active = store.claim_next(self.now, "2" * 32)
        self.assertIsNotNone(active)

        self.assertEqual(store.release_auth_required(), 1)

        self.assertEqual(store.status(self.backup.sha256), BackupStatus.READY)
        self.assertEqual(store.status(other.sha256), BackupStatus.UPLOADING)

    def test_claim_transition_requires_exact_claim_owner(self) -> None:
        store = self.open_store()
        store.enqueue(self.backup)
        claim = store.claim_next(self.now, "1" * 32)
        self.assertIsNotNone(claim)
        foreign = BackupClaim(self.backup, "2" * 32, 0)

        with self.assertRaises(ClaimLostError):
            store.schedule_claim_retry(
                foreign,
                error_code="network_unavailable",
                retry_at=self.now + timedelta(minutes=1),
                increment_attempt=True,
            )

        self.assertEqual(store.status(self.backup.sha256), BackupStatus.UPLOADING)

    def test_retry_attempt_is_incremented_atomically_and_survives_reopen(self) -> None:
        store = self.open_store()
        store.enqueue(self.backup)
        first = store.claim_next(self.now, "1" * 32)
        self.assertIsNotNone(first)
        retry_at = self.now + timedelta(minutes=1)
        store.schedule_claim_retry(
            first,  # type: ignore[arg-type]
            error_code="network_unavailable",
            retry_at=retry_at,
            increment_attempt=True,
        )
        store.close()
        reopened = self.open_store()

        second = reopened.claim_next(retry_at, "2" * 32)

        self.assertEqual(second.attempt_count, 1)  # type: ignore[union-attr]

    def test_user_retry_resets_persisted_attempt_count(self) -> None:
        store = self.open_store()
        store.enqueue(self.backup)
        claim = store.claim_next(self.now, "1" * 32)
        self.assertIsNotNone(claim)
        store.schedule_claim_retry(
            claim,  # type: ignore[arg-type]
            error_code="network_unavailable",
            retry_at=self.now + timedelta(minutes=1),
            increment_attempt=True,
        )

        store.retry_now(self.backup.sha256)
        retried = store.claim_next(self.now, "2" * 32)

        self.assertEqual(retried.attempt_count, 0)  # type: ignore[union-attr]

    def test_user_retry_transitions_only_retry_wait_once(self) -> None:
        store = self.open_store()
        store.enqueue(self.backup)

        with self.assertRaises(ValueError):
            store.retry_now(self.backup.sha256)

        store.mark_status(
            self.backup.sha256,
            BackupStatus.AUTH_REQUIRED,
            error_code="authentication_required",
        )
        with self.assertRaises(ValueError):
            store.retry_now(self.backup.sha256)

        store.mark_status(
            self.backup.sha256,
            BackupStatus.RETRY_WAIT,
            error_code="network_unavailable",
            retry_at=self.now + timedelta(minutes=1),
        )
        store.retry_now(self.backup.sha256)

        self.assertEqual(store.status(self.backup.sha256), BackupStatus.READY)
        with self.assertRaises(ValueError):
            store.retry_now(self.backup.sha256)

    def test_uploaded_transition_records_remote_atomically(self) -> None:
        store = self.open_store()
        store.enqueue(self.backup)
        claim = store.claim_next(self.now, "1" * 32)
        store.mark_claim_confirming(claim)  # type: ignore[arg-type]
        store.complete_claim(claim, self.remote, self.now)  # type: ignore[arg-type]
        self.assertEqual(store.status(self.backup.sha256), BackupStatus.UPLOADED)
        self.assertEqual(store.confirmed_remote_files(), {self.remote.uid: self.remote})

    def test_existing_remote_uid_cannot_be_reassigned_to_another_backup(self) -> None:
        store = self.open_store()
        store.enqueue(self.backup)
        claim = store.claim_next(self.now, "1" * 32)
        store.mark_claim_confirming(claim)  # type: ignore[arg-type]
        store.complete_claim(claim, self.remote, self.now)  # type: ignore[arg-type]
        other = StableBackup(Path("/backup/other.tar"), "other.tar", 7, 456, "b" * 64)
        store.enqueue(other)
        other_claim = store.claim_next(self.now, "2" * 32)
        store.mark_claim_confirming(other_claim)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            store.complete_claim(other_claim, self.remote, self.now)  # type: ignore[arg-type]
        self.assertEqual(store.status(other.sha256), BackupStatus.CONFIRMING)
        self.assertEqual(store.confirmed_remote_files(), {self.remote.uid: self.remote})

    def test_repeating_same_remote_uid_and_sha_is_idempotent(self) -> None:
        store = self.open_store()
        store.enqueue(self.backup)
        claim = store.claim_next(self.now, "1" * 32)
        store.mark_claim_confirming(claim)  # type: ignore[arg-type]
        store.complete_claim(claim, self.remote, self.now)  # type: ignore[arg-type]
        store.complete_claim(claim, self.remote, self.now)  # type: ignore[arg-type]
        self.assertEqual(store.status(self.backup.sha256), BackupStatus.UPLOADED)
        self.assertEqual(store.confirmed_remote_files(), {self.remote.uid: self.remote})

    def test_idempotent_completion_requires_exact_durable_uploaded_status(self) -> None:
        store = self.open_store()
        store.enqueue(self.backup)
        claim = store.claim_next(self.now, "1" * 32)
        store.mark_claim_confirming(claim)  # type: ignore[arg-type]
        store.complete_claim(claim, self.remote, self.now)  # type: ignore[arg-type]
        store._db.execute(
            "UPDATE backups SET status = ? WHERE sha256 = ?",
            (BackupStatus.REMOTE_AMBIGUOUS.value, self.backup.sha256),
        )

        with self.assertRaises(ClaimLostError):
            store.complete_claim(claim, self.remote, self.now)  # type: ignore[arg-type]

    def test_legacy_status_transition_cannot_fabricate_upload_outcomes(self) -> None:
        store = self.open_store()
        store.enqueue(self.backup)

        for status in (BackupStatus.UPLOADED, BackupStatus.REMOTE_AMBIGUOUS):
            with self.subTest(status=status), self.assertRaises(ValueError):
                store.mark_status(self.backup.sha256, status)

        self.assertEqual(store.status(self.backup.sha256), BackupStatus.READY)

    def test_remote_insert_failure_rolls_back_uploaded_status(self) -> None:
        store = self.open_store()
        store.enqueue(self.backup)
        claim = store.claim_next(self.now, "1" * 32)
        store.mark_claim_confirming(claim)  # type: ignore[arg-type]
        store._db.execute(
            "CREATE TRIGGER reject_remote_insert BEFORE INSERT ON remote_files "
            "BEGIN SELECT RAISE(ABORT, 'forced remote failure'); END"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            store.complete_claim(claim, self.remote, self.now)  # type: ignore[arg-type]
        self.assertEqual(store.status(self.backup.sha256), BackupStatus.CONFIRMING)
        self.assertEqual(store.confirmed_remote_files(), {})

    def test_partial_versioned_schema_fails_closed_without_repair(self) -> None:
        self.open_store().close()
        connection = sqlite3.connect(self.db)
        try:
            connection.execute("DROP TABLE remote_files")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(RuntimeError):
            StateStore(self.db)
        connection = sqlite3.connect(self.db)
        try:
            self.assertNotIn(
                "remote_files",
                {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")},
            )
        finally:
            connection.close()

    def test_malformed_persisted_values_fail_closed(self) -> None:
        cases = (
            ("UPDATE metadata SET value = 'not-an-installation-id' WHERE key = 'installation_id'",),
            ("INSERT INTO backups(sha256, local_path, display_name, size, mtime_ns, status, retry_at) "
             "VALUES ('c', '/backup/a.tar', 'a.tar', 1, 1, 'ready', '2026-08-10T12:00:00Z')",),
            ("INSERT INTO backups(sha256, local_path, display_name, size, mtime_ns, status) "
             "VALUES ('d', '/backup/b.tar', 'b.tar', 1, 1, 'unknown')",),
        )
        for (statement,) in cases:
            with self.subTest(statement=statement):
                self.open_store().installation_id()
                self.stores.pop().close()
                connection = sqlite3.connect(self.db)
                try:
                    connection.execute(statement)
                    connection.commit()
                finally:
                    connection.close()
                with self.assertRaises(RuntimeError):
                    StateStore(self.db)
                self.db.unlink()

    def test_locked_database_is_not_renamed_as_corrupt(self) -> None:
        store = self.open_store()
        store._db.execute("BEGIN EXCLUSIVE")
        try:
            with self.assertRaises(sqlite3.OperationalError):
                StateStore(self.db)
            self.assertTrue(self.db.exists())
            self.assertEqual(list(self.db.parent.glob("state.sqlite.corrupt-*")), [])
        finally:
            store._db.rollback()

    def test_corrupt_database_is_preserved_with_timestamped_name(self) -> None:
        self.db.parent.mkdir(parents=True)
        self.db.write_bytes(b"this is not a sqlite database")
        with self.assertRaises(RuntimeError):
            StateStore(self.db)
        corrupt = list(self.db.parent.glob("state.sqlite.corrupt-????????T??????Z"))
        self.assertEqual(len(corrupt), 1)
        self.assertEqual(corrupt[0].read_bytes(), b"this is not a sqlite database")
        self.assertFalse(self.db.exists())


if __name__ == "__main__":
    unittest.main()
