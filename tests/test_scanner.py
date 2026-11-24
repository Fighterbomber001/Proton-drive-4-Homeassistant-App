from __future__ import annotations

import copy
import os
import stat
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, Thread
from unittest.mock import patch

APP_ROOT = Path(__file__).resolve().parents[1] / "proton_drive_backup" / "rootfs" / "app"
sys.path.insert(0, str(APP_ROOT))

from proton_backup import scanner as scanner_module
from proton_backup.scanner import BackupScanner
from proton_backup.state import StateStore


SECURE_DIR_FD_AVAILABLE = (
    hasattr(os, "O_DIRECTORY")
    and hasattr(os, "O_NOFOLLOW")
    and os.open in os.supports_dir_fd
    and os.stat in os.supports_dir_fd
    and os.stat in os.supports_follow_symlinks
    and os.listdir in os.supports_fd
)


class BackupScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary_directory.name)
        self.root = self.base / "backup"
        self.root.mkdir()
        self.store = StateStore(self.base / "state" / "state.sqlite")
        self.scanner = BackupScanner(self.root, self.store)
        self.t0 = datetime(2026, 8, 10, 12, 0, tzinfo=UTC)

    def tearDown(self) -> None:
        self.store.close()
        self.temporary_directory.cleanup()

    def write_backup(self, name: str, content: bytes) -> Path:
        path = self.root / name
        path.write_bytes(content)
        return path

    def symlink_or_skip(self, link: Path, target: Path, *, target_is_directory: bool = False) -> None:
        try:
            link.symlink_to(target, target_is_directory=target_is_directory)
        except OSError as error:
            self.skipTest(f"symlinks are unavailable: {error}")

    def require_secure_directory_descriptors(self) -> None:
        if not SECURE_DIR_FD_AVAILABLE:
            self.skipTest("secure directory-descriptor primitives are unavailable")

    def validate(self, evidence, cancel: Event | None = None):
        token = cancel or Event()
        return self.scanner.validate_scan(evidence, token).finish(token)

    def test_requires_exactly_two_unchanged_observations(self) -> None:
        self.require_secure_directory_descriptors()
        path = self.write_backup("safe.tar", b"one")

        self.assertEqual(self.scanner.scan(self.t0), [])
        ready = self.scanner.scan(self.t0 + timedelta(seconds=60))

        self.assertEqual(len(ready), 1)
        self.assertEqual(ready[0].local_path, path)
        self.assertEqual(ready[0].display_name, "safe.tar")
        self.assertEqual(ready[0].size, 3)
        self.assertEqual(ready[0].mtime_ns, path.stat().st_mtime_ns)
        self.assertEqual(
            ready[0].sha256,
            "7692c3ad3540bb803c020b3aee66cd8887123234ea0c6e7143c0add73ff431ed",
        )
        self.assertEqual(self.store.next_ready(self.t0 + timedelta(seconds=60)), ready[0])

    def test_split_scan_collects_off_owner_and_applies_two_complete_generations(self) -> None:
        self.require_secure_directory_descriptors()
        path = self.write_backup("split.tar", b"split-content")

        first_baseline = self.scanner.prepare_scan(1, self.t0)
        first_results: list[object] = []
        first_thread = Thread(
            target=lambda: first_results.append(
                self.scanner.collect_scan(first_baseline, Event())
            )
        )
        first_thread.start()
        first_thread.join(2)
        self.assertFalse(first_thread.is_alive())
        self.assertEqual(self.scanner.apply_scan(self.validate(first_results[0]), 1), [])

        second_baseline = self.scanner.prepare_scan(
            2, self.t0 + timedelta(seconds=60)
        )
        second_results: list[object] = []
        second_thread = Thread(
            target=lambda: second_results.append(
                self.scanner.collect_scan(second_baseline, Event())
            )
        )
        second_thread.start()
        second_thread.join(2)
        self.assertFalse(second_thread.is_alive())
        ready = self.scanner.apply_scan(self.validate(second_results[0]), 2)

        self.assertEqual([backup.local_path for backup in ready], [path])
        self.assertEqual(self.store.next_ready(self.t0 + timedelta(seconds=60)), ready[0])

    def test_owner_rejects_unvalidated_synthetic_scan_evidence(self) -> None:
        identity_type = getattr(scanner_module, "FileIdentity", None)
        candidate_type = getattr(scanner_module, "CandidateEvidence", None)
        evidence_type = getattr(scanner_module, "ScanEvidence", None)
        disposition_type = getattr(scanner_module, "ScanDisposition", None)
        self.assertIsNotNone(identity_type)
        self.assertIsNotNone(candidate_type)
        self.assertIsNotNone(evidence_type)
        self.assertIsNotNone(disposition_type)
        path = self.root / "evidence.tar"
        identity = identity_type(1, 2, stat.S_IFREG, 8, 123)
        first_candidate = candidate_type(
            path, "evidence.tar", 8, 123, identity, None, False, False
        )
        first = evidence_type(
            100,
            self.t0,
            disposition_type.COMPLETE,
            (first_candidate,),
        )
        second_candidate = candidate_type(
            path,
            "evidence.tar",
            8,
            123,
            identity,
            "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4",
            False,
            False,
        )
        second = evidence_type(
            101,
            self.t0 + timedelta(seconds=60),
            disposition_type.COMPLETE,
            (second_candidate,),
        )

        with self.assertRaises(ValueError):
            self.scanner.apply_scan(first, 100)
        with self.assertRaises(ValueError):
            self.scanner.apply_scan(second, 101)
        self.assertIsNone(self.store.next_ready(self.t0 + timedelta(seconds=60)))

    def test_validation_capability_is_instance_bound_single_use_and_uncopyable(self) -> None:
        baseline = self.scanner.prepare_scan(1, self.t0)
        evidence = self.scanner.collect_scan(baseline, Event())
        validation = self.scanner.validate_scan(evidence, Event())
        token = validation.finish(Event())

        for forged in (copy.copy(token), copy.deepcopy(token)):
            with self.assertRaises(ValueError):
                self.scanner.apply_scan(forged, 1)

        other_root = self.base / "other"
        other_root.mkdir()
        other_store = StateStore(self.base / "other-state" / "state.sqlite")
        try:
            other_scanner = BackupScanner(other_root, other_store)
            with self.assertRaises(ValueError):
                other_scanner.apply_scan(token, 1)
        finally:
            other_store.close()

        self.assertEqual(self.scanner.apply_scan(token, 1), [])
        with self.assertRaises(ValueError):
            self.scanner.apply_scan(token, 1)

    def test_public_validation_constructor_cannot_mint_apply_capability(self) -> None:
        evidence = scanner_module.ScanEvidence(
            1,
            self.t0,
            scanner_module.ScanDisposition.COMPLETE,
            (),
        )
        forged = scanner_module.ScanValidation(evidence, ()).finish(Event())

        with self.assertRaises(ValueError):
            self.scanner.apply_scan(forged, 1)
        self.assertEqual(self.store.observed_paths(), set())

    def test_synthetic_cancelled_failed_and_stale_evidence_are_rejected(self) -> None:
        identity_type = getattr(scanner_module, "FileIdentity", None)
        candidate_type = getattr(scanner_module, "CandidateEvidence", None)
        evidence_type = getattr(scanner_module, "ScanEvidence", None)
        disposition_type = getattr(scanner_module, "ScanDisposition", None)
        self.assertIsNotNone(identity_type)
        self.assertIsNotNone(candidate_type)
        self.assertIsNotNone(evidence_type)
        self.assertIsNotNone(disposition_type)
        existing = self.root / "existing.tar"
        self.store.observe(existing, 1, 1, self.t0)
        pending = self.root / "pending.tar"
        candidate = candidate_type(
            pending,
            "pending.tar",
            4,
            2,
            identity_type(1, 3, stat.S_IFREG, 4, 2),
            "8493100b11a2fe625bcf97fc313f83b83f8d3f3f2d7f832a020e39d878f561c0",
            False,
            False,
        )

        cancelled = evidence_type(
            200, self.t0, disposition_type.CANCELLED, (candidate,)
        )
        with self.assertRaises(ValueError):
            self.scanner.validate_scan(cancelled, Event())
        self.assertEqual(self.store.observed_paths(), {existing})
        self.assertIsNone(self.store.next_ready(self.t0))

        stale = evidence_type(201, self.t0, disposition_type.COMPLETE, (candidate,))
        with self.assertRaises(ValueError):
            self.scanner.validate_scan(stale, Event())
        self.assertEqual(self.store.observed_paths(), {existing})
        self.assertIsNone(self.store.next_ready(self.t0))

        failed = evidence_type(203, self.t0, disposition_type.FAILED, (candidate,))
        with self.assertRaises(ValueError):
            self.scanner.validate_scan(failed, Event())
        self.assertEqual(self.store.observed_paths(), {existing})
        self.assertIsNone(self.store.next_ready(self.t0))

    def test_cancelled_hash_generation_never_enqueues_partial_evidence(self) -> None:
        self.require_secure_directory_descriptors()
        self.write_backup("cancelled.tar", b"A" * (2 * 1024 * 1024))
        self.assertEqual(self.scanner.scan(self.t0), [])
        baseline = self.scanner.prepare_scan(10, self.t0 + timedelta(seconds=60))
        cancel = Event()
        real_read = os.read
        reads = 0

        def cancel_after_first_read(file_descriptor: int, size: int) -> bytes:
            nonlocal reads
            chunk = real_read(file_descriptor, size)
            reads += 1
            if chunk and reads == 1:
                cancel.set()
            return chunk

        with patch("proton_backup.scanner.os.read", side_effect=cancel_after_first_read):
            result = self.scanner.collect_scan(baseline, cancel)

        self.assertEqual(self.scanner.apply_scan(self.validate(result, cancel), 10), [])
        self.assertIsNone(self.store.next_ready(self.t0 + timedelta(seconds=60)))
        self.assertEqual(reads, 1)

    def test_partial_generation_never_enqueues_a_successful_earlier_candidate(self) -> None:
        self.require_secure_directory_descriptors()
        self.write_backup("first.tar", b"first")
        self.write_backup("second.tar", b"second")
        self.assertEqual(self.scanner.scan(self.t0), [])
        baseline = self.scanner.prepare_scan(20, self.t0 + timedelta(seconds=60))
        real_read = os.read
        reads = 0

        def fail_second_candidate(file_descriptor: int, size: int) -> bytes:
            nonlocal reads
            reads += 1
            if reads >= 3:
                raise OSError("forced second-candidate read failure")
            return real_read(file_descriptor, size)

        with patch("proton_backup.scanner.os.read", side_effect=fail_second_candidate):
            result = self.scanner.collect_scan(baseline, Event())

        self.assertEqual(self.scanner.apply_scan(self.validate(result), 20), [])
        self.assertIsNone(self.store.next_ready(self.t0 + timedelta(seconds=60)))

    def test_superseded_generation_is_discarded_before_state_changes(self) -> None:
        self.require_secure_directory_descriptors()
        self.write_backup("stale.tar", b"stale")
        self.assertEqual(self.scanner.scan(self.t0), [])
        baseline = self.scanner.prepare_scan(30, self.t0 + timedelta(seconds=60))
        result = self.scanner.collect_scan(baseline, Event())

        self.assertEqual(self.scanner.apply_scan(self.validate(result), 31), [])
        self.assertIsNone(self.store.next_ready(self.t0 + timedelta(seconds=60)))

    def test_replacement_between_collection_and_owner_apply_is_rejected(self) -> None:
        self.require_secure_directory_descriptors()
        path = self.write_backup("queue-hop.tar", b"first-content")
        self.assertEqual(self.scanner.scan(self.t0), [])
        baseline = self.scanner.prepare_scan(40, self.t0 + timedelta(seconds=60))
        evidence = self.scanner.collect_scan(baseline, Event())
        original = path.stat()
        replacement = self.root / "replacement.tmp"
        replacement.write_bytes(b"other-content")
        os.utime(replacement, ns=(original.st_atime_ns, original.st_mtime_ns))
        replacement.replace(path)

        ready = self.scanner.apply_scan(self.validate(evidence), 40)

        self.assertEqual(ready, [])
        self.assertIsNone(self.store.next_ready(self.t0 + timedelta(seconds=60)))

    def test_growing_file_needs_two_new_unchanged_observations(self) -> None:
        self.require_secure_directory_descriptors()
        path = self.write_backup("growing.tar", b"one")
        self.assertEqual(self.scanner.scan(self.t0), [])
        path.write_bytes(b"one-two")

        self.assertEqual(self.scanner.scan(self.t0 + timedelta(seconds=60)), [])
        ready = self.scanner.scan(self.t0 + timedelta(seconds=120))

        self.assertEqual([backup.display_name for backup in ready], ["growing.tar"])
        self.assertEqual(ready[0].size, 7)

    def test_ignores_non_tar_files_and_directories(self) -> None:
        self.require_secure_directory_descriptors()
        ignored = self.write_backup("notes.txt", b"not a backup")
        directory = self.root / "folder.tar"
        directory.mkdir()

        self.scanner.scan(self.t0)
        self.assertEqual(self.scanner.scan(self.t0 + timedelta(seconds=60)), [])

        self.assertNotIn(ignored, self.store.observed_paths())
        self.assertNotIn(directory, self.store.observed_paths())

    def test_rejects_symlink_even_when_target_is_inside_root(self) -> None:
        self.require_secure_directory_descriptors()
        target = self.write_backup("real.tar", b"data")
        link = self.root / "link.tar"
        self.symlink_or_skip(link, target)

        self.scanner.scan(self.t0)

        self.assertNotIn(link, self.store.observed_paths())

    def test_rejects_path_resolving_outside_root(self) -> None:
        self.require_secure_directory_descriptors()
        target = self.base / "outside.tar"
        target.write_bytes(b"outside")
        link = self.root / "escape.tar"
        self.symlink_or_skip(link, target)

        self.scanner.scan(self.t0)

        self.assertNotIn(link, self.store.observed_paths())
        self.assertNotIn(target, self.store.observed_paths())

    def test_does_not_follow_symlinked_directories(self) -> None:
        self.require_secure_directory_descriptors()
        outside_directory = self.base / "outside"
        outside_directory.mkdir()
        outside_backup = outside_directory / "hidden.tar"
        outside_backup.write_bytes(b"outside")
        link = self.root / "linked-directory"
        self.symlink_or_skip(link, outside_directory, target_is_directory=True)

        self.scanner.scan(self.t0)
        self.scanner.scan(self.t0 + timedelta(seconds=60))

        self.assertEqual(self.store.observed_paths(), set())
        self.assertIsNone(self.store.next_ready(self.t0 + timedelta(seconds=60)))

    def test_unreadable_file_is_not_enqueued(self) -> None:
        self.require_secure_directory_descriptors()
        path = self.write_backup("unreadable.tar", b"secret")
        self.scanner.scan(self.t0)
        real_open = os.open

        def denying_candidate_open(
            candidate: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            flags: int,
            *,
            dir_fd: int | None = None,
        ) -> int:
            if dir_fd is not None:
                raise PermissionError("denied")
            return real_open(candidate, flags)

        with patch("proton_backup.scanner.os.open", side_effect=denying_candidate_open):
            ready = self.scanner.scan(self.t0 + timedelta(seconds=60))

        self.assertEqual(ready, [])
        self.assertIsNone(self.store.next_ready(self.t0 + timedelta(seconds=60)))
        self.assertNotIn(path, self.store.observed_paths())

        self.assertEqual(self.scanner.scan(self.t0 + timedelta(seconds=120)), [])
        recovered = self.scanner.scan(self.t0 + timedelta(seconds=180))
        self.assertEqual([backup.display_name for backup in recovered], ["unreadable.tar"])

    def test_hashes_deterministically_in_one_mibibyte_reads(self) -> None:
        self.require_secure_directory_descriptors()
        payload = b"A" * (2 * 1024 * 1024) + b"1234567"
        self.write_backup("large.tar", payload)
        self.scanner.scan(self.t0)
        requested_sizes: list[int] = []
        real_read = os.read

        def recording_read(file_descriptor: int, size: int) -> bytes:
            requested_sizes.append(size)
            return real_read(file_descriptor, size)

        with patch("proton_backup.scanner.os.read", side_effect=recording_read):
            ready = self.scanner.scan(self.t0 + timedelta(seconds=60))

        self.assertEqual(len(ready), 1)
        self.assertEqual(
            ready[0].sha256,
            "e1c070f74ed0ce0ee8f7cf50171922a5510ac36fcd69ffb74da97ec0e0bc98ec",
        )
        self.assertGreaterEqual(len(requested_sizes), 4)
        self.assertEqual(set(requested_sizes), {1024 * 1024})

    def test_duplicate_content_keeps_first_filename_in_queue(self) -> None:
        self.require_secure_directory_descriptors()
        self.write_backup("first.tar", b"same")
        self.write_backup("second.tar", b"same")
        self.scanner.scan(self.t0)

        ready = self.scanner.scan(self.t0 + timedelta(seconds=60))

        self.assertEqual(
            [backup.display_name for backup in ready],
            ["first.tar", "second.tar"],
        )
        queued = self.store.next_ready(self.t0 + timedelta(seconds=60))
        self.assertIsNotNone(queued)
        self.assertEqual(queued.display_name, "first.tar")

    def test_rejects_same_metadata_when_path_identity_changes_before_open(self) -> None:
        self.require_secure_directory_descriptors()
        path = self.write_backup("raced.tar", b"same")
        self.scanner.scan(self.t0)
        original = path.stat()
        replacement = self.root / "replacement.tmp"
        replacement.write_bytes(b"same")
        os.utime(replacement, ns=(original.st_atime_ns, original.st_mtime_ns))
        real_open = os.open
        replaced = False

        def replacing_open(
            candidate: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            flags: int,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal replaced
            if dir_fd is not None and not replaced:
                replacement.replace(path)
                replaced = True
            return real_open(candidate, flags, dir_fd=dir_fd)

        with patch("proton_backup.scanner.os.open", side_effect=replacing_open):
            ready = self.scanner.scan(self.t0 + timedelta(seconds=60))

        self.assertEqual(ready, [])
        self.assertIsNone(self.store.next_ready(self.t0 + timedelta(seconds=60)))

    def test_rejects_file_that_changes_while_being_hashed(self) -> None:
        self.require_secure_directory_descriptors()
        path = self.write_backup("changing.tar", b"A" * (1024 * 1024 + 1))
        self.scanner.scan(self.t0)
        real_read = os.read
        changed = False

        def changing_read(file_descriptor: int, size: int) -> bytes:
            nonlocal changed
            chunk = real_read(file_descriptor, size)
            if chunk and not changed:
                with path.open("ab") as stream:
                    stream.write(b"changed")
                changed = True
            return chunk

        with patch("proton_backup.scanner.os.read", side_effect=changing_read):
            ready = self.scanner.scan(self.t0 + timedelta(seconds=60))

        self.assertEqual(ready, [])
        self.assertIsNone(self.store.next_ready(self.t0 + timedelta(seconds=60)))

    def test_missing_file_clears_stale_observation_before_recreation(self) -> None:
        self.require_secure_directory_descriptors()
        path = self.write_backup("recreated.tar", b"same")
        original = path.stat()
        self.assertEqual(self.scanner.scan(self.t0), [])
        path.unlink()

        self.assertEqual(self.scanner.scan(self.t0 + timedelta(seconds=60)), [])
        self.assertNotIn(path, self.store.observed_paths())
        path.write_bytes(b"same")
        os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns))

        self.assertEqual(self.scanner.scan(self.t0 + timedelta(seconds=120)), [])
        ready = self.scanner.scan(self.t0 + timedelta(seconds=180))
        self.assertEqual([backup.display_name for backup in ready], ["recreated.tar"])

    def test_invalid_candidate_clears_stale_observation(self) -> None:
        self.require_secure_directory_descriptors()
        path = self.write_backup("invalid.tar", b"same")
        self.assertEqual(self.scanner.scan(self.t0), [])
        path.unlink()
        path.mkdir()

        self.assertEqual(self.scanner.scan(self.t0 + timedelta(seconds=60)), [])
        self.assertNotIn(path, self.store.observed_paths())

    def test_root_scan_failure_clears_stale_observations(self) -> None:
        self.require_secure_directory_descriptors()
        path = self.write_backup("safe.tar", b"same")
        self.assertEqual(self.scanner.scan(self.t0), [])
        displaced = self.base / "backup-away"
        self.root.rename(displaced)

        self.assertEqual(self.scanner.scan(self.t0 + timedelta(seconds=60)), [])
        self.assertEqual(self.store.observed_paths(), set())
        displaced.rename(self.root)

        self.assertEqual(self.scanner.scan(self.t0 + timedelta(seconds=120)), [])
        ready = self.scanner.scan(self.t0 + timedelta(seconds=180))
        self.assertEqual([backup.display_name for backup in ready], ["safe.tar"])

    def test_unchanged_enqueued_file_is_not_rehashed_but_replacement_is(self) -> None:
        self.require_secure_directory_descriptors()
        path = self.write_backup("safe.tar", b"one")
        self.scanner.scan(self.t0)
        self.assertEqual(
            [backup.display_name for backup in self.scanner.scan(self.t0 + timedelta(seconds=60))],
            ["safe.tar"],
        )

        with patch("proton_backup.scanner.os.read", side_effect=AssertionError("unexpected rehash")):
            self.assertEqual(self.scanner.scan(self.t0 + timedelta(seconds=120)), [])

        original = path.stat()
        replacement = self.root / "replacement.tmp"
        replacement.write_bytes(b"two")
        os.utime(replacement, ns=(original.st_atime_ns, original.st_mtime_ns))
        replacement.replace(path)
        with patch("proton_backup.scanner.os.read", side_effect=AssertionError("premature hash")):
            self.assertEqual(self.scanner.scan(self.t0 + timedelta(seconds=180)), [])

        ready = self.scanner.scan(self.t0 + timedelta(seconds=240))
        self.assertEqual(len(ready), 1)
        self.assertEqual(
            ready[0].sha256,
            "3fc4ccfe745870e2c0d99f71f30ff0656c8dedd41cc1d7d3d376b0dbe685e2f3",
        )

    def test_ancestor_swap_after_root_open_fails_closed(self) -> None:
        self.require_secure_directory_descriptors()
        parent = self.base / "mount"
        parent.mkdir()
        root = parent / "backup"
        root.mkdir()
        (root / "safe.tar").write_bytes(b"inside")
        scanner = BackupScanner(root, self.store)
        self.assertEqual(scanner.scan(self.t0), [])
        outside_parent = self.base / "outside-mount"
        outside_root = outside_parent / "backup"
        outside_root.mkdir(parents=True)
        (outside_root / "safe.tar").write_bytes(b"outside")
        displaced = self.base / "mount-original"
        real_listdir = os.listdir
        swapped = False

        def swapping_listdir(directory_descriptor: int) -> list[str]:
            nonlocal swapped
            names = real_listdir(directory_descriptor)
            if not swapped:
                parent.rename(displaced)
                self.symlink_or_skip(parent, outside_parent, target_is_directory=True)
                swapped = True
            return names

        try:
            with patch("proton_backup.scanner.os.listdir", side_effect=swapping_listdir):
                self.assertEqual(scanner.scan(self.t0 + timedelta(seconds=60)), [])
            self.assertIsNone(self.store.next_ready(self.t0 + timedelta(seconds=60)))
            self.assertEqual(self.store.observed_paths(), set())
        finally:
            if parent.is_symlink():
                parent.unlink()
            if displaced.exists():
                displaced.rename(parent)

    def test_close_error_rejects_only_candidate_and_resets_stability(self) -> None:
        self.require_secure_directory_descriptors()
        self.write_backup("close-error.tar", b"data")
        self.scanner.scan(self.t0)
        real_close = os.close
        failed = False

        def failing_close(file_descriptor: int) -> None:
            nonlocal failed
            mode = os.fstat(file_descriptor).st_mode
            real_close(file_descriptor)
            if stat.S_ISREG(mode) and not failed:
                failed = True
                raise OSError("forced close failure")

        with patch("proton_backup.scanner.os.close", side_effect=failing_close):
            self.assertEqual(self.scanner.scan(self.t0 + timedelta(seconds=60)), [])
        self.assertEqual(self.store.observed_paths(), set())

        self.assertEqual(self.scanner.scan(self.t0 + timedelta(seconds=120)), [])
        ready = self.scanner.scan(self.t0 + timedelta(seconds=180))
        self.assertEqual([backup.display_name for backup in ready], ["close-error.tar"])

    @unittest.skipIf(SECURE_DIR_FD_AVAILABLE, "platform provides secure directory descriptors")
    def test_platform_without_secure_directory_descriptors_fails_closed(self) -> None:
        path = self.write_backup("unsafe-platform.tar", b"data")

        self.assertEqual(self.scanner.scan(self.t0), [])
        self.assertEqual(self.scanner.scan(self.t0 + timedelta(seconds=60)), [])
        self.assertNotIn(path, self.store.observed_paths())
        self.assertIsNone(self.store.next_ready(self.t0 + timedelta(seconds=60)))


if __name__ == "__main__":
    unittest.main()
