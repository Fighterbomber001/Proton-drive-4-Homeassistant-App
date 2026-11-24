from __future__ import annotations

import sys
import unittest
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

APP_ROOT = Path(__file__).resolve().parents[1] / "proton_drive_backup" / "rootfs" / "app"
sys.path.insert(0, str(APP_ROOT))

from proton_backup.models import RemoteFile
from proton_backup.proton_cli import FinalListing, RemoteLayout
from proton_backup.retention import RetentionManager


INSTALLATION_ID = "0123456789abcdef0123456789abcdef"
OTHER_INSTALLATION_ID = "fedcba9876543210fedcba9876543210"
ROOT = f"/my-files/HomeAssistant-Backups/{INSTALLATION_ID}"
LAYOUT = RemoteLayout(ROOT, f"{ROOT}/incoming", f"{ROOT}/backups")


def remote_file(
    index: int,
    *,
    installation_id: str = INSTALLATION_ID,
    timestamp: str | None = None,
    base: str | None = None,
    size: int | None = None,
    path: str | None = None,
    uid: str | None = None,
) -> RemoteFile:
    timestamp = timestamp or f"202608{index + 1:02d}T120000Z"
    base = base or f"backup-{index:02d}"
    name = (
        f"ha-v1--{installation_id}--{timestamp}--{base}--"
        f"{index:012x}.tar"
    )
    final = f"/my-files/HomeAssistant-Backups/{installation_id}/backups"
    return RemoteFile(
        uid or f"remote-{index:02d}",
        name,
        path or f"{final}/{name}",
        index + 100 if size is None else size,
        datetime(2026, 8, min(index + 1, 28), 12, tzinfo=UTC),
    )


class FakeState:
    def __init__(self, confirmed: dict[str, RemoteFile], *, fails: bool = False) -> None:
        self.confirmed = confirmed
        self.fails = fails

    def confirmed_remote_files(self) -> dict[str, RemoteFile]:
        if self.fails:
            raise RuntimeError("database details must not escape")
        return dict(self.confirmed)


class FakeClient:
    def __init__(
        self,
        listing: list[object],
        *,
        listing_fails: bool = False,
        listing_result: object | None = None,
        delete_failure_uid: str | None = None,
        remove_deleted: bool = False,
    ) -> None:
        self.listing = list(listing)
        self.listing_fails = listing_fails
        self.listing_result = listing_result
        self.delete_failure_uid = delete_failure_uid
        self.remove_deleted = remove_deleted
        self.delete_attempts: list[RemoteFile] = []
        self.deleted: list[RemoteFile] = []

    def list_final(self, layout: RemoteLayout) -> object:
        if self.listing_fails:
            raise RuntimeError("incomplete remote listing")
        if self.listing_result is not None:
            return self.listing_result
        return FinalListing(tuple(self.listing), complete=True)  # type: ignore[arg-type]

    def permanently_delete_owned(self, remote: RemoteFile, layout: RemoteLayout) -> None:
        self.delete_attempts.append(remote)
        if remote.uid == self.delete_failure_uid:
            raise RuntimeError("remote details must not escape")
        self.deleted.append(remote)
        if self.remove_deleted:
            self.listing.remove(remote)


def confirmed(files: list[RemoteFile]) -> dict[str, RemoteFile]:
    return {remote.uid: remote for remote in files}


class RetentionManagerTests(unittest.TestCase):
    def manager(
        self,
        files: list[object],
        *,
        confirmed_files: dict[str, RemoteFile] | None = None,
        **client_options,
    ) -> tuple[RetentionManager, FakeClient]:
        client = FakeClient(files, **client_options)
        owned = [item for item in files if isinstance(item, RemoteFile)]
        state = FakeState(confirmed(owned) if confirmed_files is None else confirmed_files)
        return RetentionManager(client, state), client

    def test_deletes_only_oldest_confirmed_owned_file_over_fourteen(self) -> None:
        files = [remote_file(index) for index in range(15)]
        manager, client = self.manager(files)

        result = manager.reconcile_after_success(LAYOUT, INSTALLATION_ID)

        self.assertEqual(result.deleted, [files[0]])
        self.assertIsNone(result.error_code)
        self.assertEqual(client.deleted, [files[0]])

    def test_empty_and_exactly_fourteen_owned_files_delete_nothing(self) -> None:
        for count in (0, 14):
            with self.subTest(count=count):
                files = [remote_file(index) for index in range(count)]
                manager, client = self.manager(files)
                result = manager.reconcile_after_success(LAYOUT, INSTALLATION_ID)
                self.assertEqual(result.deleted, [])
                self.assertIsNone(result.error_code)
                self.assertEqual(client.delete_attempts, [])

    def test_incomplete_remote_listing_deletes_nothing(self) -> None:
        files = [remote_file(index) for index in range(15)]
        manager, client = self.manager(files, listing_fails=True)

        result = manager.reconcile_after_success(LAYOUT, INSTALLATION_ID)

        self.assertEqual(result.deleted, [])
        self.assertEqual(result.error_code, "remote_listing_failed")
        self.assertEqual(client.delete_attempts, [])

    def test_successful_partial_listing_with_omitted_oldest_never_deletes(self) -> None:
        all_files = [remote_file(index) for index in range(16)]
        partial = all_files[1:]
        listing_result = FinalListing(tuple(partial), complete=False)
        manager, client = self.manager(
            partial,
            confirmed_files=confirmed(all_files),
            listing_result=listing_result,
        )

        result = manager.reconcile_after_success(LAYOUT, INSTALLATION_ID)

        self.assertEqual(result.deleted, [])
        self.assertEqual(result.error_code, "remote_listing_incomplete")
        self.assertEqual(client.delete_attempts, [])

    def test_absent_or_unknown_listing_completeness_fails_closed(self) -> None:
        files = [remote_file(index) for index in range(15)]
        cases = (
            list(files),
            SimpleNamespace(files=tuple(files)),
            SimpleNamespace(files=tuple(files), complete=None),
            SimpleNamespace(files=tuple(files), complete="true"),
        )
        for listing_result in cases:
            with self.subTest(listing_result=listing_result):
                manager, client = self.manager(
                    files, listing_result=listing_result
                )

                result = manager.reconcile_after_success(
                    LAYOUT, INSTALLATION_ID
                )

                self.assertEqual(result.deleted, [])
                self.assertEqual(result.error_code, "remote_listing_incomplete")
                self.assertEqual(client.delete_attempts, [])

    def test_positive_complete_listing_retains_fourteen_for_fifteen_and_seventeen(self) -> None:
        for count, deleted_count in ((15, 1), (17, 3)):
            with self.subTest(count=count):
                files = [remote_file(index) for index in range(count)]
                manager, client = self.manager(
                    files,
                    listing_result=FinalListing(
                        files=tuple(files), complete=True
                    ),
                )

                result = manager.reconcile_after_success(
                    LAYOUT, INSTALLATION_ID
                )

                self.assertEqual(result.deleted, files[:deleted_count])
                self.assertIsNone(result.error_code)
                self.assertEqual(client.deleted, files[:deleted_count])

    def test_unconfirmed_or_foreign_records_never_count_toward_retention(self) -> None:
        owned = [remote_file(index) for index in range(14)]
        another_installation = remote_file(20, installation_id=OTHER_INSTALLATION_ID)
        another_installation = RemoteFile(
            another_installation.uid,
            another_installation.name,
            f"{LAYOUT.final}/{another_installation.name}",
            another_installation.size,
            another_installation.modified_at,
        )
        wrong_prefix = remote_file(21)
        wrong_prefix = RemoteFile(
            wrong_prefix.uid,
            "foreign.tar",
            f"{LAYOUT.final}/foreign.tar",
            wrong_prefix.size,
            wrong_prefix.modified_at,
        )
        wrong_size = remote_file(22)
        wrong_size_confirmation = RemoteFile(
            wrong_size.uid,
            wrong_size.name,
            wrong_size.path,
            wrong_size.size + 1,
            wrong_size.modified_at,
        )
        unconfirmed = remote_file(23)
        incoming = remote_file(24, path=f"{LAYOUT.incoming}/{remote_file(24).name}")
        trash = remote_file(25, path=f"/trash/trash-id/{remote_file(25).name}")
        folder_record = SimpleNamespace(
            uid="folder-1",
            name=remote_file(26).name,
            path=f"{LAYOUT.final}/{remote_file(26).name}",
            size=126,
            modified_at=datetime(2026, 8, 26, 12, tzinfo=UTC),
            kind="folder",
        )
        listing: list[object] = [
            *owned,
            another_installation,
            wrong_prefix,
            wrong_size,
            unconfirmed,
            incoming,
            trash,
            folder_record,
        ]
        state_files = confirmed(owned)
        state_files.update(
            confirmed([another_installation, wrong_prefix, incoming, trash])
        )
        state_files[wrong_size.uid] = wrong_size_confirmation
        manager, client = self.manager(listing, confirmed_files=state_files)

        result = manager.reconcile_after_success(LAYOUT, INSTALLATION_ID)

        self.assertEqual(result.deleted, [])
        self.assertIsNone(result.error_code)
        self.assertEqual(client.delete_attempts, [])

    def test_duplicate_owned_name_fails_closed_before_deletion(self) -> None:
        files = [remote_file(index) for index in range(15)]
        duplicate = RemoteFile(
            "remote-duplicate",
            files[0].name,
            files[0].path,
            files[0].size,
            files[0].modified_at,
        )
        listing = [*files, duplicate]
        manager, client = self.manager(listing)

        result = manager.reconcile_after_success(LAYOUT, INSTALLATION_ID)

        self.assertEqual(result.deleted, [])
        self.assertEqual(result.error_code, "ambiguous_remote_listing")
        self.assertEqual(client.delete_attempts, [])

    def test_equal_timestamps_have_deterministic_name_and_uid_tie_breaks(self) -> None:
        files = [
            remote_file(
                index,
                timestamp="20260810T120000Z",
                base=f"same-time-{chr(ord('a') + index)}",
            )
            for index in range(15)
        ]
        manager, client = self.manager(list(reversed(files)))

        result = manager.reconcile_after_success(LAYOUT, INSTALLATION_ID)

        self.assertEqual(result.deleted, [files[0]])
        self.assertEqual(client.deleted, [files[0]])

    def test_invalid_or_ambiguous_name_timestamp_is_not_owned(self) -> None:
        files = [remote_file(index) for index in range(14)]
        malformed = remote_file(20, timestamp="20260230T120000Z")
        manager, client = self.manager([*files, malformed])

        result = manager.reconcile_after_success(LAYOUT, INSTALLATION_ID)

        self.assertEqual(result.deleted, [])
        self.assertIsNone(result.error_code)
        self.assertEqual(client.delete_attempts, [])

    def test_malformed_remote_metadata_is_not_owned_even_when_state_matches(self) -> None:
        files = [remote_file(index) for index in range(14)]
        candidate = remote_file(20)
        malformed = RemoteFile(
            candidate.uid,
            candidate.name,
            candidate.path,
            candidate.size,
            "2026-08-21T12:00:00Z",  # type: ignore[arg-type]
        )
        manager, client = self.manager([*files, malformed])

        result = manager.reconcile_after_success(LAYOUT, INSTALLATION_ID)

        self.assertEqual(result.deleted, [])
        self.assertEqual(result.error_code, "ambiguous_remote_metadata")
        self.assertEqual(client.delete_attempts, [])

    def test_fifteen_files_with_unprovable_utc_metadata_abort_before_deletion(self) -> None:
        cases = (
            ("remote-none", None, datetime(2026, 8, 8, 12, tzinfo=UTC)),
            (
                "remote-malformed",
                "2026-08-08T12:00:00Z",
                "2026-08-08T12:00:00Z",
            ),
            ("state-none", datetime(2026, 8, 8, 12, tzinfo=UTC), None),
            (
                "state-malformed",
                datetime(2026, 8, 8, 12, tzinfo=UTC),
                "2026-08-08T12:00:00Z",
            ),
            (
                "state-mismatch",
                datetime(2026, 8, 8, 12, tzinfo=UTC),
                datetime(2026, 8, 8, 12, 0, 1, tzinfo=UTC),
            ),
        )
        for label, remote_modified, state_modified in cases:
            with self.subTest(label=label):
                files = [remote_file(index) for index in range(15)]
                candidate = files[7]
                listed = RemoteFile(
                    candidate.uid,
                    candidate.name,
                    candidate.path,
                    candidate.size,
                    remote_modified,  # type: ignore[arg-type]
                )
                files[7] = listed
                state_files = confirmed(files)
                state_files[listed.uid] = RemoteFile(
                    listed.uid,
                    listed.name,
                    listed.path,
                    listed.size,
                    state_modified,  # type: ignore[arg-type]
                )
                manager, client = self.manager(files, confirmed_files=state_files)

                result = manager.reconcile_after_success(LAYOUT, INSTALLATION_ID)

                self.assertEqual(result.deleted, [])
                self.assertEqual(result.error_code, "ambiguous_remote_metadata")
                self.assertEqual(client.delete_attempts, [])

    def test_retention_does_not_run_before_fifteenth_upload_confirmation(self) -> None:
        files = [remote_file(index) for index in range(15)]
        manager, client = self.manager(files, confirmed_files=confirmed(files[:14]))

        result = manager.reconcile_after_success(LAYOUT, INSTALLATION_ID)

        self.assertEqual(result.deleted, [])
        self.assertEqual(client.delete_attempts, [])

    def test_partial_delete_failure_stops_and_reports_only_completed_deletions(self) -> None:
        files = [remote_file(index) for index in range(17)]
        manager, client = self.manager(files, delete_failure_uid=files[1].uid)

        result = manager.reconcile_after_success(LAYOUT, INSTALLATION_ID)

        self.assertEqual(result.deleted, [files[0]])
        self.assertEqual(result.error_code, "remote_delete_failed")
        self.assertEqual(client.delete_attempts, files[:2])
        self.assertEqual(client.deleted, [files[0]])

    def test_successfully_deletes_every_excess_file_and_leaves_fourteen(self) -> None:
        files = [remote_file(index) for index in range(17)]
        manager, client = self.manager(files)

        result = manager.reconcile_after_success(LAYOUT, INSTALLATION_ID)

        self.assertEqual(result.deleted, files[:3])
        self.assertIsNone(result.error_code)
        self.assertEqual(client.deleted, files[:3])
        self.assertEqual(len(files) - len(result.deleted), 14)

    def test_repeated_reconciliation_is_idempotent_after_success(self) -> None:
        files = [remote_file(index) for index in range(15)]
        manager, client = self.manager(files, remove_deleted=True)

        first = manager.reconcile_after_success(LAYOUT, INSTALLATION_ID)
        second = manager.reconcile_after_success(LAYOUT, INSTALLATION_ID)

        self.assertEqual(first.deleted, [files[0]])
        self.assertEqual(second.deleted, [])
        self.assertEqual(client.delete_attempts, [files[0]])

    def test_invalid_layout_identity_or_state_failure_deletes_nothing(self) -> None:
        files = [remote_file(index) for index in range(15)]
        client = FakeClient(files)
        invalid_layout = RemoteLayout(LAYOUT.root, LAYOUT.incoming, "/foreign/backups")
        invalid_result = RetentionManager(client, FakeState(confirmed(files))).reconcile_after_success(
            invalid_layout, INSTALLATION_ID
        )
        state_result = RetentionManager(client, FakeState({}, fails=True)).reconcile_after_success(
            LAYOUT, INSTALLATION_ID
        )

        self.assertEqual(invalid_result.error_code, "invalid_retention_scope")
        self.assertEqual(state_result.error_code, "state_read_failed")
        self.assertEqual(client.delete_attempts, [])


if __name__ == "__main__":
    unittest.main()
