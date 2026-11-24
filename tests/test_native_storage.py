"""Native remote storage contracts, with the process boundary replaced by a memory drive."""
import json
import tempfile
import unittest
import uuid
from pathlib import Path, PurePosixPath
from threading import Event

import tests
from tests.test_cli070_contract import sdk_node
from proton_backup.models import CommandResult
from proton_backup.proton_cli import ProtonAuthenticationRequired, ProtonDriveClient

from proton_backup import native_storage as native


INSTALL = "a" * 32
ID = "test-0_1"
DATA = b"example archive contents"
META = {
    "addons": [{"name": None, "slug": "example", "version": "1.0"}], "backup_id": ID,
    "date": "2026-11-22T12:00:00+00:00", "database_included": True,
    "extra_metadata": {"key": "value"}, "folders": ["addons/local", "ssl"],
    "homeassistant_included": True, "homeassistant_version": "2026.11.2",
    "name": "My backup", "protected": False, "size": len(DATA),
}


class MemoryDrive:
    def __init__(self):
        self.entries = {}
        self.calls = []
        self.download_mode = None
        self.stop_after_archive = False
        self.stop_after_list = False
        self.authentication_required = False

    def put(self, key, data):
        assert key not in self.entries
        node = sdk_node(PurePosixPath(key).name, uid=uuid.uuid4().hex,
                        kind="folder" if data is None else "file", size=len(data or b""))
        self.entries[key] = (node, data)
        return node

    def run(self, args, *, cancel, **kwargs):
        assert args[1] == "filesystem" and args[-1] == "--json", args
        op, src = args[2:4]
        self.calls.append((op, src))
        if self.authentication_required:
            raise ProtonAuthenticationRequired("session unavailable")
        if op == "list":
            assert src == "/my-files" or self.entries[src][0]["type"] == "folder"
            result = [node for key, (node, _) in self.entries.items() if str(PurePosixPath(key).parent) == src]
            if self.stop_after_list:
                cancel.set()
        elif op == "create-folder":
            result = self.put(src + "/" + args[4], None)
        elif op == "info":
            result = self.entries[src][0]
        elif op in ("upload", "download"):
            assert args[args.index("--conflict-strategy") + 1] == "skip"
            if op == "upload":
                path = Path(src)
                data = path.read_bytes()
                self.put(args[4] + "/" + path.name, data)
                if self.stop_after_archive and "/archives/" in args[4]:
                    cancel.set()
            else:
                data = self.entries[src][1]
                path = Path(args[4]) / PurePosixPath(src).name
                assert path.parent.is_dir() and not path.exists()
                if self.download_mode != "no_file":
                    path.write_bytes(data)
            result = {"transferredItems": 1, "transferredBytes": len(data),
                      "skippedItems": 0, "failedItems": 0, "failures": []}
            if op == "download" and self.download_mode == "skipped":
                result["skippedItems"] = 1
        else:
            raise AssertionError(f"Unexpected command {op}")
        return CommandResult(tuple(args), 0, json.dumps(result), "")


class NativeStorageTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        (self.root / "native").mkdir()
        self.path = self.root / "native" / "incoming.tmp"
        self.path.write_bytes(DATA)
        self.fs = MemoryDrive()
        self.client = ProtonDriveClient(runner=self.fs)
        self.store = native.NativeStorage(self.client, INSTALL, self.root)
        self.cancel = Event()

    def upload(self):
        return self.store.upload_backup(ID, META, self.path, self.cancel)

    def archive(self):
        return next(key for key, (_, data) in self.fs.entries.items() if "/archives/" in key and data is not None)

    def test_new_installation_can_discover_and_restore_exact_bytes(self):
        self.assertEqual(self.store.list_backups(self.cancel), [])
        self.assertEqual(self.upload(), META)
        other = native.NativeStorage(self.client, "b"*32, self.root / "other")
        self.assertEqual(other.list_backups(self.cancel), [META])
        self.assertEqual(other.get_backup(ID, self.cancel), META)
        download = other.download_backup(ID, self.cancel)
        self.assertEqual(download.size, len(DATA))
        self.assertEqual(download.path.parent, self.root / "other" / "native")
        self.assertEqual(download.path.read_bytes(), DATA)

    def test_retry_identical_is_idempotent_different_digest_never_overwrites(self):
        self.upload()
        snapshot = dict(self.fs.entries)
        self.assertEqual(self.upload(), META)
        self.path.write_bytes(b"x"*len(DATA))
        with self.assertRaises(native.NativeStorageError):
            self.upload()
        self.assertEqual(self.fs.entries, snapshot)

    def test_duplicate_id_with_changed_metadata_never_changes_manifest(self):
        self.upload()
        snapshot = dict(self.fs.entries)
        with self.assertRaises(native.NativeStorageError):
            self.store.upload_backup(ID, dict(META, name="different"), self.path, self.cancel)
        self.assertEqual(self.fs.entries, snapshot)

    def test_cancel_during_empty_inventory_is_not_success(self):
        self.fs.stop_after_list = True
        with self.assertRaises(native.NativeStorageError):
            self.store.list_backups(self.cancel)

    def test_authentication_failure_is_not_empty_inventory(self):
        self.fs.authentication_required = True
        with self.assertRaises(native.NativeAuthenticationRequired) as failure:
            self.store.list_backups(self.cancel)
        self.assertEqual(failure.exception.code, "authentication_required")

    def test_cancelled_orphan_never_becomes_an_adopted_backup(self):
        self.fs.stop_after_archive = True
        with self.assertRaises(native.NativeStorageError):
            self.upload()
        self.cancel.clear()
        orphan = self.archive()
        self.assertEqual(self.store.list_backups(self.cancel), [])
        self.fs.stop_after_archive = False
        self.upload()
        self.assertEqual(len([k for k, (_, data) in self.fs.entries.items() if "/archives/" in k and data is not None]), 2)
        self.assertIn(orphan, self.fs.entries)

    def test_same_size_corrupt_download_never_returns_a_file(self):
        self.upload()
        arc = self.archive()
        self.fs.entries[arc] = (self.fs.entries[arc][0], b"x"*len(DATA))
        with self.assertRaises(native.NativeStorageError):
            self.store.download_backup(ID, self.cancel)
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])

    def test_retry_does_not_confirm_an_existing_archive_with_changed_bytes(self):
        self.upload()
        arc = self.archive()
        self.fs.entries[arc] = (self.fs.entries[arc][0], b"x"*len(DATA))
        snapshot = dict(self.fs.entries)
        with self.assertRaises(native.NativeStorageError):
            self.upload()
        self.assertEqual(self.fs.entries, snapshot)
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])

    def test_archive_uid_replacement_is_not_a_backup(self):
        self.upload()
        self.fs.entries[self.archive()][0]["uid"] = "substitute"
        with self.assertRaises(native.NativeStorageError):
            self.store.get_backup(ID, self.cancel)

    def test_failed_manifest_download_does_not_claim_inventory(self):
        self.upload()
        for self.fs.download_mode in ("no_file", "skipped"):
            with self.subTest(mode=self.fs.download_mode), self.assertRaises(native.NativeStorageError):
                self.store.list_backups(self.cancel)
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])

    def test_oversized_remote_manifest_never_downloads(self):
        self.upload()
        manifest = next(k for k in self.fs.entries if k.endswith(".json"))
        self.fs.entries[manifest][0]["activeRevision"]["claimedSize"] = 999999
        self.fs.calls.clear()
        with self.assertRaises(native.NativeStorageError):
            self.store.list_backups(self.cancel)
        self.assertFalse(any(op == "download" for op, _ in self.fs.calls))

    def test_manifest_cannot_direct_a_lookup_to_another_file_or_local_device(self):
        self.upload()
        manifest = next(k for k in self.fs.entries if k.endswith(".json"))
        node, original = self.fs.entries[manifest]
        for name in ("../../outside.tar", "NUL.tar", "COM1"):
            with self.subTest(name=name):
                doc = json.loads(original)
                doc["archive"]["name"] = name
                data = json.dumps(doc).encode()
                node["activeRevision"]["claimedSize"] = len(data)
                self.fs.entries[manifest] = (node, data)
                self.fs.calls.clear()
                with self.assertRaises(native.NativeStorageError):
                    self.store.get_backup(ID, self.cancel)
                self.assertFalse(any(op == "info" and "/archives/" in key for op, key in self.fs.calls))

    def test_invalid_input_rejected_before_remote_access(self):
        outside = self.root / "outside"
        outside.write_bytes(DATA)
        for id_, meta, path in [
            ("../id", META, self.path), ("x", META, self.path),
            (ID, dict(META, size=True), self.path), (ID, dict(META, date="wrong"), self.path),
            (ID, dict(META, name="x"*24576), self.path), (ID, dict(META, folders=["../media"]), self.path),
            (ID, dict(META, addons=[{"slug": "a"}]), self.path), (ID, dict(META, size=10), self.path),
            (ID, META, outside),
        ]:
            with self.subTest(id_=id_, path=path), self.assertRaises(native.NativeStorageError):
                self.store.upload_backup(id_, meta, path, self.cancel)
        self.assertEqual(self.fs.calls, [])

    def test_delete_always_refuses_and_unknown_get_is_not_found(self):
        with self.assertRaises(native.NativeDeleteUnsupported):
            self.store.delete_backup(ID, self.cancel)
        self.assertFalse(self.fs.calls)
        with self.assertRaises(native.NativeBackupNotFound):
            self.store.get_backup(ID, self.cancel)
