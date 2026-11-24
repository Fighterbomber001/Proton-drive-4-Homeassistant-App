"""Contracts reconstructed from the checksum-verified 0.7.0 binary.

These are SDK node objects, transfer summaries and per-UID operation results,
not the normalized six-field objects used by older adapter fixtures.
"""
import json
import tests  # Activate the app path for bare unittest discovery too.
import unittest
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from threading import Event

from proton_backup.models import CommandResult, StableBackup
from proton_backup.proton_cli import ProtonCliError, ProtonDriveClient, RemoteLayout


INSTALL = "0123456789abcdef0123456789abcdef"
ROOT = f"/my-files/HomeAssistant-Backups/{INSTALL}"
LAYOUT = RemoteLayout(ROOT, ROOT + "/incoming", ROOT + "/backups")


def sdk_node(name, *, uid="volume~file", kind="file", size=4096):
    result = {
        "uid": uid, "parentUid": "volume~parent", "type": kind,
        "name": {"ok": True, "value": name},
        "creationTime": "2026-08-10T12:34:56.000Z",
        "modificationTime": "2026-08-10T12:34:56.000Z",
        "isShared": False, "isSharedByUrl": False,
        "nameAuthor": {"ok": True, "value": None},
        "keyAuthor": {"ok": True, "value": None},
    }
    if kind == "file":
        result["activeRevision"] = {"uid": uid + "~revision", "claimedSize": size}
    else:
        result["folder"] = {"isImported": False}
    return result


class Cli070ContractTests(unittest.TestCase):
    def test_actual_sdk_nodes_and_operation_arrays_finish_upload_and_delete(self):
        calls = []
        current = ["test.tar"]
        class Runner:
            def run(self, args, **kwargs):
                calls.append(tuple(args))
                op = args[2]
                if op == "create-folder":
                    value = sdk_node(args[4], uid="volume~folder", kind="folder")
                elif op == "upload":
                    value = {"transferredItems": 1, "transferredBytes": 4096,
                             "skippedItems": 0, "failedItems": 0, "failures": []}
                elif op == "info":
                    value = sdk_node(current[0])
                elif op == "rename":
                    current[0] = args[4]
                    value = sdk_node(current[0])
                elif op in {"move", "trash", "delete"}:
                    value = [{"uid": "volume~file", "ok": True}]
                elif op == "list":
                    value = [sdk_node(current[0])]
                else:
                    raise AssertionError(op)
                return CommandResult(tuple(args), 0, json.dumps(value), "")
        client = ProtonDriveClient(runner=Runner(), executable="proton-drive")
        backup = StableBackup(Path("/backup/test.tar"), "test.tar", 4096,
                              1786365296000000000, "a" * 64)
        remote = client.upload_and_finalize(backup, LAYOUT, Event())
        self.assertEqual(remote.uid, "volume~file")
        self.assertEqual(remote.modified_at, datetime(2026, 8, 10, 12, 34, 56, tzinfo=UTC))
        self.assertEqual(client.list_final(LAYOUT).files, (remote,))
        with self.assertRaisesRegex(ProtonCliError, "not supported"):
            client.permanently_delete_owned(remote, LAYOUT)
        self.assertFalse(any(call[2] in {"trash", "delete"} for call in calls))

    def test_actual_list_rejects_undecryptable_or_duplicate_nodes(self):
        valid = sdk_node("test.tar")
        bad = dict(valid, name={"ok": False, "error": {"name": "private"}})
        for value in ([bad], [valid, valid]):
            with self.subTest(value=value):
                with self.assertRaises(ProtonCliError):
                    ProtonDriveClient._parse_list(json.dumps(value), LAYOUT.final)

    def test_real_uid_and_millisecond_timestamp_are_accepted(self):
        nodes = ProtonDriveClient._parse_list(json.dumps([sdk_node("test.tar")]), LAYOUT.final)
        self.assertEqual(nodes[0].uid, "volume~file")
        self.assertEqual(nodes[0].path, LAYOUT.final + "/test.tar")

    def test_unsigned_metadata_and_false_operation_ack_are_rejected(self):
        from proton_backup.proton_cli import _operation_uid
        for value in ([{"uid": "volume~file", "ok": False}],
                      [{"uid": "volume~file", "ok": 1}],
                      [{"uid": "volume~file", "ok": True}, {"uid": "volume~other", "ok": True}]):
            with self.subTest(value=value), self.assertRaises(ProtonCliError):
                _operation_uid(value)
        node = sdk_node("test.tar")
        node["nameAuthor"] = {"ok": False, "error": {"claimedAuthor": "private"}}
        with self.assertRaises(ProtonCliError):
            ProtonDriveClient._parse_list(json.dumps([node]), LAYOUT.final)

    def test_legacy_sdk_uid_with_base64_padding_is_valid(self):
        uid = "a" * 87 + "=~" + "b" * 87 + "="
        nodes = ProtonDriveClient._parse_list(json.dumps([sdk_node("test.tar", uid=uid)]), LAYOUT.final)
        self.assertEqual(nodes[0].uid, uid)

    def test_real_subprocess_listing_above_16k_is_still_valid_json(self):
        import sys
        from proton_backup.process import ProcessRunner
        sample = sdk_node("test.tar")
        sample["padding"] = "x" * 1024
        program = ("import json; n=" + repr(sample)
                   + "; print(json.dumps([dict(n, uid='v~file'+str(i), name={'ok':True,'value':'file'+str(i)+'.tar'}) for i in range(30)]))")
        result = ProcessRunner().run([sys.executable, "-c", program], timeout=10, cancel=Event())
        self.assertEqual(result.returncode, 0)
        self.assertGreater(len(result.stdout), 16384)
        self.assertEqual(len(ProtonDriveClient._parse_list(result.stdout, LAYOUT.final)), 30)
