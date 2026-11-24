from __future__ import annotations

import io
import json
import logging
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
import sys
from threading import Event, Thread
from unittest.mock import patch
from urllib.parse import urlsplit

APP_ROOT = Path(__file__).resolve().parents[1] / "proton_drive_backup" / "rootfs" / "app"
sys.path.insert(0, str(APP_ROOT))

from proton_backup.models import CommandResult, RemoteFile, StableBackup
from proton_backup.process import ProcessExecutionError
from proton_backup.redaction import SafeLogger


FIXTURE_ROOT = Path(__file__).parent / "fixtures"
INSTALLATION_ID = "0123456789abcdef0123456789abcdef"
TRANSFER_ID = "11111111111111111111111111111111"
ROOT = f"/my-files/HomeAssistant-Backups/{INSTALLATION_ID}"
INCOMING = f"{ROOT}/incoming"
FINAL = f"{ROOT}/backups"
FINAL_NAME = (
    "ha-v1--0123456789abcdef0123456789abcdef--20260810T123456Z--"
    "nightly-home--aaaaaaaaaaaa.tar"
)


def fixture(name: str) -> str:
    return (FIXTURE_ROOT / name).read_text(encoding="utf-8")


def node(*, uid: str, name: str, path: str, kind: str = "folder", size: int = 0):
    return json.dumps(
        {
            "uid": uid,
            "name": name,
            "path": path,
            "type": kind,
            "size": size,
            "modified_at": "2026-08-10T12:34:56Z",
        }
    )


class FakeCliRunner:
    def __init__(self, handler=None, *, login_lines=(), before_login=None):
        self.handler = handler or (lambda args: CommandResult(tuple(args), 0, "[]", ""))
        self.login_lines = tuple(login_lines)
        self.before_login = before_login
        self.calls: list[tuple[str, ...]] = []
        self.timeouts: list[int] = []

    def run(
        self,
        args,
        *,
        timeout,
        cancel,
        on_stdout_line=None,
        secret_event=None,
    ):
        call = tuple(args)
        self.calls.append(call)
        self.timeouts.append(timeout)
        if call[1:] == ("auth", "login"):
            if cancel.is_set():
                return CommandResult(call, -1, "", "", cancelled=True)
            if self.before_login is not None:
                self.before_login()
            try:
                for line in self.login_lines:
                    secret_event.inspect(line)
                secret_event.finish()
            except Exception:
                raise ProcessExecutionError("Unable to process secret event") from None
            return CommandResult(call, 0, "[REDACTED]", "")
        return self.handler(call)


class FakeCredentialStore:
    def __init__(self, *, fail=False):
        self.removed = 0
        self.fail = fail

    def remove(self):
        self.removed += 1
        if self.fail:
            raise RuntimeError("fake-private-cleanup-error")


class ProtonDriveClientTests(unittest.TestCase):
    def setUp(self):
        try:
            from proton_backup.proton_cli import ProtonDriveClient, RemoteLayout
        except ModuleNotFoundError as error:
            self.fail(f"Proton CLI adapter is missing: {error}")
        self.ProtonDriveClient = ProtonDriveClient
        self.RemoteLayout = RemoteLayout
        self.layout = RemoteLayout(ROOT, INCOMING, FINAL)
        self.backup = StableBackup(
            Path("/backup/Nightly Home.tar"),
            "Nightly Home.tar",
            4096,
            1_786_365_296_000_000_000,
            "a" * 64,
        )
        self.log_stream = io.StringIO()
        logger = logging.Logger("test-proton-cli")
        logger.addHandler(logging.StreamHandler(self.log_stream))
        self.safe_log = SafeLogger(logger)

    def _client(self, runner, **kwargs):
        return self.ProtonDriveClient(
            runner=runner,
            executable="proton-drive",
            transfer_id_factory=lambda: TRANSFER_ID,
            logger=self.safe_log,
            **kwargs,
        )

    def test_timed_out_command_raises_exported_process_timeout(self) -> None:
        from proton_backup.proton_cli import ProtonProcessTimeout

        runner = FakeCliRunner(
            lambda call: CommandResult(call, -1, "", "", timed_out=True)
        )

        with self.assertRaises(ProtonProcessTimeout):
            self._client(runner).list_final(self.layout)

    def test_provable_connection_failure_raises_exported_network_error(self) -> None:
        from proton_backup.proton_cli import ProtonNetworkError

        def fail(_call):
            raise ConnectionError("private network endpoint")

        with self.assertRaises(ProtonNetworkError) as raised:
            self._client(FakeCliRunner(fail)).list_final(self.layout)
        self.assertNotIn("endpoint", str(raised.exception))

    def test_validate_upload_result_requires_exact_owned_backup_identity(self) -> None:
        from proton_backup.proton_cli import ProtonCliError, validate_upload_result

        valid = RemoteFile(
            "remote-1",
            FINAL_NAME,
            f"{FINAL}/{FINAL_NAME}",
            self.backup.size,
            datetime(2026, 8, 10, 12, 34, 56, tzinfo=UTC),
        )
        self.assertIs(validate_upload_result(valid, self.backup, self.layout), valid)
        malformed = (
            replace(valid, size=valid.size + 1),
            replace(valid, path=f"{INCOMING}/{valid.name}"),
            replace(valid, name=valid.name.replace("aaaaaaaaaaaa", "bbbbbbbbbbbb")),
            {"uid": valid.uid},
        )
        for candidate in malformed:
            with self.subTest(candidate=candidate):
                with self.assertRaises(ProtonCliError):
                    validate_upload_result(candidate, self.backup, self.layout)

    def test_successful_upload_closes_transfer_cancellation_before_return(self) -> None:
        from proton_backup.proton_cli import TransferControl

        control = TransferControl()

        remote = self._client(self._upload_runner()).upload_and_finalize(
            self.backup, self.layout, control
        )

        self.assertEqual(remote.path, f"{FINAL}/{FINAL_NAME}")
        self.assertFalse(control.request_cancel())

    def _upload_runner(self, *, info_output=None):
        upload = json.loads(fixture("cli_upload.json"))
        final = fixture("cli_info.json") if info_output is None else info_output
        current_name = [upload["name"]]

        def handler(call):
            operation = call[2]
            if operation == "create-folder":
                path = f"{call[3]}/{call[4]}"
                return CommandResult(
                    call, 0, node(uid="folder-transfer", name=call[4], path=path), ""
                )
            if operation == "upload":
                uploaded = dict(upload)
                uploaded["name"] = PurePosixPath(call[3]).name
                uploaded["path"] = f"{call[4]}/{uploaded['name']}"
                current_name[0] = uploaded["name"]
                return CommandResult(call, 0, json.dumps(uploaded), "")
            if operation == "rename":
                renamed = dict(upload)
                renamed["name"] = call[4]
                renamed["path"] = f"{INCOMING}/{TRANSFER_ID}/{call[4]}"
                current_name[0] = call[4]
                return CommandResult(call, 0, json.dumps(renamed), "")
            if operation == "move":
                moved = json.loads(final)
                moved["name"] = current_name[0]
                moved["path"] = f"{call[4]}/{current_name[0]}"
                return CommandResult(call, 0, json.dumps(moved), "")
            if operation == "info":
                confirmed = json.loads(final)
                confirmed["name"] = current_name[0]
                confirmed["path"] = call[3]
                return CommandResult(call, 0, json.dumps(confirmed), "")
            raise AssertionError(f"unexpected fake operation: {operation}")

        return FakeCliRunner(handler)

    def test_upload_uses_exact_unique_incoming_rename_move_and_info_arrays(self):
        runner = self._upload_runner()
        client = self._client(runner)

        remote = client.upload_and_finalize(self.backup, self.layout, Event())

        transfer_folder = f"{INCOMING}/{TRANSFER_ID}"
        final_path = f"{FINAL}/{FINAL_NAME}"
        self.assertEqual(
            runner.calls,
            [
                ("proton-drive", "filesystem", "create-folder", INCOMING, TRANSFER_ID, "--json"),
                (
                    "proton-drive",
                    "filesystem",
                    "upload",
                    "/backup/Nightly Home.tar",
                    transfer_folder,
                    "--conflict-strategy",
                    "skip",
                    "--skip-thumbnails",
                    "--json",
                ),
                (
                    "proton-drive",
                    "filesystem",
                    "rename",
                    f"{transfer_folder}/Nightly Home.tar",
                    FINAL_NAME,
                    "--json",
                ),
                (
                    "proton-drive",
                    "filesystem",
                    "move",
                    f"{transfer_folder}/{FINAL_NAME}",
                    FINAL,
                    "--json",
                ),
                ("proton-drive", "filesystem", "info", final_path, "--json"),
            ],
        )
        self.assertEqual(remote.uid, "remote-upload-001")
        self.assertEqual(remote.name, FINAL_NAME)
        self.assertEqual(remote.path, final_path)
        self.assertEqual(remote.size, self.backup.size)

    def test_upload_passes_shell_metacharacters_as_one_argument(self):
        runner = self._upload_runner()
        backup = StableBackup(
            Path("/backup/x; touch PWNED.tar"),
            "x; touch PWNED.tar",
            self.backup.size,
            self.backup.mtime_ns,
            self.backup.sha256,
        )

        self._client(runner).upload_and_finalize(backup, self.layout, Event())

        upload_call = runner.calls[1]
        self.assertEqual(upload_call[3], "/backup/x; touch PWNED.tar")
        self.assertNotIn("shell", " ".join(upload_call).casefold())

    def test_upload_rejects_malformed_schema_and_final_size_mismatch(self):
        cases = (
            ("malformed", fixture("cli_malformed.json")),
            (
                "wrong-size",
                fixture("cli_info.json").replace('"size": 4096', '"size": 4097'),
            ),
        )
        from proton_backup.proton_cli import ProtonCliError

        for label, output in cases:
            with self.subTest(label=label):
                runner = self._upload_runner(info_output=output)
                with self.assertRaises(ProtonCliError):
                    self._client(runner).upload_and_finalize(
                        self.backup, self.layout, Event()
                    )

    def test_upload_rejects_malformed_backup_metadata_before_any_cli_command(self):
        cases = (
            ("negative-size", replace(self.backup, size=-1)),
            ("boolean-size", replace(self.backup, size=True)),
            ("oversized-size", replace(self.backup, size=2**63)),
            ("negative-mtime", replace(self.backup, mtime_ns=-1)),
            ("oversized-mtime", replace(self.backup, mtime_ns=10**30)),
            ("uppercase-sha", replace(self.backup, sha256="A" * 64)),
            ("short-sha", replace(self.backup, sha256="a" * 63)),
            ("separator-name", replace(self.backup, display_name="foreign/x.tar")),
            ("control-name", replace(self.backup, display_name="bad\nname.tar")),
            ("oversized-name", replace(self.backup, display_name="x" * 252 + ".tar")),
            (
                "non-path-local",
                replace(self.backup, local_path="/backup/Nightly Home.tar"),
            ),
            (
                "path-name-mismatch",
                replace(self.backup, display_name="Different.tar"),
            ),
        )
        from proton_backup.proton_cli import ProtonCliError

        for label, backup in cases:
            with self.subTest(label=label):
                runner = self._upload_runner()
                with self.assertRaises(ProtonCliError):
                    self._client(runner).upload_and_finalize(
                        backup, self.layout, Event()
                    )
                self.assertEqual(runner.calls, [])

    def test_upload_stops_on_duplicate_json_keys_before_follow_up_command(self):
        duplicate = (
            '{"uid":"folder-transfer","uid":"injected","name":"'
            + TRANSFER_ID
            + '","path":"'
            + INCOMING
            + "/"
            + TRANSFER_ID
            + '","type":"folder","size":0,'
            '"modified_at":"2026-08-10T12:34:56Z"}'
        )
        runner = FakeCliRunner(
            lambda call: CommandResult(call, 0, duplicate, "")
        )
        from proton_backup.proton_cli import ProtonCliError

        with self.assertRaises(ProtonCliError):
            self._client(runner).upload_and_finalize(self.backup, self.layout, Event())

        self.assertEqual(len(runner.calls), 1)
        self.assertEqual(runner.calls[0][2], "create-folder")

    def test_upload_stops_neutrally_on_unbounded_or_nonfinite_json_numbers(self):
        base = (
            '{"uid":"folder-transfer","name":"'
            + TRANSFER_ID
            + '","path":"'
            + INCOMING
            + "/"
            + TRANSFER_ID
            + '","type":"folder","size":VALUE,'
            '"modified_at":"2026-08-10T12:34:56Z"}'
        )
        cases = (
            ("huge-integer", "9" * 5_000),
            ("nonfinite", "NaN"),
            ("bool-as-int", "true"),
        )
        from proton_backup.proton_cli import ProtonCliError

        for label, value in cases:
            with self.subTest(label=label):
                runner = FakeCliRunner(
                    lambda call, output=base.replace("VALUE", value): CommandResult(
                        call, 0, output, ""
                    )
                )
                with self.assertRaises(ProtonCliError) as raised:
                    self._client(runner).upload_and_finalize(
                        self.backup, self.layout, Event()
                    )
                self.assertEqual(
                    str(raised.exception),
                    "Unable to validate Proton Drive response",
                )
                self.assertEqual(len(runner.calls), 1)
                self.assertEqual(runner.calls[0][2], "create-folder")

    def test_json_boundary_normalizes_expected_decoder_exception_classes(self):
        from proton_backup.proton_cli import ProtonCliError, _load_json

        private_marker = "private-decoder-value"
        cases = (
            json.JSONDecodeError(private_marker, private_marker, 0),
            ValueError(private_marker),
            TypeError(private_marker),
            OverflowError(private_marker),
            RecursionError(private_marker),
        )
        for error in cases:
            with self.subTest(error_type=type(error).__name__):
                with patch("proton_backup.proton_cli.json.loads", side_effect=error):
                    with self.assertRaises(ProtonCliError) as raised:
                        _load_json("[]")
                self.assertEqual(
                    str(raised.exception),
                    "Unable to validate Proton Drive response",
                )
                self.assertNotIn(private_marker, str(raised.exception))

    def test_json_boundary_rejects_nonfinite_or_oversized_numbers(self):
        from proton_backup.proton_cli import ProtonCliError, _load_json

        cases = (
            "NaN",
            "Infinity",
            "-Infinity",
            "1e309",
            "0." + "0" * 65 + "1",
            "9" * 5_000,
        )
        for index, document in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(ProtonCliError):
                    _load_json(document)

    def test_json_boundary_rejects_recursive_and_aggregate_bound_violations(self):
        from proton_backup.proton_cli import ProtonCliError, _load_json

        documents = (
            "[" * 33 + "0" + "]" * 33,
            '{"k":' * 33 + "0" + "}" * 33,
            json.dumps([0] * 1_025),
            json.dumps({f"k{index}": 0 for index in range(65)}),
            json.dumps({"k" * 129: 0}),
            json.dumps("x" * 4_097),
            json.dumps([[0] * 1_000 for _ in range(66)]),
            json.dumps("é" * 32_768, ensure_ascii=False),
        )
        for index, document in enumerate(documents):
            with self.subTest(index=index):
                with self.assertRaises(ProtonCliError):
                    _load_json(document)

    def test_json_boundary_rejects_non_json_hook_results(self):
        from proton_backup.proton_cli import ProtonCliError, _load_json

        for value in ({1: "value"}, object()):
            with self.subTest(value_type=type(value).__name__):
                with patch("proton_backup.proton_cli.json.loads", return_value=value):
                    with self.assertRaises(ProtonCliError):
                        _load_json("{}")

    def test_nonzero_command_error_is_neutral(self):
        def fail(call):
            return CommandResult(call, 9, "fake-private-json", "fake-private-error")

        from proton_backup.proton_cli import ProtonCliError

        with self.assertRaises(ProtonCliError) as raised:
            self._client(FakeCliRunner(fail)).list_final(self.layout)
        message = str(raised.exception)
        self.assertNotIn("fake-private", message)
        self.assertNotIn(FINAL, message)

    def _final_listing(self, *entries):
        return "[" + ",".join(entries) + "]"

    def test_find_final_returns_exact_candidate_not_ownership_proof(self):
        listing = self._final_listing(
            node(
                uid="final-1",
                name=FINAL_NAME,
                path=f"{FINAL}/{FINAL_NAME}",
                kind="file",
                size=4096,
            )
        )
        runner = FakeCliRunner(lambda call: CommandResult(call, 0, listing, ""))

        remote = self._client(runner).find_final(self.backup, self.layout)

        self.assertEqual(
            (remote.uid, remote.name, remote.path, remote.size),
            ("final-1", FINAL_NAME, f"{FINAL}/{FINAL_NAME}", 4096),
        )
        self.assertEqual(
            runner.calls, [("proton-drive", "filesystem", "list", FINAL, "--json")]
        )

    def test_find_final_returns_none_when_backup_was_never_finalized(self):
        other = FINAL_NAME.replace("aaaaaaaaaaaa", "bbbbbbbbbbbb")
        listing = self._final_listing(
            node(uid="final-2", name=other, path=f"{FINAL}/{other}", kind="file", size=4096)
        )
        runner = FakeCliRunner(lambda call: CommandResult(call, 0, listing, ""))

        self.assertIsNone(self._client(runner).find_final(self.backup, self.layout))

    def test_find_final_reports_same_name_with_other_size_as_conflict(self):
        from proton_backup.proton_cli import ProtonRemoteConflict

        listing = self._final_listing(
            node(
                uid="final-3",
                name=FINAL_NAME,
                path=f"{FINAL}/{FINAL_NAME}",
                kind="file",
                size=4095,
            )
        )
        runner = FakeCliRunner(lambda call: CommandResult(call, 0, listing, ""))

        with self.assertRaises(ProtonRemoteConflict):
            self._client(runner).find_final(self.backup, self.layout)

    def test_find_final_listing_failure_is_not_a_conflict(self):
        from proton_backup.proton_cli import ProtonCliError, ProtonRemoteConflict

        runner = FakeCliRunner(lambda call: CommandResult(call, 1, "", "offline"))

        with self.assertRaises(ProtonCliError) as caught:
            self._client(runner).find_final(self.backup, self.layout)
        self.assertNotIsInstance(caught.exception, ProtonRemoteConflict)

    def test_list_final_strictly_parses_only_normalized_children(self):
        runner = FakeCliRunner(
            lambda call: CommandResult(call, 0, fixture("cli_list.json"), "")
        )

        listing = self._client(runner).list_final(self.layout)
        from proton_backup.proton_cli import FinalListing

        self.assertEqual(
            runner.calls,
            [("proton-drive", "filesystem", "list", FINAL, "--json")],
        )
        self.assertIs(type(listing), FinalListing)
        self.assertIs(listing.complete, True)
        self.assertEqual(
            [remote.name for remote in listing.files],
            [FINAL_NAME],
        )

    def test_list_final_rejects_injected_paths_ids_and_duplicate_entries(self):
        valid = json.loads(fixture("cli_list.json"))[0]
        cases = []
        injected_path = dict(valid, path=f"{FINAL}/../foreign/{FINAL_NAME}")
        cases.append(("traversal", [injected_path]))
        injected_uid = dict(valid, uid="id/../../foreign")
        cases.append(("uid", [injected_uid]))
        cases.append(("duplicate", [valid, valid]))
        from proton_backup.proton_cli import ProtonCliError

        for label, payload in cases:
            with self.subTest(label=label):
                runner = FakeCliRunner(
                    lambda call, payload=payload: CommandResult(
                        call, 0, json.dumps(payload), ""
                    )
                )
                with self.assertRaises(ProtonCliError):
                    self._client(runner).list_final(self.layout)

    def test_list_final_rejects_duplicate_keys_and_oversized_values(self):
        valid = json.loads(fixture("cli_list.json"))[0]
        duplicate_keys = fixture("cli_list.json").replace(
            '"uid": "remote-upload-001",',
            '"uid": "remote-upload-001", "uid": "injected",',
        )
        cases = (
            ("duplicate-keys", duplicate_keys),
            ("uid", json.dumps([dict(valid, uid="x" * 129)])),
            ("name", json.dumps([dict(valid, name="x" * 256, path=FINAL + "/" + "x" * 256)])),
            ("size", json.dumps([dict(valid, size=2**63)])),
            ("container", json.dumps([] * 0 + [valid] * 1025)),
        )
        from proton_backup.proton_cli import ProtonCliError

        for label, output in cases:
            with self.subTest(label=label):
                runner = FakeCliRunner(
                    lambda call, output=output: CommandResult(call, 0, output, "")
                )
                with self.assertRaises(ProtonCliError):
                    self._client(runner).list_final(self.layout)
                self.assertEqual(len(runner.calls), 1)

    def test_ensure_layout_creates_only_installation_owned_folder_tree(self):
        def handler(call):
            operation = call[2]
            if operation == "list":
                return CommandResult(call, 0, "[]", "")
            if operation == "create-folder":
                path = f"{call[3]}/{call[4]}"
                return CommandResult(
                    call,
                    0,
                    node(uid=f"folder-{call[4]}", name=call[4], path=path),
                    "",
                )
            raise AssertionError(operation)

        runner = FakeCliRunner(handler)

        layout = self._client(runner).ensure_layout(INSTALLATION_ID)

        self.assertEqual(layout, self.layout)
        create_calls = [call for call in runner.calls if call[2] == "create-folder"]
        self.assertEqual(
            create_calls,
            [
                ("proton-drive", "filesystem", "create-folder", "/my-files", "HomeAssistant-Backups", "--json"),
                ("proton-drive", "filesystem", "create-folder", "/my-files/HomeAssistant-Backups", INSTALLATION_ID, "--json"),
                ("proton-drive", "filesystem", "create-folder", ROOT, "incoming", "--json"),
                ("proton-drive", "filesystem", "create-folder", ROOT, "backups", "--json"),
            ],
        )

    def test_ensure_layout_rejects_installation_or_cli_path_injection(self):
        from proton_backup.proton_cli import ProtonCliError

        client = self._client(FakeCliRunner())
        for value in ("../foreign", "A" * 32, "a" * 31):
            with self.subTest(value=value):
                with self.assertRaises(ProtonCliError):
                    client.ensure_layout(value)

        def injected(call):
            if call[2] == "list":
                return CommandResult(call, 0, "[]", "")
            return CommandResult(
                call,
                0,
                node(uid="folder-safe", name=call[4], path="/foreign/injected"),
                "",
            )

        with self.assertRaises(ProtonCliError):
            self._client(FakeCliRunner(injected)).ensure_layout(INSTALLATION_ID)

    def test_permanent_delete_requires_owned_final_file_and_exact_trash_flow(self):
        remote = self._client(
            FakeCliRunner(
                lambda call: CommandResult(call, 0, fixture("cli_list.json"), "")
            )
        ).list_final(self.layout).files[0]

        def handler(call):
            if call[2] == "info":
                return CommandResult(call, 0, fixture("cli_info.json"), "")
            if call[2] == "trash":
                trashed = json.loads(fixture("cli_info.json"))
                trashed["path"] = f"/trash/trash-unique-001/{FINAL_NAME}"
                return CommandResult(call, 0, json.dumps(trashed), "")
            if call[2] == "list":
                trashed = json.loads(fixture("cli_info.json"))
                trashed["path"] = f"/trash/trash-unique-001/{FINAL_NAME}"
                return CommandResult(call, 0, json.dumps([trashed]), "")
            if call[2] == "delete":
                deleted = json.loads(fixture("cli_info.json"))
                deleted["path"] = call[3]
                return CommandResult(call, 0, json.dumps(deleted), "")
            raise AssertionError(call)

        runner = FakeCliRunner(handler)

        self._client(runner).permanently_delete_owned(remote, self.layout)

        trash_path = f"/trash/trash-unique-001/{FINAL_NAME}"
        self.assertEqual(
            runner.calls,
            [
                ("proton-drive", "filesystem", "info", remote.path, "--json"),
                ("proton-drive", "filesystem", "trash", remote.path, "--json"),
                (
                    "proton-drive",
                    "filesystem",
                    "list",
                    "/trash",
                    "--json",
                ),
                ("proton-drive", "filesystem", "delete", trash_path, "--json"),
            ],
        )

    def test_permanent_delete_rejects_unproven_fresh_trash_listing(self):
        remote = self._client(
            FakeCliRunner(
                lambda call: CommandResult(call, 0, fixture("cli_list.json"), "")
            )
        ).list_final(self.layout).files[0]
        from proton_backup.proton_cli import ProtonCliError

        trash_path = f"/trash/trash-unique-001/{FINAL_NAME}"
        valid = json.loads(fixture("cli_info.json"))
        valid["path"] = trash_path
        cases = {
            "missing": [],
            "duplicate": [valid, valid],
            "folder": [{**valid, "type": "folder"}],
            "foreign-path": [{**valid, "path": f"/trash/other-id/{FINAL_NAME}"}],
            "uid": [{**valid, "uid": "different-uid"}],
            "size": [{**valid, "size": valid["size"] + 1}],
            "modified-at": [{**valid, "modified_at": "2026-08-10T12:34:57Z"}],
        }
        for label, listing in cases.items():
            with self.subTest(label=label):
                def handler(call, listing=listing):
                    if call[2] == "info":
                        return CommandResult(call, 0, fixture("cli_info.json"), "")
                    if call[2] == "trash":
                        return CommandResult(call, 0, json.dumps(valid), "")
                    if call[2] == "list":
                        return CommandResult(call, 0, json.dumps(listing), "")
                    if call[2] == "delete":
                        return CommandResult(call, 0, json.dumps(valid), "")
                    raise AssertionError(call)

                runner = FakeCliRunner(handler)
                with self.assertRaises(ProtonCliError):
                    self._client(runner).permanently_delete_owned(remote, self.layout)
                self.assertNotIn("delete", [call[2] for call in runner.calls])

    def test_permanent_delete_stops_when_trash_command_fails(self):
        remote = self._client(
            FakeCliRunner(
                lambda call: CommandResult(call, 0, fixture("cli_list.json"), "")
            )
        ).list_final(self.layout).files[0]
        from proton_backup.proton_cli import ProtonCliError

        def handler(call):
            if call[2] == "info":
                return CommandResult(call, 0, fixture("cli_info.json"), "")
            if call[2] == "trash":
                return CommandResult(call, 1, "", "private failure details")
            raise AssertionError(call)

        runner = FakeCliRunner(handler)
        with self.assertRaises(ProtonCliError):
            self._client(runner).permanently_delete_owned(remote, self.layout)
        self.assertEqual([call[2] for call in runner.calls], ["info", "trash"])

    def test_permanent_delete_fails_closed_for_foreign_or_injected_remote(self):
        from proton_backup.models import RemoteFile
        from proton_backup.proton_cli import ProtonCliError

        runner = FakeCliRunner()
        client = self._client(runner)
        foreign = RemoteFile("foreign", "foreign.tar", "/foreign/foreign.tar", 1, None)
        with self.assertRaises(ProtonCliError):
            client.permanently_delete_owned(foreign, self.layout)
        self.assertEqual(runner.calls, [])

    def test_permanent_delete_rejects_malformed_owned_name_before_any_command(self):
        from proton_backup.models import RemoteFile
        from proton_backup.proton_cli import ProtonCliError

        names = (
            f"ha-v1--{INSTALLATION_ID}--bad-time--nightly--aaaaaaaaaaaa.tar",
            f"ha-v1--{INSTALLATION_ID}--20260810T123456Z--bad_base--aaaaaaaaaaaa.tar",
            f"ha-v1--{INSTALLATION_ID}--20260810T123456Z--nightly--AAAAAAAAAAAA.tar",
        )
        for name in names:
            with self.subTest(name=name):
                runner = FakeCliRunner()
                remote = RemoteFile("owned", name, f"{FINAL}/{name}", 1, None)
                with self.assertRaises(ProtonCliError):
                    self._client(runner).permanently_delete_owned(remote, self.layout)
                self.assertEqual(runner.calls, [])

    def test_permanent_delete_rejects_malformed_remote_scalars_before_any_command(self):
        from proton_backup.models import RemoteFile
        from proton_backup.proton_cli import ProtonCliError

        valid_name = FINAL_NAME
        cases = (
            RemoteFile(7, valid_name, f"{FINAL}/{valid_name}", 1, None),
            RemoteFile("owned", 7, f"{FINAL}/{valid_name}", 1, None),
            RemoteFile("owned", valid_name, 7, 1, None),
        )
        for remote in cases:
            with self.subTest(
                uid_type=type(remote.uid).__name__,
                name_type=type(remote.name).__name__,
                path_type=type(remote.path).__name__,
            ):
                runner = FakeCliRunner()
                with self.assertRaises(ProtonCliError):
                    self._client(runner).permanently_delete_owned(remote, self.layout)
                self.assertEqual(runner.calls, [])

    def test_permanent_delete_requires_present_strict_utc_input_metadata(self):
        from proton_backup.models import RemoteFile
        from proton_backup.proton_cli import ProtonCliError

        cases = (
            None,
            "2026-08-10T12:34:56Z",
            datetime(2026, 8, 10, 12, 34, 56),
            datetime(
                2026,
                8,
                10,
                14,
                34,
                56,
                tzinfo=timezone(timedelta(hours=2)),
            ),
        )
        for modified_at in cases:
            with self.subTest(modified_at=modified_at):
                runner = FakeCliRunner()
                remote = RemoteFile(
                    "remote-upload-001",
                    FINAL_NAME,
                    f"{FINAL}/{FINAL_NAME}",
                    4096,
                    modified_at,  # type: ignore[arg-type]
                )
                with self.assertRaises(ProtonCliError):
                    self._client(runner).permanently_delete_owned(remote, self.layout)
                self.assertEqual(runner.calls, [])

    def test_permanent_delete_requires_strict_matching_info_and_trash_metadata(self):
        remote = self._client(
            FakeCliRunner(
                lambda call: CommandResult(call, 0, fixture("cli_list.json"), "")
            )
        ).list_final(self.layout).files[0]
        from proton_backup.proton_cli import ProtonCliError

        cases = (
            ("info-none", "info", None),
            ("info-malformed", "info", "not-a-timestamp"),
            ("info-mismatch", "info", "2026-08-10T12:34:57Z"),
            ("trash-none", "trash", None),
            ("trash-malformed", "trash", "not-a-timestamp"),
            ("trash-mismatch", "trash", "2026-08-10T12:34:57Z"),
        )
        for label, stage, modified_at in cases:
            with self.subTest(label=label):
                def handler(call, stage=stage, modified_at=modified_at):
                    output = json.loads(fixture("cli_info.json"))
                    if call[2] == "info":
                        if stage == "info":
                            output["modified_at"] = modified_at
                        return CommandResult(call, 0, json.dumps(output), "")
                    if call[2] == "trash":
                        output["path"] = f"/trash/trash-unique-001/{FINAL_NAME}"
                        output["modified_at"] = modified_at
                        return CommandResult(call, 0, json.dumps(output), "")
                    raise AssertionError(call)

                runner = FakeCliRunner(handler)
                with self.assertRaises(ProtonCliError):
                    self._client(runner).permanently_delete_owned(remote, self.layout)
                expected = ["info"] if stage == "info" else ["info", "trash"]
                self.assertEqual([call[2] for call in runner.calls], expected)

    def test_permanent_delete_rejects_folder_or_metadata_mismatch_before_trash(self):
        remote = self._client(
            FakeCliRunner(
                lambda call: CommandResult(call, 0, fixture("cli_list.json"), "")
            )
        ).list_final(self.layout).files[0]
        from proton_backup.proton_cli import ProtonCliError

        cases = (
            ("folder", fixture("cli_info.json").replace('"type": "file"', '"type": "folder"')),
            ("size", fixture("cli_info.json").replace('"size": 4096', '"size": 4097')),
            ("uid", fixture("cli_info.json").replace("remote-upload-001", "different-uid")),
        )
        for label, info_output in cases:
            with self.subTest(label=label):
                runner = FakeCliRunner(
                    lambda call, output=info_output: CommandResult(call, 0, output, "")
                )
                with self.assertRaises(ProtonCliError):
                    self._client(runner).permanently_delete_owned(remote, self.layout)
                self.assertEqual([call[2] for call in runner.calls], ["info"])

    def test_permanent_delete_rejects_ambiguous_or_foreign_trash_path(self):
        remote = self._client(
            FakeCliRunner(
                lambda call: CommandResult(call, 0, fixture("cli_list.json"), "")
            )
        ).list_final(self.layout).files[0]
        from proton_backup.proton_cli import ProtonCliError

        cases = (
            ("foreign-descendant", f"/trash/foreign/nested/{FINAL_NAME}"),
            ("missing-unique-id", f"/trash/{FINAL_NAME}"),
        )
        for label, trash_path in cases:
            with self.subTest(label=label):
                def handler(call, trash_path=trash_path):
                    output = json.loads(fixture("cli_info.json"))
                    if call[2] == "info":
                        return CommandResult(call, 0, json.dumps(output), "")
                    output["path"] = trash_path
                    return CommandResult(call, 0, json.dumps(output), "")

                runner = FakeCliRunner(handler)
                with self.assertRaises(ProtonCliError):
                    self._client(runner).permanently_delete_owned(remote, self.layout)
                self.assertEqual([call[2] for call in runner.calls], ["info", "trash"])

    def test_is_authenticated_uses_strict_root_list_without_auth_secrets(self):
        root_listing = "[" + node(
            uid="root-folder", name="HomeAssistant-Backups", path="/my-files/HomeAssistant-Backups"
        ) + "]"
        runner = FakeCliRunner(lambda call: CommandResult(call, 0, root_listing, ""))

        self.assertTrue(self._client(runner).is_authenticated())
        self.assertEqual(
            runner.calls,
            [("proton-drive", "filesystem", "list", "/my-files", "--json")],
        )

    def test_is_authenticated_returns_false_on_nonzero_and_rejects_malformed_json(self):
        from proton_backup.proton_cli import ProtonCliError

        failure = FakeCliRunner(lambda call: CommandResult(call, 1, "", "logged out"))
        self.assertFalse(self._client(failure).is_authenticated())
        malformed = FakeCliRunner(
            lambda call: CommandResult(call, 0, fixture("cli_malformed.json"), "")
        )
        with self.assertRaises(ProtonCliError):
            self._client(malformed).is_authenticated()

    def test_is_authenticated_rejects_valid_json_outside_my_files(self):
        runner = FakeCliRunner(
            lambda call: CommandResult(call, 0, fixture("cli_list.json"), "")
        )
        from proton_backup.proton_cli import ProtonCliError

        with self.assertRaises(ProtonCliError):
            self._client(runner).is_authenticated()

    def test_login_emits_only_https_proton_url_to_privileged_callback(self):
        login_url = "https://account.proton.me/login?token=fake-browser-value"
        runner = FakeCliRunner(login_lines=(f"Open {login_url}",))
        received = []

        self._client(runner).start_login(received.append, Event())

        self.assertEqual(runner.calls, [("proton-drive", "auth", "login")])
        self.assertEqual(len(received), 1)
        parsed = urlsplit(received[0])
        self.assertEqual(parsed.scheme, "https")
        self.assertTrue(
            parsed.hostname == "proton.me" or parsed.hostname.endswith(".proton.me")
        )
        self.assertNotIn(received[0], self.log_stream.getvalue())
        self.assertNotIn("fake-browser-value", self.log_stream.getvalue())

    def test_login_process_and_secret_share_remaining_absolute_deadline(self):
        clock = [100.0]
        runner = FakeCliRunner(
            login_lines=("Open https://account.proton.me/login?token=fake",)
        )
        client = self._client(runner, monotonic=lambda: clock[0])

        client.start_login(lambda _url: None, Event(), deadline=101.0)

        self.assertEqual(runner.timeouts, [1])

    def test_expired_absolute_login_deadline_never_starts_process(self):
        clock = [220.0]
        runner = FakeCliRunner()
        client = self._client(runner, monotonic=lambda: clock[0])
        from proton_backup.proton_cli import ProtonCliError

        with self.assertRaises(ProtonCliError):
            client.start_login(lambda _url: None, Event(), deadline=220.0)

        self.assertEqual(runner.calls, [])

    def test_absolute_login_deadline_caps_probe_and_logout_without_runner_after_expiry(self):
        clock = [100.0]
        root_listing = "[" + node(
            uid="root-folder",
            name="HomeAssistant-Backups",
            path="/my-files/HomeAssistant-Backups",
        ) + "]"
        runner = FakeCliRunner(
            lambda call: CommandResult(call, 0, root_listing, "")
        )
        client = self._client(runner, monotonic=lambda: clock[0])

        self.assertTrue(client.is_authenticated(deadline=101.0))
        client.logout(cancel=Event(), deadline=101.0)
        self.assertEqual(runner.timeouts, [1.0, 1.0])

        clock[0] = 101.0
        from proton_backup.proton_cli import ProtonProcessTimeout

        with self.assertRaises(ProtonProcessTimeout):
            client.is_authenticated(deadline=101.0)
        self.assertEqual(len(runner.calls), 2)

    def test_login_rejects_nonallowlisted_ambiguous_or_oversized_lines(self):
        cases = (
            ("http", ("Open http://account.proton.me/login?token=fake",)),
            ("userinfo", ("Open https://user@account.proton.me/login?token=fake",)),
            ("suffix", ("Open https://proton.me.attacker.invalid/login?token=fake",)),
            ("path", ("Open https://account.proton.me/not-allowed?token=fake",)),
            ("control", ("Open https://account.proton.me/login?token=fake\x00",)),
            ("encoding", ("Open https://account.proton.me/login?token=faké",)),
            ("oversized", ("Open https://account.proton.me/login?token=" + "x" * 4096,)),
            (
                "same-line-multiple",
                (
                    "Open https://account.proton.me/login?token=fake-one "
                    "https://account.proton.me/login?token=fake-two",
                ),
            ),
            (
                "multiple-lines",
                (
                    "Open https://account.proton.me/login?token=fake-one",
                    "Open https://account.proton.me/login?token=fake-two",
                ),
            ),
        )
        from proton_backup.proton_cli import ProtonCliError

        for label, lines in cases:
            with self.subTest(label=label):
                with self.assertRaises(ProtonCliError):
                    self._client(FakeCliRunner(login_lines=lines)).start_login(
                        lambda value: None, Event()
                    )

    def test_login_url_expires_in_memory_and_active_attempt_is_cleared(self):
        clock = [100.0]
        login_url = "https://account.proton.me/login?token=fake-expired-value"
        runner = FakeCliRunner(
            login_lines=(f"Open {login_url}",),
            before_login=lambda: clock.__setitem__(0, 401.0),
        )
        from proton_backup.proton_cli import ProtonCliError

        client = self._client(runner, monotonic=lambda: clock[0], login_url_ttl=120)
        with self.assertRaises(ProtonCliError):
            client.start_login(lambda value: None, Event())

        runner.before_login = lambda: clock.__setitem__(0, 402.0)
        client.start_login(lambda value: None, Event())

    def test_login_allows_only_one_active_attempt(self):
        started = Event()
        release = Event()
        login_url = "https://account.proton.me/login?token=fake-active-value"

        class BlockingRunner(FakeCliRunner):
            def run(self, args, **kwargs):
                started.set()
                release.wait(2)
                return super().run(args, **kwargs)

        runner = BlockingRunner(login_lines=(f"Open {login_url}",))
        client = self._client(runner)
        failures = []
        thread = Thread(
            target=lambda: self._capture_failure(
                failures, lambda: client.start_login(lambda value: None, Event())
            )
        )
        thread.start()
        self.assertTrue(started.wait(1))
        from proton_backup.proton_cli import LoginInProgressError

        with self.assertRaises(LoginInProgressError):
            client.start_login(lambda value: None, Event())
        release.set()
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])

    @staticmethod
    def _capture_failure(failures, operation):
        try:
            operation()
        except Exception as error:
            failures.append(type(error).__name__)

    def test_login_cancellation_is_neutral_and_releases_active_attempt(self):
        from proton_backup.proton_cli import ProtonCliCancelled

        cancel = Event()
        cancel.set()
        runner = FakeCliRunner()
        client = self._client(runner)
        with self.assertRaises(ProtonCliCancelled):
            client.start_login(lambda value: None, cancel)

        runner.login_lines = (
            "Open https://account.proton.me/login?token=fake-after-cancel",
        )
        client.start_login(lambda value: None, Event())

    def test_logout_uses_exact_argv_then_removes_private_credentials(self):
        credentials = FakeCredentialStore()
        runner = FakeCliRunner(
            lambda call: CommandResult(call, 0, "", "")
        )
        client = self._client(runner, credential_store=credentials)

        client.logout(cancel=Event())

        self.assertEqual(runner.calls, [("proton-drive", "auth", "logout")])
        self.assertEqual(credentials.removed, 1)

    def test_logout_failure_still_removes_private_credentials_with_neutral_error(self):
        credentials = FakeCredentialStore()

        def fail(call):
            raise RuntimeError("fake-private-logout-error")

        from proton_backup.proton_cli import ProtonCliError

        with self.assertRaises(ProtonCliError) as raised:
            self._client(FakeCliRunner(fail), credential_store=credentials).logout(cancel=Event())
        self.assertEqual(credentials.removed, 1)
        self.assertNotIn("fake-private", str(raised.exception))

    def test_hung_login_cleanup_still_attempts_private_credential_removal(self):
        credentials = FakeCredentialStore()
        runner = FakeCliRunner(lambda call: CommandResult(call, 0, "", ""))
        client = self._client(
            runner,
            credential_store=credentials,
            login_cleanup_timeout=0.01,
        )
        client._login_cancel = Event()
        client._login_done.clear()
        from proton_backup.proton_cli import ProtonCliError

        with self.assertRaises(ProtonCliError):
            client.logout(cancel=Event())

        self.assertTrue(client._login_cancel.is_set())
        self.assertEqual(credentials.removed, 1)

    def test_logout_and_credential_cleanup_failures_are_aggregated_neutrally(self):
        credentials = FakeCredentialStore(fail=True)
        runner = FakeCliRunner(lambda call: CommandResult(call, 7, "private", "private"))
        from proton_backup.proton_cli import ProtonCliError

        with self.assertRaises(ProtonCliError) as raised:
            self._client(runner, credential_store=credentials).logout(cancel=Event())
        self.assertEqual(credentials.removed, 1)
        self.assertEqual(str(raised.exception), "Unable to disconnect Proton Drive")


if __name__ == "__main__":
    unittest.main()
