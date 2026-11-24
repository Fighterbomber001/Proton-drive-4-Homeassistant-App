import io
import tests  # Activate the app path for bare unittest discovery too.
import json
import logging
from dataclasses import replace
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from queue import Queue
from types import SimpleNamespace
from unittest.mock import Mock, patch

from proton_backup import __main__ as entrypoint
from proton_backup.redaction import SafeLogger
from proton_backup.web import DiagnosticBuffer


class OperationsTests(unittest.TestCase):
    def test_event_reaches_log_and_the_actual_diagnostics_route(self):
        from proton_backup.events import EventLog
        diagnostics = DiagnosticBuffer()
        output = io.StringIO()
        logger = logging.Logger("operations-test")
        logger.addHandler(logging.StreamHandler(output))
        events = EventLog(diagnostics=diagnostics, logger=SafeLogger(logger))
        events.record("upload_started", backup_name="password=fake-secret.tar")
        class Server:
            def __init__(self, **kwargs):
                self.controller = kwargs["controller"]
        server = entrypoint.compose_web_server(
            snapshot_provider=lambda: None, command_queue=Queue(maxsize=2),
            home_assistant_origin="https://ha.example.invalid", server_factory=Server,
            diagnostics=diagnostics,
        )
        response = server.controller.handle(
            method="GET", target="/api/diagnostics", peer="172.30.32.2",
            headers={"X-Remote-User-Id": "a" * 32},
        )
        self.assertEqual(response.status, 200)
        self.assertIn("upload_started", response.body.decode())
        self.assertIn("Upload gestartet", output.getvalue())
        self.assertNotIn("fake-secret", output.getvalue() + response.body.decode())

    def test_origin_options_validated_before_any_runtime_work(self):
        with TemporaryDirectory() as temporary:
            options = Path(temporary) / "options.json"
            options.write_text(json.dumps({"home_assistant_origin": "https://ha.example.invalid",
                                           "additional_origins": ["http://192.0.2.20:8123"]}))
            self.assertEqual(entrypoint.load_allowed_origins(options), frozenset({
                "https://ha.example.invalid", "http://192.0.2.20:8123"}))
            for extra in (["https://ha.example.invalid/path"], ["https://a@ha.example.invalid"], "https://other.invalid"):
                options.write_text(json.dumps({"home_assistant_origin": "https://ha.example.invalid", "additional_origins": extra}))
                with self.assertRaises(ValueError):
                    entrypoint.load_allowed_origins(options)

    def test_startup_failure_is_visible_without_exception_secret(self):
        def fail():
            raise RuntimeError("password=should-never-appear")
        with self.assertLogs("proton_backup", level="ERROR") as captured:
            self.assertEqual(entrypoint.main(service_factory=fail), 1)
        self.assertIn("startup_failed", " ".join(captured.output))
        self.assertNotIn("should-never-appear", " ".join(captured.output))

    def test_native_options_require_an_explicit_mode_and_valid_local_token(self):
        with TemporaryDirectory() as temporary:
            options = Path(temporary) / "options.json"
            options.write_text("{}")
            self.assertEqual(entrypoint.load_native_options(options), (False, ""))
            options.write_text(json.dumps({"native_mode": True, "integration_token": "b" * 64}))
            self.assertEqual(entrypoint.load_native_options(options), (True, "b" * 64))
            for invalid in ({"native_mode": "true"}, {"native_mode": True},
                            {"native_mode": True, "integration_token": "short"},
                            {"native_mode": True, "integration_token": "x" * 129},
                            {"native_mode": False, "integration_token": 3}):
                options.write_text(json.dumps(invalid))
                with self.subTest(options=invalid):
                    with self.assertRaises(ValueError) as caught:
                        entrypoint.load_native_options(options)
                    self.assertNotIn("short", str(caught.exception))

    def test_invalid_native_options_fail_before_creating_private_directories(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            options = root / "options.json"
            options.write_text(json.dumps({"home_assistant_origin": "https://ha.example.invalid",
                                           "native_mode": True, "integration_token": "short"}))
            with self.assertRaises(ValueError):
                entrypoint.build_service(options_path=options, private_root=root / "private",
                                         state_db=root / "state" / "state.sqlite")
            self.assertFalse((root / "private").exists())

    def test_native_status_exposes_mode_and_operation_without_a_fake_hash(self):
        from tests.test_service import empty_snapshot
        snapshot = replace(empty_snapshot(), web_ready=True, native_mode=True,
                           native_operation="download", active_name="Restore")
        controller = entrypoint.WebController(snapshot_provider=lambda: snapshot,
                    command_queue=Queue(maxsize=2), allowed_origins=frozenset({"https://ha.example.invalid"}))
        response = controller.handle(method="GET", target="/api/status", peer="172.30.32.2",
                                     headers={"X-Remote-User-Id": "a" * 32})
        data = json.loads(response.body)
        self.assertTrue(data["service"]["native_mode"])
        self.assertEqual(data["upload"]["native_operation"], "download")
        self.assertIsNone(data["upload"]["sha256"])

    def test_native_runtime_wires_the_persistent_identity_to_storage(self):
        credentials = SimpleNamespace(bootstrap=lambda: None, environment=lambda: {})
        store = SimpleNamespace(installation_id=lambda: "b" * 32, close=lambda: None)
        client, storage = object(), object()
        create_storage = Mock(return_value=storage)
        root = Path("/data/private")
        runtime = entrypoint.compose_runtime(private_root=root, native_mode=True,
            credential_store_factory=lambda _: credentials, state_store_factory=lambda _: store,
            process_runner_factory=lambda **_: object(), client_factory=lambda **_: client,
            retention_factory=lambda *_: object(), scanner_factory=lambda *_: object(),
            worker_factory=lambda *_: object(), native_storage_factory=create_storage)
        create_storage.assert_called_once_with(client, "b" * 32, root)
        self.assertIs(runtime.native_storage, storage)
        self.assertIs(runtime.auth_client, client)

    def test_native_service_build_wires_private_api_without_starting_proton(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            options = root / "options.json"
            options.write_text(json.dumps({"home_assistant_origin": "https://ha.example.invalid",
                                           "native_mode": True, "integration_token": "b" * 64}))
            runtime = SimpleNamespace(native_storage=SimpleNamespace(installation_id="a" * 32))
            with patch.object(entrypoint, "compose_runtime", return_value=runtime) as compose:
                service = entrypoint.build_service(options_path=options, private_root=root / "private",
                                                    state_db=root / "state" / "state.sqlite")
                self.assertIs(service._runtime_factory(), runtime)
                self.assertTrue(compose.call_args.kwargs["native_mode"])
                api = service._native_api_factory(service, runtime)
                self.assertEqual(api.port, 8100)
                self.assertEqual(api._installation_id, "a" * 32)
                self.assertIsNone(api._thread)
