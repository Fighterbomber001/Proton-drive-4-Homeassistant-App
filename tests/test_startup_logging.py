"""Startup failures must be actionable without exposing configuration values."""
import tests
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from proton_backup import __main__ as app
from proton_backup.events import EventLog


VALID = {"home_assistant_origin": "https://private-ha.example.invalid",
         "native_mode": True, "integration_token": "a" * 64}
SECRET = "SHOULD_NOT_LOG_PRIVATE"


class StartupLoggingTests(unittest.TestCase):
    def run_options(self, options, *, change=None):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "options.json"
            path.write_text(json.dumps(options), encoding="utf-8")
            with self.assertLogs("proton_backup", level="INFO") as captured:
                with change if change is not None else patch.object(app, "configure_logging"):
                    result = app.main(service_factory=lambda: app.build_service(
                        options_path=path, private_root=root / "private",
                        state_db=root / "state" / "state.sqlite"), service_runner=lambda _: 0)
            return result, "\n".join(captured.output), (root / "private").exists()

    def test_invalid_origin_identifies_the_field_without_logging_its_value(self):
        options = {**VALID, "home_assistant_origin": "https://user:" + SECRET + "@ha.invalid/path"}
        result, output, created = self.run_options(options)
        self.assertEqual(result, 1)
        self.assertIn("startup_origin_invalid", output)
        self.assertNotIn("startup_options_ready", output)
        self.assertNotIn(SECRET, output)
        self.assertNotIn(options["home_assistant_origin"], output)
        self.assertFalse(created)

    def test_additional_origin_failure_is_distinguishable_from_primary_origin(self):
        result, output, created = self.run_options({**VALID, "additional_origins": ["https://" + SECRET + ".invalid/path"]})
        self.assertEqual(result, 1)
        self.assertIn("startup_additional_origins_invalid", output)
        self.assertNotIn(SECRET, output)
        self.assertFalse(created)

    def test_pairing_key_length_and_character_errors_are_distinct_and_secret_free(self):
        for token, code in ((SECRET, "startup_token_length_invalid"),
                            (SECRET + "+" + "a" * 40, "startup_token_characters_invalid")):
            with self.subTest(code=code):
                result, output, created = self.run_options({**VALID, "integration_token": token})
                self.assertEqual(result, 1)
                self.assertIn(code, output)
                self.assertNotIn(token, output)
                self.assertNotIn(SECRET, output)
                self.assertFalse(created)

    def test_invalid_native_mode_is_explained_without_echoing_input(self):
        result, output, _ = self.run_options({**VALID, "native_mode": SECRET})
        self.assertEqual(result, 1)
        self.assertIn("startup_native_mode_invalid", output)
        self.assertNotIn(SECRET, output)

    def test_private_directory_failure_reports_stage_not_os_exception(self):
        change = patch.object(app, "prepare_data_directories", side_effect=PermissionError("Bearer " + SECRET))
        result, output, _ = self.run_options(VALID, change=change)
        self.assertEqual(result, 1)
        self.assertIn("startup_private_storage_failed", output)
        self.assertNotIn("startup_private_storage_ready", output)
        self.assertNotIn(SECRET, output)

    def test_successful_preparation_records_stages_but_not_configuration(self):
        result, output, _ = self.run_options(VALID)
        self.assertEqual(result, 0)
        for code in ("startup_started", "startup_options_ready", "startup_native_enabled",
                     "startup_private_storage_ready", "startup_configuration_ready"):
            self.assertIn(code, output)
        self.assertNotIn(VALID["home_assistant_origin"], output)
        self.assertNotIn(VALID["integration_token"], output)
        self.assertNotIn("service_started", output, "The fake runner did not start the service")

    def test_credential_bootstrap_failure_identifies_credential_stage(self):
        def fail():
            raise RuntimeError("password=" + SECRET)
        credentials = SimpleNamespace(bootstrap=fail)
        with self.assertLogs("proton_backup", level="INFO") as captured:
            with self.assertRaises(RuntimeError):
                app.compose_runtime(credential_store_factory=lambda _: credentials, event_log=EventLog())
        output = "\n".join(captured.output)
        self.assertIn("startup_credentials_failed", output)
        self.assertNotIn("startup_credentials_ready", output)
        self.assertNotIn(SECRET, output)

    def test_state_open_failure_identifies_database_stage(self):
        credentials = SimpleNamespace(bootstrap=lambda: None, environment=lambda: {})
        def fail(_):
            raise OSError(SECRET)
        with self.assertLogs("proton_backup", level="INFO") as captured:
            with self.assertRaises(OSError):
                app.compose_runtime(credential_store_factory=lambda _: credentials,
                                    state_store_factory=fail, event_log=EventLog())
        output = "\n".join(captured.output)
        self.assertIn("startup_credentials_ready", output)
        self.assertIn("startup_state_failed", output)
        self.assertNotIn(SECRET, output)

    def test_dependency_import_failure_does_not_log_import_error_details(self):
        real_import = __import__
        def fail_native_import(name, *args, **kwargs):
            if name == "native_api":
                raise ImportError(SECRET)
            return real_import(name, *args, **kwargs)
        result, output, _ = self.run_options(VALID, change=patch("builtins.__import__", side_effect=fail_native_import))
        self.assertEqual(result, 1)
        self.assertIn("startup_dependencies_failed", output)
        self.assertNotIn("startup_dependencies_ready", output)
        self.assertNotIn(SECRET, output)

    def test_missing_or_invalid_options_are_reported_without_contents(self):
        with TemporaryDirectory() as temporary:
            options = Path(temporary) / "options.json"
            for content in (None, SECRET, json.dumps([SECRET]), json.dumps({})):
                with self.subTest(content=content):
                    if content is not None:
                        options.write_text(content, encoding="utf-8")
                    with self.assertLogs("proton_backup", level="INFO") as captured:
                        result = app.main(service_factory=lambda: app.build_service(options_path=options),
                                          service_runner=lambda _: 0)
                    output = "\n".join(captured.output)
                    self.assertEqual(result, 1)
                    self.assertIn("startup_origin_missing" if content == "{}" else "startup_options_invalid", output)
                    self.assertNotIn(SECRET, output)
