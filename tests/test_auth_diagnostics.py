"""Failed browser-login attempts expose categories, never subprocess content."""
import tests
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
import unittest

from proton_backup.events import EventLog
from proton_backup.process import ProcessRunner
from proton_backup.proton_cli import ProtonDriveClient, ProtonCliError
from tests.fakes import python_executable, write_python_script
from tests.test_login_contract import DESKTOP_URL


PRIVATE = "PRIVATE_AUTH_DETAIL_MUST_NOT_APPEAR"


class AuthDiagnosticTests(unittest.TestCase):
    def failed_login(self, source):
        with TemporaryDirectory() as temporary:
            script = write_python_script(Path(temporary), "local_cli.py", source)
            class LocalRunner:
                def run(runner, args, **kwargs):
                    if args[1:] != ("auth", "login"):
                        raise AssertionError("unexpected CLI operation")
                    return ProcessRunner().run([python_executable(), str(script)], **kwargs)
            client = ProtonDriveClient(runner=LocalRunner())
            with self.assertLogs("proton_backup", level="INFO") as captured:
                with self.assertRaises(ProtonCliError):
                    client.start_login(lambda _url: self.fail("must not deliver"), Event())
        output = "\n".join(captured.output)
        for forbidden in (PRIVATE, "FakeUserCode123", DESKTOP_URL, "account.proton.me"):
            self.assertNotIn(forbidden, output)
        self.assertIn("auth_login_failed", output)
        self.assertNotIn("auth_login_link_ready", output)
        return output

    def test_cli_exit_without_link_retains_exit_code_and_stderr_presence(self):
        output = self.failed_login(
            "import sys\n"
            f"print('credentials load failed {PRIVATE} {DESKTOP_URL}', file=sys.stderr)\n"
            "sys.exit(7)\n"
        )
        self.assertIn("auth_process_no_url", output)
        self.assertIn("exit_code=7 stdout=absent stderr=present", output)
        self.assertIn("auth_hint_credentials", output)

    def test_rejected_stdout_is_not_misreported_as_no_url_exit(self):
        value = DESKTOP_URL.replace("/desktop/login", "/unrecognized-login-route")
        output = self.failed_login(f"print({value!r}, flush=True)\n")
        self.assertIn("auth_process_secret_rejected", output)
        self.assertNotIn("auth_process_no_url", output)
        self.assertIn("stdout=present stderr=absent", output)

    def test_non_ascii_stdout_reports_inspection_rejection_without_content(self):
        output = self.failed_login("import sys\n" + f"sys.stdout.buffer.write(({PRIVATE!r} + chr(10003) + '\\n').encode('utf-8'))\n")
        self.assertIn("auth_process_secret_rejected", output)
        self.assertNotIn(PRIVATE, output)

    def test_zero_exit_without_link_is_not_a_successful_login(self):
        output = self.failed_login("print('ordinary startup output')\n")
        self.assertIn("auth_process_no_url", output)
        self.assertIn("exit_code=0 stdout=present stderr=absent", output)
        self.assertNotIn("auth_login_finished", output)

    def test_known_error_hints_do_not_forward_the_error_text(self):
        cases = (
            ("getaddrinfo ENOTFOUND", "network"),
            ("certificate verification failed", "certificate"),
            ("EACCES permission denied", "permissions"),
            ("error loading shared library", "runtime"),
            ("unknown command", "usage"),
        )
        for text, hint in cases:
            with self.subTest(hint=hint):
                output = self.failed_login(
                    "import sys\n" + f"print({text!r} + ' ' + {PRIVATE!r}, file=sys.stderr)\n" + "sys.exit(1)\n"
                )
                self.assertIn("auth_hint_" + hint, output)

    def test_numeric_diagnostics_never_format_untrusted_objects_or_strings(self):
        events = EventLog()
        report = getattr(events, "auth_process_failure", None)
        self.assertTrue(callable(report), "safe authentication outcome reporting is missing")
        class Hostile:
            def __str__(self):
                raise AssertionError("must never format")
            def __bool__(self):
                raise AssertionError("must never coerce")
        for value in (PRIVATE, Hostile(), True, 2**1024):
            with self.subTest(kind=type(value).__name__):
                with self.assertLogs("proton_backup", level="INFO") as captured:
                    report(failure_kind=value, exit_code=value, stdout_seen=value,
                           stderr_seen=value, stderr_hint=value)
                output = "\n".join(captured.output)
                self.assertNotIn(PRIVATE, output)
                self.assertIn("auth_process_unknown", output)
                self.assertIn("exit_code=unavailable", output)

