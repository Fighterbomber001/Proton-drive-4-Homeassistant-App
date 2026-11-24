"""Pinned CLI 0.7.0 desktop sign-in links stay private and reach their owner."""
import tests
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
import time
import unittest

from proton_backup.process import ProcessRunner, ProtonLoginSecretEvent, _SecretEventError
from proton_backup.redaction import redact
from proton_backup.web import ControlAction, ControlCommand, LoginUrlBroker
from tests.fakes import python_executable, write_python_script
from tests.test_proton_cli import FakeCliRunner
from proton_backup.proton_cli import ProtonDriveClient, ProtonCliError


# Synthetic fork values, shaped after the pinned official CLI's URL builder.
# Not a real login URL: its random-key field represents 32 zero bytes.
DESKTOP_URL = (
    "https://account.proton.me/desktop/login?app=drive&pv=3#payload="
    "0%3AFakeUserCode123%3A"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D%3Acli-drive"
)


class DesktopLoginContractTests(unittest.TestCase):
    def test_actual_stdout_shape_delivers_url_without_result_or_callback_leak(self):
        with TemporaryDirectory() as temporary:
            script = write_python_script(
                Path(temporary), "desktop_signin.py",
                "import sys\n"
                "print('Sign in in your browser. Keep the terminal open. Waiting for authentication to complete...', flush=True)\n"
                "print('Open following URL manually (can be on another device) if browser did not open automatically:', flush=True)\n"
                f"print({DESKTOP_URL!r}, flush=True)\n"
                "print('PRIVATE_STDERR_SENTINEL', file=sys.stderr, flush=True)\n",
            )
            secret, ordinary = [], []
            channel = ProtonLoginSecretEvent(secret.append, expires_at=time.monotonic() + 5)
            try:
                result = ProcessRunner().run(
                    [python_executable(), str(script)], timeout=5, cancel=Event(),
                    on_stdout_line=ordinary.append, secret_event=channel,
                )
            except Exception as error:
                self.fail(f"Official desktop-login URL was rejected: {type(error).__name__}")
        self.assertEqual(secret, [DESKTOP_URL])
        self.assertEqual(result.returncode, 0)
        self.assertEqual(ordinary, ["[REDACTED]"] * 3)
        self.assertEqual(result.stdout, "[REDACTED]")
        self.assertEqual(result.stderr, "[REDACTED]")

    def test_desktop_link_is_handed_off_once_only_to_requesting_user(self):
        broker = LoginUrlBroker(monotonic=lambda: 10.0)
        command = ControlCommand("d" * 32, ControlAction.CONNECT, "operator-a")
        channel = ProtonLoginSecretEvent(broker.begin(command), expires_at=70.0, monotonic=lambda: 10.0)
        try:
            channel.inspect(DESKTOP_URL)
            channel.finish()
        except Exception as error:
            self.fail(f"Official desktop-login handoff was rejected: {type(error).__name__}")
        self.assertIsNone(broker.consume("operator-b"))
        self.assertEqual(broker.consume("operator-a").url, DESKTOP_URL)
        self.assertIsNone(broker.consume("operator-a"))

    def test_percent_encoded_base64_key_is_preserved_unchanged(self):
        value = DESKTOP_URL.replace("A" * 43 + "%3D", "%2F" * 42 + "8%3D")
        received = []
        channel = ProtonLoginSecretEvent(received.append, expires_at=70.0, monotonic=lambda: 10.0)
        try:
            channel.inspect(value)
            channel.finish()
        except Exception as error:
            self.fail(f"Encoded 32-byte key was rejected: {type(error).__name__}")
        self.assertEqual(received, [value])

    def test_desktop_fragment_is_not_a_general_fragment_exception(self):
        cases = (
            DESKTOP_URL.replace("https:", "http:"),
            DESKTOP_URL.replace("account.proton.me", "account.proton.me.attacker.invalid"),
            DESKTOP_URL.replace("account.proton.me", "drive.proton.me"),
            DESKTOP_URL.replace("account.proton.me", "user@account.proton.me"),
            DESKTOP_URL.replace("account.proton.me", "account.proton.me:8443"),
            DESKTOP_URL.replace("/desktop/login", "/login"),
            DESKTOP_URL.replace("/desktop/login", "/desktop/log%69n"),
            DESKTOP_URL.replace("app=drive", "app=mail"),
            DESKTOP_URL.replace("pv=3", "pv=4"),
            DESKTOP_URL.replace("#payload=", "&redirect=https://attacker.invalid#payload="),
            DESKTOP_URL.replace("#payload=", "#other="),
            DESKTOP_URL.split("#")[0],
            DESKTOP_URL.split("#")[0] + "#payload=",
            DESKTOP_URL.replace("FakeUserCode123", "Fake%0AUserCode123"),
            DESKTOP_URL.replace("FakeUserCode123", "Fake%250AUserCode123"),
            DESKTOP_URL.replace("%3A", "%ZZ", 1),
            DESKTOP_URL.replace("0%3A", "1%3A", 1),
            DESKTOP_URL.replace("cli-drive", "attacker-app"),
            DESKTOP_URL + "&redirect=attacker.invalid",
        )
        for index, value in enumerate(cases):
            received = []
            channel = ProtonLoginSecretEvent(received.append, expires_at=70.0, monotonic=lambda: 10.0)
            with self.subTest(index=index), self.assertRaises(_SecretEventError):
                channel.inspect(value)
            self.assertEqual(received, [])

    def test_redaction_removes_the_entire_desktop_login_link(self):
        self.assertEqual(redact("Open " + DESKTOP_URL), "Open [REDACTED]")

    def test_login_progress_is_logged_without_the_link_or_payload(self):
        client = ProtonDriveClient(runner=FakeCliRunner(login_lines=(DESKTOP_URL,)))
        received = []
        with self.assertLogs("proton_backup", level="INFO") as captured:
            client.start_login(received.append, Event())
        output = "\n".join(captured.output)
        self.assertEqual(received, [DESKTOP_URL])
        self.assertIn("auth_login_started", output)
        self.assertIn("auth_login_link_ready", output)
        self.assertIn("auth_login_finished", output)
        self.assertNotIn("auth_login_failed", output)
        for forbidden in (DESKTOP_URL, "FakeUserCode123", "#payload=", "account.proton.me"):
            self.assertNotIn(forbidden, output)

    def test_rejected_link_reports_failure_without_false_ready(self):
        rejected = DESKTOP_URL.replace("account.proton.me", "attacker.invalid")
        client = ProtonDriveClient(runner=FakeCliRunner(login_lines=(rejected,)))
        with self.assertLogs("proton_backup", level="INFO") as captured:
            with self.assertRaises(ProtonCliError):
                client.start_login(lambda _url: self.fail("must not deliver"), Event())
        output = "\n".join(captured.output)
        self.assertIn("ERROR:proton_backup.proton_cli:auth_login_failed", output)
        self.assertNotIn("auth_login_link_ready", output)
        self.assertNotIn("auth_login_finished", output)
        self.assertNotIn("FakeUserCode123", output)
        self.assertNotIn("attacker.invalid", output)

