from __future__ import annotations

import json
import io
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from threading import Event, Thread, Timer
from unittest.mock import patch

APP_ROOT = Path(__file__).resolve().parents[1] / "proton_drive_backup" / "rootfs" / "app"
sys.path.insert(0, str(APP_ROOT))

from proton_backup.process import (
    ProcessExecutionError,
    ProcessRunner,
    active_process_reader_threads,
)
from tests.fakes import python_executable, write_python_script


class ProcessRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp = Path(self.temp_dir.name)
        self.echo_script = write_python_script(
            self.temp,
            "echo_arg.py",
            "import sys\nprint(sys.argv[1])\n",
        )
        self.runner = ProcessRunner()
        self.python = python_executable()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_runner_passes_filename_as_one_argument_without_shell(self):
        injected = "x; touch PWNED"

        previous_cwd = Path.cwd()
        try:
            os.chdir(self.temp)
            result = self.runner.run(
                [self.python, str(self.echo_script), injected],
                timeout=5,
                cancel=Event(),
            )
        finally:
            os.chdir(previous_cwd)

        self.assertIn(injected, result.stdout)
        self.assertEqual(result.args[2:], (injected,))
        self.assertFalse((self.temp / "PWNED").exists())
        self.assertEqual(result.returncode, 0)

    def test_runner_rejects_string_empty_non_string_and_nul_arguments(self):
        invalid_commands = (
            "echo unsafe",
            [],
            [""],
            [self.python, 7],
            [self.python, "bad\0argument"],
        )

        for command in invalid_commands:
            with self.subTest(command=command):
                with self.assertRaisesRegex(ValueError, "Invalid process arguments"):
                    self.runner.run(command, timeout=5, cancel=Event())

    def test_result_redacts_sensitive_argv_and_process_output(self):
        argv_script = write_python_script(
            self.temp,
            "argv.py",
            "import sys\nprint(' '.join(sys.argv[1:]))\n",
        )
        secret = "fake-sensitive-value"
        private_path = "/data/private/process-runner-fixture"

        result = self.runner.run(
            [
                self.python,
                str(argv_script),
                "--password",
                secret,
                "--access-token=also-fake",
                private_path,
                "visible",
            ],
            timeout=5,
            cancel=Event(),
        )

        combined = " ".join(result.args[2:]) + result.stdout + result.stderr
        self.assertNotIn(secret, combined)
        self.assertNotIn("also-fake", combined)
        self.assertNotIn(private_path, combined)
        self.assertIn("visible", combined)
        self.assertIn("[REDACTED]", combined)

    def test_sensitive_argv_forces_non_reversible_output_redaction(self):
        transformed_script = write_python_script(
            self.temp,
            "transformed_secret.py",
            "import json, sys, urllib.parse\n"
            "secret = sys.argv[2]\n"
            "print(secret.upper(), json.dumps(secret), urllib.parse.quote(secret))\n",
        )
        secret = "MiXeD secret/value"
        received = []

        result = self.runner.run(
            [self.python, str(transformed_script), "--password", secret],
            timeout=5,
            cancel=Event(),
            on_stdout_line=received.append,
        )

        self.assertEqual(result.stdout, "[REDACTED]")
        self.assertEqual(received, ["[REDACTED]"])
        combined = " ".join(result.args[2:]) + result.stdout + " ".join(received)
        for forbidden in ("MiXeD", "MIXED", "secret", "%20", "%2F", "value"):
            self.assertNotIn(forbidden, combined)

    def test_runner_passes_only_allowlisted_environment_with_private_home(self):
        environment_script = write_python_script(
            self.temp,
            "environment.py",
            "import json, os\n"
            "expected = {\n"
            " 'GNUPGHOME': '/data/private/custom-gnupg',\n"
            " 'HOME': '/data/private/home',\n"
            " 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',\n"
            " 'PASSWORD_STORE_DIR': '/data/private/custom-pass',\n"
            " 'PROTON_DRIVE_CACHE_DIR': '/data/private/custom-proton',\n"
            " 'PROTON_DRIVE_CREDENTIALS_STORE': 'pass',\n"
            " 'PROTON_DRIVE_LOG_LEVEL': 'ERROR'}\n"
            "print(json.dumps({\n"
            " 'values_are_safe': all(os.environ.get(k) == v for k, v in expected.items()),\n"
            " 'unrelated_inherited': 'UNRELATED_TOKEN' in os.environ}))\n",
        )
        source_environment = {
            "PATH": os.environ.get("PATH", ""),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "HOME": "C:\\Users\\private-user",
            "GNUPGHOME": "/data/private/custom-gnupg",
            "PASSWORD_STORE_DIR": "/data/private/custom-pass",
            "PROTON_DRIVE_CREDENTIALS_STORE": "pass",
            "PROTON_DRIVE_CACHE_DIR": "/data/private/custom-proton",
            "PROTON_DRIVE_LOG_LEVEL": "ERROR",
            "UNRELATED_TOKEN": "must-not-be-inherited",
        }
        runner = ProcessRunner(environment=source_environment)

        result = runner.run(
            [self.python, str(environment_script)],
            timeout=5,
            cancel=Event(),
        )

        self.assertEqual(
            json.loads(result.stdout),
            {"values_are_safe": True, "unrelated_inherited": False},
        )
        self.assertNotIn("must-not-be-inherited", result.stdout)
        self.assertNotIn("/data/private", result.stdout)

    def test_runner_replaces_unsafe_credential_environment_values(self):
        environment_script = write_python_script(
            self.temp,
            "selected_environment.py",
            "import json, os\n"
            "expected = {'HOME': '/data/private/home', "
            "'GNUPGHOME': '/data/private/gnupg', "
            "'PASSWORD_STORE_DIR': '/data/private/pass', "
            "'PROTON_DRIVE_CREDENTIALS_STORE': 'pass', "
            "'PROTON_DRIVE_CACHE_DIR': '/data/private/proton'}\n"
            "print(json.dumps({'values_are_safe': "
            "all(os.environ.get(k) == v for k, v in expected.items())}))\n",
        )
        runner = ProcessRunner(
            environment={
                "PATH": os.environ.get("PATH", ""),
                "HOME": "/home/outside",
                "GNUPGHOME": "/tmp/gnupg",
                "PASSWORD_STORE_DIR": "/tmp/pass",
                "PROTON_DRIVE_CREDENTIALS_STORE": "unsafe_file",
                "PROTON_DRIVE_CACHE_DIR": "/tmp/proton",
            }
        )

        result = runner.run(
            [self.python, str(environment_script)],
            timeout=5,
            cancel=Event(),
        )

        self.assertEqual(
            json.loads(result.stdout),
            {"values_are_safe": True},
        )
        self.assertNotIn("/data/private", result.stdout)

    def test_runner_excludes_unapproved_lc_environment_names(self):
        locale_script = write_python_script(
            self.temp,
            "locale_environment.py",
            "import json, os\n"
            "approved = ('LANG', 'LANGUAGE', 'LC_ALL', 'LC_CTYPE')\n"
            "forbidden = ('LC_PASSWORD', 'LC_TOKEN', 'LC_MESSAGES')\n"
            "print(json.dumps({\n"
            " 'approved_present': all(name in os.environ for name in approved),\n"
            " 'forbidden_present': any(name in os.environ for name in forbidden)}))\n",
        )
        runner = ProcessRunner(
            environment={
                "PATH": os.environ.get("PATH", ""),
                "LANG": "C.UTF-8",
                "LANGUAGE": "de",
                "LC_ALL": "C.UTF-8",
                "LC_CTYPE": "C.UTF-8",
                "LC_PASSWORD": "locale-password-secret",
                "LC_TOKEN": "locale-token-secret",
                "LC_MESSAGES": "C.UTF-8",
            }
        )

        result = runner.run(
            [self.python, str(locale_script)], timeout=5, cancel=Event()
        )

        self.assertEqual(
            json.loads(result.stdout),
            {"approved_present": True, "forbidden_present": False},
        )
        self.assertNotIn("locale-password-secret", result.stdout)
        self.assertNotIn("locale-token-secret", result.stdout)

    def test_stdout_callback_never_receives_raw_secrets_or_private_paths(self):
        callback_script = write_python_script(
            self.temp,
            "callback_secrets.py",
            "import sys, time\n"
            "chunks = [\n"
            " 'Authorization: Bearer callback-', 'secret\\n',\n"
            " ' continued-secret\\n',\n"
            " 'Cookie: SID=cookie-secret\\n', ' folded-cookie\\n',\n"
            " '/data/private/pass /home/alice/private ',\n"
            " 'C:\\\\Users\\\\Alice\\\\private\\n',\n"
            " 'https://account.proton.me/%61uth?token=url-secret\\n']\n"
            "for chunk in chunks:\n"
            " sys.stdout.write(chunk); sys.stdout.flush(); time.sleep(0.01)\n",
        )
        received = []

        self.runner.run(
            [self.python, str(callback_script)],
            timeout=5,
            cancel=Event(),
            on_stdout_line=received.append,
        )

        callback_text = "\n".join(received)
        for forbidden in (
            "callback-secret",
            "continued-secret",
            "cookie-secret",
            "folded-cookie",
            "/data/private",
            "/home/alice",
            "C:\\Users\\Alice",
            "account.proton.me",
            "url-secret",
        ):
            self.assertNotIn(forbidden, callback_text)
        self.assertIn("[REDACTED]", callback_text)

    def test_timeout_terminates_process_and_returns_safe_result(self):
        sleeping_script = write_python_script(
            self.temp,
            "sleep.py",
            "import time\nprint('started', flush=True)\ntime.sleep(3)\n",
        )
        started_at = time.monotonic()

        result = self.runner.run(
            [self.python, str(sleeping_script)], timeout=1, cancel=Event()
        )

        self.assertLess(time.monotonic() - started_at, 5)
        self.assertTrue(result.timed_out)
        self.assertFalse(result.cancelled)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("started", result.stdout)

    @unittest.skipUnless(os.name == "nt", "Windows teardown behavior")
    def test_windows_teardown_contains_taskkill_spawn_and_timeout_failures(self):
        sleeping_script = write_python_script(
            self.temp,
            "teardown_failure.py",
            "import time\nprint('started', flush=True)\ntime.sleep(5)\n",
        )
        failures = (
            OSError("taskkill-spawn-secret"),
            subprocess.TimeoutExpired("taskkill-timeout-secret", 1),
        )

        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                with patch(
                    "proton_backup.process.subprocess.run", side_effect=failure
                ):
                    result = self.runner.run(
                        [self.python, str(sleeping_script)],
                        timeout=1,
                        cancel=Event(),
                    )

                self.assertTrue(result.timed_out)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("secret", result.stdout + result.stderr)

    @unittest.skipIf(os.name == "nt", "POSIX teardown behavior")
    def test_posix_teardown_contains_permission_errors_and_reaps_leader(self):
        sleeping_script = write_python_script(
            self.temp,
            "posix_teardown_failure.py",
            "import time\nprint('started', flush=True)\ntime.sleep(5)\n",
        )

        with patch(
            "proton_backup.process.os.killpg",
            side_effect=PermissionError("killpg-permission-secret"),
        ):
            started_at = time.monotonic()
            result = self.runner.run(
                [self.python, str(sleeping_script)], timeout=1, cancel=Event()
            )

        self.assertTrue(result.timed_out)
        self.assertLess(time.monotonic() - started_at, 4)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("secret", result.stdout + result.stderr)

    def test_cancellation_terminates_process_and_returns_safe_result(self):
        sleeping_script = write_python_script(
            self.temp,
            "cancel.py",
            "import time\nprint('started', flush=True)\ntime.sleep(3)\n",
        )
        cancel = Event()
        timer = Timer(0.2, cancel.set)
        timer.start()
        started_at = time.monotonic()
        try:
            result = self.runner.run(
                [self.python, str(sleeping_script)], timeout=10, cancel=cancel
            )
        finally:
            timer.cancel()

        self.assertLess(time.monotonic() - started_at, 1.5)
        self.assertFalse(result.timed_out)
        self.assertTrue(result.cancelled)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("started", result.stdout)

    @unittest.skipIf(os.name == "nt", "POSIX process-group behavior")
    def test_timeout_terminates_descendant_processes(self):
        marker = self.temp / "descendant-survived"
        child_code = (
            "import pathlib,time;time.sleep(2);"
            f"pathlib.Path({str(marker)!r}).write_text('survived')"
        )
        parent_script = write_python_script(
            self.temp,
            "parent.py",
            "import subprocess, sys, time\n"
            "child = subprocess.Popen([sys.argv[1], '-c', sys.argv[2]])\n"
            "print(child.pid, flush=True)\n"
            "time.sleep(4)\n",
        )

        result = self.runner.run(
            [self.python, str(parent_script), self.python, child_code],
            timeout=1,
            cancel=Event(),
        )
        time.sleep(2.0)

        self.assertTrue(result.timed_out)
        self.assertFalse(marker.exists())

    @unittest.skipIf(os.name == "nt", "POSIX process-group behavior")
    def test_timeout_still_governs_pipes_after_leader_exits(self):
        marker = self.temp / "orphan-descendant-survived"
        child_code = (
            "import pathlib,time;time.sleep(2);"
            f"pathlib.Path({str(marker)!r}).write_text('survived')"
        )
        parent_script = write_python_script(
            self.temp,
            "exiting_parent.py",
            "import subprocess, sys\n"
            "subprocess.Popen([sys.argv[1], '-c', sys.argv[2]])\n",
        )
        started_at = time.monotonic()

        result = self.runner.run(
            [self.python, str(parent_script), self.python, child_code],
            timeout=1,
            cancel=Event(),
        )
        time.sleep(1.2)

        self.assertTrue(result.timed_out)
        self.assertLess(time.monotonic() - started_at, 3)
        self.assertFalse(marker.exists())

    def test_runner_bounds_and_decodes_stdout_and_stderr(self):
        output_script = write_python_script(
            self.temp,
            "large_output.py",
            "import sys\n"
            "sys.stdout.buffer.write(b'out\\xff' + b'x' * 3000000)\n"
            "sys.stderr.buffer.write(b'err\\xfe' + b'y' * 100000)\n",
        )

        result = self.runner.run(
            [self.python, str(output_script)], timeout=5, cancel=Event()
        )

        self.assertLessEqual(len(result.stdout), 2_097_152)
        self.assertLessEqual(len(result.stderr), 16_400)
        self.assertIn("out\ufffd", result.stdout)
        self.assertIn("err\ufffd", result.stderr)
        self.assertTrue(result.stdout.endswith("[TRUNCATED]"))
        self.assertTrue(result.stderr.endswith("[TRUNCATED]"))

    def test_runner_streams_complete_stdout_lines(self):
        lines_script = write_python_script(
            self.temp,
            "lines.py",
            "import sys\nsys.stdout.buffer.write(b'first\\r\\nsecond')\n",
        )
        received = []

        result = self.runner.run(
            [self.python, str(lines_script)],
            timeout=5,
            cancel=Event(),
            on_stdout_line=received.append,
        )

        self.assertEqual(received, ["first", "second"])
        self.assertEqual(result.stdout, "first\nsecond")

    def test_runner_delivers_flushed_short_callback_line_promptly(self):
        prompt_script = write_python_script(
            self.temp,
            "prompt_line.py",
            "import time\nprint('ready', flush=True)\ntime.sleep(5)\n",
        )
        callback_received = Event()
        cancel = Event()

        def on_line(line):
            if line == "ready":
                callback_received.set()

        runner_thread = Thread(
            target=self.runner.run,
            kwargs={
                "args": [self.python, str(prompt_script)],
                "timeout": 10,
                "cancel": cancel,
                "on_stdout_line": on_line,
            },
        )
        runner_thread.start()
        delivered_promptly = callback_received.wait(0.5)
        cancel.set()
        runner_thread.join(3)

        self.assertTrue(delivered_promptly)
        self.assertFalse(runner_thread.is_alive())

    def test_noncooperative_pipe_reader_cleanup_is_bounded_and_tracked(self):
        read_descriptor, write_descriptor = os.pipe()
        pipe_stream = open(
            read_descriptor,
            "r",
            encoding="utf-8",
            errors="replace",
            closefd=True,
        )

        class ExitedProcess:
            pid = 12345
            stdout = pipe_stream
            stderr = io.StringIO("")

            @staticmethod
            def poll():
                return 0

        started_at = time.monotonic()
        try:
            with patch("proton_backup.process.subprocess.Popen", return_value=ExitedProcess()):
                with patch("proton_backup.process._terminate_process_group", return_value=True):
                    with self.assertRaisesRegex(
                        ProcessExecutionError, "Unable to clean up process"
                    ):
                        self.runner.run(
                            [self.python, str(self.echo_script), "safe"],
                            timeout=1,
                            cancel=Event(),
                        )
            self.assertLess(time.monotonic() - started_at, 4)
            self.assertTrue(
                any(
                    reader.name == "process-stdout"
                    for reader in active_process_reader_threads()
                )
            )
        finally:
            os.close(write_descriptor)
            deadline = time.monotonic() + 1
            while active_process_reader_threads() and time.monotonic() < deadline:
                Event().wait(0.01)
        self.assertEqual(active_process_reader_threads(), ())

    def _secret_event(self, consumer):
        try:
            from proton_backup.process import ProtonLoginSecretEvent
        except ImportError as error:
            self.fail(f"Proton login secret event boundary is missing: {error}")
        return ProtonLoginSecretEvent(
            consumer,
            expires_at=time.monotonic() + 5,
        )

    def test_secret_event_is_delivered_once_while_all_ordinary_output_is_redacted(self):
        secret_value = "https://account.proton.me/login?token=fake-one-shot-value"
        secret_script = write_python_script(
            self.temp,
            "secret_event.py",
            "import sys\n"
            f"print({secret_value!r}, flush=True)\n"
            "print('unsafe stderr context', file=sys.stderr, flush=True)\n",
        )
        received_secret = []
        received_ordinary = []
        channel = self._secret_event(received_secret.append)

        result = self.runner.run(
            [self.python, str(secret_script)],
            timeout=5,
            cancel=Event(),
            on_stdout_line=received_ordinary.append,
            secret_event=channel,
        )

        self.assertEqual(len(received_secret), 1)
        self.assertTrue(received_secret[0].startswith("https://account.proton.me/"))
        self.assertEqual(received_ordinary, ["[REDACTED]"])
        self.assertEqual(result.stdout, "[REDACTED]")
        self.assertEqual(result.stderr, "[REDACTED]")
        self.assertNotIn("fake-one-shot-value", result.stdout + result.stderr)
        self.assertNotIn("account.proton.me", result.stdout + result.stderr)

    def test_secret_event_consumer_failure_terminates_process_with_neutral_error(self):
        secret_value = "https://account.proton.me/login?token=fake-consumer-value"
        sleeping_script = write_python_script(
            self.temp,
            "secret_consumer_failure.py",
            f"import time\nprint({secret_value!r}, flush=True)\ntime.sleep(5)\n",
        )

        def failing_consumer(value):
            raise RuntimeError(value)

        channel = self._secret_event(failing_consumer)
        started_at = time.monotonic()

        with self.assertRaises(ProcessExecutionError) as raised:
            self.runner.run(
                [self.python, str(sleeping_script)],
                timeout=10,
                cancel=Event(),
                secret_event=channel,
            )

        self.assertLess(time.monotonic() - started_at, 1.5)
        self.assertEqual(str(raised.exception), "Unable to process secret event")
        self.assertNotIn("fake-consumer-value", str(raised.exception))
        self.assertNotIn("account.proton.me", str(raised.exception))

    def test_secret_event_run_fails_closed_when_no_event_is_extracted(self):
        script = write_python_script(
            self.temp,
            "missing_secret_event.py",
            "print('ordinary output')\n",
        )
        channel = self._secret_event(lambda value: None)

        with self.assertRaisesRegex(
            ProcessExecutionError, "Unable to process secret event"
        ):
            self.runner.run(
                [self.python, str(script)],
                timeout=5,
                cancel=Event(),
                secret_event=channel,
            )

    def test_secret_event_run_preserves_cancellation_before_an_event(self):
        script = write_python_script(
            self.temp,
            "cancel_before_secret.py",
            "import time\ntime.sleep(5)\n",
        )
        channel = self._secret_event(lambda value: None)
        cancel = Event()
        timer = Timer(0.2, cancel.set)
        timer.start()
        try:
            result = self.runner.run(
                [self.python, str(script)],
                timeout=10,
                cancel=cancel,
                secret_event=channel,
            )
        finally:
            timer.cancel()

        self.assertTrue(result.cancelled)
        self.assertFalse(result.timed_out)
        self.assertEqual(result.stdout, "")

    def test_rejected_login_link_terminates_process_with_neutral_error(self):
        rejected_value = "http://account.proton.me/login?token=fake-rejected-value"
        sleeping_script = write_python_script(
            self.temp,
            "rejected_login_link.py",
            f"import time\nprint({rejected_value!r}, flush=True)\ntime.sleep(5)\n",
        )
        channel = self._secret_event(lambda value: None)
        started_at = time.monotonic()

        with self.assertRaises(ProcessExecutionError) as raised:
            self.runner.run(
                [self.python, str(sleeping_script)],
                timeout=10,
                cancel=Event(),
                secret_event=channel,
            )

        self.assertLess(time.monotonic() - started_at, 1.5)
        self.assertEqual(str(raised.exception), "Unable to process secret event")
        self.assertNotIn("fake-rejected-value", str(raised.exception))

    def test_login_secret_event_accepts_url_at_exact_length_boundary(self):
        prefix = "https://account.proton.me/login?token="
        secret_value = prefix + "x" * (4096 - len(prefix))
        script = write_python_script(
            self.temp,
            "maximum_login_link.py",
            f"print('Open ' + {secret_value!r}, flush=True)\n",
        )
        received = []

        result = self.runner.run(
            [self.python, str(script)],
            timeout=5,
            cancel=Event(),
            secret_event=self._secret_event(received.append),
        )

        self.assertEqual(len(received), 1)
        self.assertEqual(len(received[0]), 4096)
        self.assertEqual(result.stdout, "[REDACTED]")

    def test_runner_rejects_arbitrary_or_subclassed_secret_inspector_before_spawn(self):
        from proton_backup.process import ProtonLoginSecretEvent

        class ArbitraryInspector:
            def inspect(self, raw_line, *, truncated=False):
                raise AssertionError("must not inspect")

            def finish(self):
                raise AssertionError("must not finish")

        class SubclassedLoginEvent(ProtonLoginSecretEvent):
            pass

        candidates = (
            ArbitraryInspector(),
            SubclassedLoginEvent(
                lambda value: None,
                expires_at=time.monotonic() + 5,
            ),
        )
        for candidate in candidates:
            with self.subTest(kind=type(candidate).__name__):
                with patch("proton_backup.process.subprocess.Popen") as popen:
                    with self.assertRaisesRegex(ValueError, "Invalid secret event"):
                        self.runner.run(
                            [self.python, str(self.echo_script), "safe"],
                            timeout=5,
                            cancel=Event(),
                            secret_event=candidate,
                        )
                popen.assert_not_called()

    def test_login_secret_event_rejects_malformed_or_unsafe_percent_encoding(self):
        cases = (
            "https://account.proton.me/login?state=%0Aunsafe",
            "https://account.proton.me/login?state=%00unsafe",
            "https://account.proton.me/login?state=%250Aunsafe",
            "https://account.proton.me/login?state=%ZZ",
            "https://account.proton.me/log%69n?state=safe",
            "https://account.proton.me%40attacker.invalid/login?state=safe",
        )
        for index, rejected_value in enumerate(cases):
            with self.subTest(index=index):
                script = write_python_script(
                    self.temp,
                    f"encoded_login_{index}.py",
                    f"print({rejected_value!r}, flush=True)\n",
                )
                received = []
                with self.assertRaisesRegex(
                    ProcessExecutionError, "Unable to process secret event"
                ):
                    self.runner.run(
                        [self.python, str(script)],
                        timeout=5,
                        cancel=Event(),
                        secret_event=self._secret_event(received.append),
                    )
                self.assertEqual(received, [])

    def test_login_secret_event_treats_exact_expiry_instant_as_expired(self):
        from proton_backup.process import ProtonLoginSecretEvent

        clock = [100.0]
        received = []
        channel = ProtonLoginSecretEvent(
            received.append,
            expires_at=101.0,
            monotonic=lambda: clock[0],
        )
        clock[0] = 101.0
        script = write_python_script(
            self.temp,
            "exactly_expired_login.py",
            "print('https://account.proton.me/login?state=safe', flush=True)\n",
        )

        with self.assertRaisesRegex(
            ProcessExecutionError, "Unable to process secret event"
        ):
            self.runner.run(
                [self.python, str(script)],
                timeout=5,
                cancel=Event(),
                secret_event=channel,
            )
        self.assertEqual(received, [])

    def test_spawn_failure_raises_neutral_error_without_command_details(self):
        secret = "fake-sensitive-spawn-value"

        with self.assertRaises(ProcessExecutionError) as raised:
            self.runner.run(
                [str(self.temp / "missing-program"), "--password", secret],
                timeout=5,
                cancel=Event(),
            )

        self.assertEqual(str(raised.exception), "Unable to start process")
        self.assertNotIn(secret, str(raised.exception))

    def test_runner_rejects_non_positive_timeout_before_spawning(self):
        for timeout in (0, -1):
            with self.subTest(timeout=timeout):
                with self.assertRaisesRegex(ValueError, "Invalid process timeout"):
                    self.runner.run(
                        [self.python, str(self.echo_script), "safe"],
                        timeout=timeout,
                        cancel=Event(),
                    )


if __name__ == "__main__":
    unittest.main()
