import io
import logging
import os
import subprocess
import sys
import unittest
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parents[1] / "proton_drive_backup" / "rootfs" / "app"
sys.path.insert(0, str(APP_ROOT))

from proton_backup.redaction import SafeLogger, redact


class RedactionTests(unittest.TestCase):
    def test_long_header_whitespace_cannot_stall_machine_data_redaction(self):
        program = (
            "from proton_backup.redaction import redact; "
            "cases=['Authorization: Bearer '+' '*32768+'private_marker',"
            "'Authorization:'+' '*32768+'private_marker']; "
            "assert all('private_marker' not in redact(x,max_chars=2097152) for x in cases); print('OK')"
        )
        result = subprocess.run([sys.executable, "-c", program], capture_output=True,
                                text=True, timeout=3,
                                env={**os.environ, "PYTHONPATH": str(APP_ROOT)})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "OK")

    def test_redacts_tokens_headers_cookies_and_login_urls(self):
        raw = (
            "Authorization: Bearer abc Cookie: UID=secret "
            "https://account.proton.me/auth?token=xyz"
        )

        safe = redact(raw)

        for forbidden in ("abc", "secret", "token=xyz"):
            self.assertNotIn(forbidden, safe)
        self.assertIn("[REDACTED]", safe)

    def test_redacts_case_insensitive_headers_and_sensitive_json_fields(self):
        raw = """aUtHoRiZaTiOn: Basic ZmFrZQ==
cOoKiE: SID=fake-cookie
{"token":"one","accessToken":"two","refresh_token":"three",
 "COOKIE":"four","Authorization":"Bearer five","ordinary":"visible"}"""

        safe = redact(raw)

        for forbidden in (
            "ZmFrZQ==",
            "fake-cookie",
            '"one"',
            '"two"',
            '"three"',
            '"four"',
            "Bearer five",
        ):
            self.assertNotIn(forbidden, safe)
        self.assertIn('"ordinary":"visible"', safe)

    def test_redacts_headers_embedded_in_cli_error_text(self):
        raw = "request failed: aUtHoRiZaTiOn: Bearer embedded-secret"

        safe = redact(raw)

        self.assertIn("request failed:", safe)
        self.assertNotIn("embedded-secret", safe)
        self.assertIn("[REDACTED]", safe)

    def test_removes_url_queries_fragments_and_entire_login_urls(self):
        raw = (
            "See https://example.invalid/path?access_token=fake#private and "
            "https://account.proton.me/auth/login?token=challenge#fragment"
        )

        safe = redact(raw)

        self.assertIn("https://example.invalid/path", safe)
        for forbidden in (
            "access_token=fake",
            "#private",
            "account.proton.me",
            "challenge",
            "#fragment",
        ):
            self.assertNotIn(forbidden, safe)

    def test_redacts_url_userinfo_and_percent_encoded_proton_login_paths(self):
        raw = (
            "https://url-user:url-password@example.invalid/path?query=private "
            "https://account.proton.me/%61uth/%6Cogin?token=url-token"
        )

        safe = redact(raw)

        for forbidden in (
            "url-user",
            "url-password",
            "query=private",
            "account.proton.me",
            "%61uth",
            "%6Cogin",
            "url-token",
        ):
            self.assertNotIn(forbidden, safe)
        self.assertGreaterEqual(safe.count("[REDACTED]"), 2)

    def test_redacts_folded_authorization_and_cookie_continuations(self):
        raw = (
            "Authorization: Bearer first-part\r\n"
            " second-part\n"
            "Cookie: UID=cookie-part\n"
            " folded-cookie-part\n"
            "ordinary: visible"
        )

        safe = redact(raw)

        for forbidden in (
            "first-part",
            "second-part",
            "cookie-part",
            "folded-cookie-part",
        ):
            self.assertNotIn(forbidden, safe)
        self.assertIn("ordinary: visible", safe)

    def test_redacts_passwords_home_paths_and_credentials_store_paths(self):
        raw = (
            'password="fake-pass" passphrase: fake-phrase otp=123456 '
            "/home/alice/private.txt C:\\Users\\Alice\\secret.txt "
            "/data/private/pass/session /data/private/gnupg/private-keys-v1.d/key "
            "/data/private/proton/cache.json"
        )

        safe = redact(raw)

        for forbidden in (
            "fake-pass",
            "fake-phrase",
            "123456",
            "/home/alice",
            "C:\\Users\\Alice",
            "/data/private/pass",
            "/data/private/gnupg",
            "/data/private/proton",
        ):
            self.assertNotIn(forbidden, safe)

    def test_bounds_redacted_output(self):
        safe = redact("x" * 100_000)

        self.assertLessEqual(len(safe), 16_400)
        self.assertTrue(safe.endswith("[TRUNCATED]"))

    def test_safe_logger_formats_then_redacts_without_leaking_login_url(self):
        stream = io.StringIO()
        logger = logging.Logger("redaction-test")
        logger.addHandler(logging.StreamHandler(stream))
        safe_logger = SafeLogger(logger)
        login_url = "https://account.proton.me/auth/login?token=one-time"

        safe_logger.info("Login URL: %s", login_url)

        output = stream.getvalue()
        self.assertIn("Login URL: [REDACTED]", output)
        self.assertNotIn(login_url, output)
        self.assertNotIn("one-time", output)

    def test_safe_logger_contains_custom_string_and_formatting_failures(self):
        class UnsafeString:
            def __str__(self):
                raise RuntimeError("custom-string-secret")

        stream = io.StringIO()
        logger = logging.Logger("redaction-exception-test")
        logger.addHandler(logging.StreamHandler(stream))
        safe_logger = SafeLogger(logger)

        safe_logger.info("unsafe value: %s", UnsafeString())
        safe_logger.info("broken format %s %s", "one")

        output = stream.getvalue()
        self.assertEqual(
            output.splitlines(),
            ["Unable to safely format log message"] * 2,
        )
        self.assertNotIn("custom-string-secret", output)


if __name__ == "__main__":
    unittest.main()
