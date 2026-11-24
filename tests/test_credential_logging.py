"""Credential setup reports fixed substeps without printing key material."""
import tests
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from proton_backup.credentials import CredentialStore, CredentialStoreError
from proton_backup.models import CommandResult
from tests.test_credentials import FakeCredentialRunner, SafeTestPrivateFilesystem, FINGERPRINT


SECRET = "PRIVATE_CREDENTIAL_DETAIL_MUST_NOT_APPEAR"


class CredentialLoggingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "private"
        self.filesystem = SafeTestPrivateFilesystem(self.root)
        self.runner = FakeCredentialRunner(self.root)

    def test_success_reports_each_substep_without_fingerprint(self):
        store = CredentialStore(self.root, runner=self.runner, filesystem=self.filesystem)
        with self.assertLogs("proton_backup", level="INFO") as captured:
            store.bootstrap()
        output = "\n".join(captured.output)
        for stage in ("startup_credential_paths", "startup_gpg_generate", "startup_gpg_fingerprint",
                      "startup_pass_init", "startup_credential_permissions"):
            self.assertIn(stage + "_ready", output)
        self.assertNotIn(FINGERPRINT, output)
        self.assertNotIn(str(self.root), output)

    def test_subprocess_failures_report_only_the_failing_substep(self):
        cases = (("--quick-generate-key", "startup_gpg_generate_failed"),
                 ("--list-secret-keys", "startup_gpg_fingerprint_failed"),
                 ("init", "startup_pass_init_failed"))
        for marker, code in cases:
            with self.subTest(marker=marker):
                class FailingRunner(FakeCredentialRunner):
                    def run(runner, args, **kwargs):
                        if marker in args:
                            return CommandResult(tuple(args), 2, SECRET, SECRET)
                        return super().run(args, **kwargs)
                store = CredentialStore(self.root, runner=FailingRunner(self.root), filesystem=self.filesystem)
                with self.assertLogs("proton_backup", level="INFO") as captured:
                    with self.assertRaises(CredentialStoreError):
                        store.bootstrap()
                output = "\n".join(captured.output)
                self.assertIn(code, output)
                self.assertNotIn(code.removesuffix("failed") + "ready", output)
                self.assertNotIn(SECRET, output)
                self.assertNotIn(FINGERPRINT, output)

    def test_malformed_fingerprint_is_reported_as_fingerprint_failure(self):
        class MalformedRunner(FakeCredentialRunner):
            def run(runner, args, **kwargs):
                result = super().run(args, **kwargs)
                if "--list-secret-keys" in args:
                    return CommandResult(tuple(args), 0, SECRET, "")
                return result
        store = CredentialStore(self.root, runner=MalformedRunner(self.root), filesystem=self.filesystem)
        with self.assertLogs("proton_backup", level="INFO") as captured:
            with self.assertRaises(CredentialStoreError):
                store.bootstrap()
        output = "\n".join(captured.output)
        self.assertIn("startup_gpg_fingerprint_failed", output)
        self.assertNotIn(SECRET, output)

    def test_permission_failure_never_becomes_a_raw_filesystem_message(self):
        class FailingFilesystem(SafeTestPrivateFilesystem):
            def secure_tree(filesystem):
                raise OSError(SECRET)
        store = CredentialStore(self.root, runner=self.runner, filesystem=FailingFilesystem(self.root))
        with self.assertLogs("proton_backup", level="INFO") as captured:
            with self.assertRaises(CredentialStoreError):
                store.bootstrap()
        output = "\n".join(captured.output)
        self.assertIn("startup_credential_permissions_failed", output)
        self.assertNotIn("startup_credential_permissions_ready", output)
        self.assertNotIn(SECRET, output)

    def test_existing_store_does_not_generate_another_key(self):
        self.filesystem.prepare()
        (self.root / "pass" / ".gpg-id").write_text(FINGERPRINT + "\n", encoding="ascii")
        store = CredentialStore(self.root, runner=self.runner, filesystem=self.filesystem)
        with self.assertLogs("proton_backup", level="INFO") as captured:
            store.bootstrap()
        output = "\n".join(captured.output)
        self.assertIn("startup_credential_existing_ready", output)
        self.assertIn("startup_credential_permissions_ready", output)
        self.assertNotIn("startup_gpg_generate_started", output)
        self.assertEqual(self.runner.calls, [])
        self.assertNotIn(FINGERPRINT, output)
