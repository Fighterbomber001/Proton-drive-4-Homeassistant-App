from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path
import sys
from unittest.mock import patch

APP_ROOT = Path(__file__).resolve().parents[1] / "proton_drive_backup" / "rootfs" / "app"
sys.path.insert(0, str(APP_ROOT))

from proton_backup.models import CommandResult


FINGERPRINT = "0123456789ABCDEF0123456789ABCDEF01234567"


class SafeTestPrivateFilesystem:
    def __init__(self, root: Path):
        self.root = root
        self.chmod_calls: list[tuple[Path, int]] = []
        self.broken_gpg_id = False
        self.swap_on_read = False
        self.swap_on_remove = False
        self.invalid_root = False

    def prepare(self):
        from proton_backup.credentials import CredentialStoreError

        if self.invalid_root:
            raise CredentialStoreError("Unable to initialize credential store")
        self.root.mkdir(parents=True, exist_ok=True)
        self._chmod(self.root, 0o700)
        for name in ("gnupg", "pass", "home", "proton"):
            directory = self.root / name
            directory.mkdir(exist_ok=True)
            self._chmod(directory, 0o700)

    def verify(self):
        from proton_backup.credentials import CredentialStoreError

        if self.invalid_root:
            raise CredentialStoreError("Unable to initialize credential store")

    def gpg_id_exists(self):
        from proton_backup.credentials import CredentialStoreError

        if self.broken_gpg_id:
            raise CredentialStoreError("Unable to initialize credential store")
        path = self.root / "pass" / ".gpg-id"
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            return False
        if not path.is_file() or path.is_symlink():
            raise CredentialStoreError("Unable to initialize credential store")
        return metadata.st_size >= 0

    def read_gpg_id(self):
        from proton_backup.credentials import CredentialStoreError

        if self.swap_on_read:
            raise CredentialStoreError("Unable to initialize credential store")
        path = self.root / "pass" / ".gpg-id"
        before = path.lstat()
        if path.is_symlink() or not path.is_file():
            raise CredentialStoreError("Unable to initialize credential store")
        value = path.read_text(encoding="ascii")
        after = path.lstat()
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise CredentialStoreError("Unable to initialize credential store")
        self._chmod(path, 0o600)
        return value

    def secure_tree(self):
        from proton_backup.credentials import CredentialStoreError

        for current, directories, files in os.walk(self.root, followlinks=False):
            current_path = Path(current)
            if current_path.is_symlink():
                raise CredentialStoreError("Unable to initialize credential store")
            self._chmod(current_path, 0o700)
            for name in directories:
                path = current_path / name
                if path.is_symlink():
                    raise CredentialStoreError("Unable to initialize credential store")
                self._chmod(path, 0o700)
            for name in files:
                path = current_path / name
                if path.is_symlink() or not path.is_file():
                    raise CredentialStoreError("Unable to initialize credential store")
                self._chmod(path, 0o600)

    def remove_children(self):
        from proton_backup.credentials import CredentialStoreError

        if self.swap_on_remove:
            raise CredentialStoreError("Unable to remove credential store")
        self.root.mkdir(parents=True, exist_ok=True)
        for child in tuple(self.root.iterdir()):
            if child.is_symlink() or not child.is_dir():
                child.unlink()
            else:
                shutil.rmtree(child)
        self._chmod(self.root, 0o700)

    def _chmod(self, path: Path, mode: int):
        os.chmod(path, mode)
        self.chmod_calls.append((path, mode))


class FakeCredentialRunner:
    def __init__(self, private_root: Path):
        self.private_root = private_root
        self.calls: list[tuple[str, ...]] = []

    def run(self, args, *, timeout, cancel, on_stdout_line=None):
        call = tuple(args)
        self.calls.append(call)
        stdout = ""
        if "--list-secret-keys" in call:
            stdout = (
                "sec:u:255:22:89ABCDEF01234567:0:0::u:::scESC:::+::ed25519:::0:\n"
                f"fpr:::::::::{FINGERPRINT}:\n"
            )
        elif call[:2] == ("pass", "init"):
            pass_root = self.private_root / "pass"
            pass_root.mkdir(parents=True, exist_ok=True)
            (pass_root / ".gpg-id").write_text(call[2] + "\n", encoding="ascii")
        return CommandResult(call, 0, stdout, "")


class CredentialStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp = Path(self.temp_dir.name)
        self.private_root = self.temp / "private"
        self.runner = FakeCredentialRunner(self.private_root)
        self.filesystem = SafeTestPrivateFilesystem(self.private_root)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _store(self):
        try:
            from proton_backup.credentials import CredentialStore
        except ModuleNotFoundError as error:
            self.fail(f"CredentialStore module is missing: {error}")
        return CredentialStore(
            self.private_root,
            runner=self.runner,
            filesystem=self.filesystem,
        )

    def test_bootstrap_uses_pass_and_private_permissions(self):
        store = self._store()

        with patch("proton_backup.credentials.os.umask") as umask:
            store.bootstrap()

        umask.assert_called_once_with(0o077)
        self.assertIn((self.private_root, 0o700), self.filesystem.chmod_calls)
        self.assertIn(
            (self.private_root / "pass" / ".gpg-id", 0o600),
            self.filesystem.chmod_calls,
        )
        environment = store.environment()
        self.assertEqual(environment["PROTON_DRIVE_CREDENTIALS_STORE"], "pass")
        self.assertNotIn("unsafe_file", environment.values())
        self.assertEqual(environment["GNUPGHOME"], str(self.private_root / "gnupg"))
        self.assertEqual(
            environment["PASSWORD_STORE_DIR"], str(self.private_root / "pass")
        )
        for directory in ("gnupg", "pass", "home", "proton"):
            self.assertIn(
                (self.private_root / directory, 0o700),
                self.filesystem.chmod_calls,
            )

    def test_bootstrap_generates_batch_key_with_empty_local_passphrase(self):
        store = self._store()

        store.bootstrap()

        generate = next(call for call in self.runner.calls if "--quick-generate-key" in call)
        self.assertIn("--batch", generate)
        self.assertEqual(generate[generate.index("--passphrase") + 1], "")
        self.assertIn("--pinentry-mode", generate)
        identity_index = generate.index(
            "Home Assistant Proton Drive Backup <local@invalid>"
        )
        self.assertEqual(
            generate[identity_index + 1 :], ("default", "default", "never")
        )
        self.assertIn(("pass", "init", FINGERPRINT), self.runner.calls)

    def test_bootstrap_is_idempotent_after_valid_pass_initialization(self):
        store = self._store()
        store.bootstrap()
        first_calls = tuple(self.runner.calls)

        store.bootstrap()

        self.assertEqual(tuple(self.runner.calls), first_calls)

    def test_bootstrap_selects_primary_fingerprint_from_default_key_and_subkey(self):
        subkey_fingerprint = "F" * 40

        class DefaultKeyRunner(FakeCredentialRunner):
            def run(self, args, *, timeout, cancel, on_stdout_line=None):
                result = super().run(
                    args,
                    timeout=timeout,
                    cancel=cancel,
                    on_stdout_line=on_stdout_line,
                )
                if "--list-secret-keys" in tuple(args):
                    return CommandResult(
                        tuple(args),
                        0,
                        "sec:u:3072:1:89ABCDEF01234567:0:0::u:::scESC:::+::rsa3072:::0:\n"
                        f"fpr:::::::::{FINGERPRINT}:\n"
                        "uid:u::::0::hash::local@invalid::::::::::0:\n"
                        "ssb:u:3072:1:FEDCBA9876543210:0:0:::::e:::+::rsa3072:\n"
                        f"fpr:::::::::{subkey_fingerprint}:\n",
                        "",
                    )
                return result

        runner = DefaultKeyRunner(self.private_root)
        from proton_backup.credentials import CredentialStore

        CredentialStore(
            self.private_root,
            runner=runner,
            filesystem=SafeTestPrivateFilesystem(self.private_root),
        ).bootstrap()

        self.assertIn(("pass", "init", FINGERPRINT), runner.calls)

    def test_environment_for_production_root_is_fixed_below_data_private(self):
        from proton_backup.credentials import CredentialStore

        environment = CredentialStore(Path("/data/private"), runner=self.runner).environment()

        self.assertEqual(environment["HOME"], "/data/private/home")
        self.assertEqual(environment["GNUPGHOME"], "/data/private/gnupg")
        self.assertEqual(environment["PASSWORD_STORE_DIR"], "/data/private/pass")
        self.assertEqual(
            environment["PROTON_DRIVE_CACHE_DIR"], "/data/private/proton"
        )
        self.assertNotIn("unsafe_file", environment.values())
        self.assertFalse(any("fake-secret" in value for value in environment.values()))

    def test_remove_deletes_only_children_of_resolved_private_root(self):
        store = self._store()
        store.bootstrap()
        sibling = self.temp / "retain-me"
        sibling.write_text("outside", encoding="ascii")
        nested = self.private_root / "session" / "value"
        nested.parent.mkdir(mode=0o700)
        nested.write_text("fake-session", encoding="ascii")

        store.remove()

        self.assertTrue(self.private_root.is_dir())
        self.assertEqual(list(self.private_root.iterdir()), [])
        self.assertEqual(sibling.read_text(encoding="ascii"), "outside")
        self.assertIn((self.private_root, 0o700), self.filesystem.chmod_calls)

    def test_store_rejects_symlinked_private_root_before_resolving_it(self):
        from proton_backup.credentials import CredentialStore, CredentialStoreError

        self.filesystem.invalid_root = True
        store = CredentialStore(
            self.private_root,
            runner=self.runner,
            filesystem=self.filesystem,
        )
        with self.assertRaises(CredentialStoreError):
            store.bootstrap()

    def test_broken_gpg_id_symlink_is_rejected_before_pass_init(self):
        from proton_backup.credentials import CredentialStoreError

        self.filesystem.broken_gpg_id = True
        outside = self.temp / "outside"
        outside.write_text("retain", encoding="ascii")

        with self.assertRaises(CredentialStoreError):
            self._store().bootstrap()

        self.assertFalse(any(call[:2] == ("pass", "init") for call in self.runner.calls))
        self.assertEqual(outside.read_text(encoding="ascii"), "retain")

    def test_gpg_id_identity_swap_fails_closed_and_preserves_outside_target(self):
        from proton_backup.credentials import CredentialStoreError

        self.filesystem.swap_on_read = True
        outside = self.temp / "outside"
        outside.write_text("retain", encoding="ascii")

        with self.assertRaises(CredentialStoreError):
            self._store().bootstrap()

        self.assertEqual(outside.read_text(encoding="ascii"), "retain")

    def test_remove_identity_swap_fails_closed_and_preserves_all_targets(self):
        from proton_backup.credentials import CredentialStoreError

        self.filesystem.prepare()
        inside = self.private_root / "session"
        inside.write_text("retain-inside", encoding="ascii")
        outside = self.temp / "outside"
        outside.write_text("retain-outside", encoding="ascii")
        self.filesystem.swap_on_remove = True

        with self.assertRaises(CredentialStoreError):
            self._store().remove()

        self.assertEqual(inside.read_text(encoding="ascii"), "retain-inside")
        self.assertEqual(outside.read_text(encoding="ascii"), "retain-outside")

    def test_real_operations_fail_closed_for_nonstandard_private_root(self):
        from proton_backup.credentials import CredentialStore, CredentialStoreError

        store = CredentialStore(self.private_root, runner=self.runner)
        with self.assertRaisesRegex(CredentialStoreError, "unsupported"):
            store.bootstrap()
        self.assertEqual(self.runner.calls, [])
        self.assertFalse(self.private_root.exists())

    def test_private_filesystem_fails_closed_without_directory_descriptors(self):
        from proton_backup.credentials import CredentialStoreError, _default_private_filesystem

        with patch("proton_backup.credentials.os.supports_dir_fd", set()):
            filesystem = _default_private_filesystem(self.private_root)

        with self.assertRaisesRegex(CredentialStoreError, "unsupported"):
            filesystem.prepare()
        self.assertFalse(self.private_root.exists())

    @unittest.skipUnless(os.name == "posix", "requires Linux directory descriptors")
    def test_linux_boundary_rejects_broken_gpg_id_symlink_before_pass_init(self):
        from proton_backup.credentials import (
            CredentialStore,
            CredentialStoreError,
            _LinuxPrivateFilesystem,
        )

        filesystem = _LinuxPrivateFilesystem(self.private_root)
        filesystem.prepare()
        outside = self.temp / "outside-gpg-id"
        outside.write_text(FINGERPRINT + "\n", encoding="ascii")
        os.symlink(outside, self.private_root / "pass" / ".gpg-id")
        store = CredentialStore(
            self.private_root,
            runner=self.runner,
            filesystem=filesystem,
        )

        with self.assertRaises(CredentialStoreError):
            store.bootstrap()

        self.assertFalse(any(call[:2] == ("pass", "init") for call in self.runner.calls))
        self.assertEqual(outside.read_text(encoding="ascii"), FINGERPRINT + "\n")

    @unittest.skipUnless(os.name == "posix", "requires Linux directory descriptors")
    def test_linux_boundary_rejects_root_swap_and_preserves_outside_target(self):
        from proton_backup.credentials import (
            CredentialStore,
            CredentialStoreError,
            _LinuxPrivateFilesystem,
        )

        filesystem = _LinuxPrivateFilesystem(self.private_root)
        filesystem.prepare()
        inside = self.private_root / "session"
        inside.write_text("retain-inside", encoding="ascii")
        moved_root = self.temp / "moved-private"
        self.private_root.rename(moved_root)
        outside = self.temp / "outside-directory"
        outside.mkdir()
        outside_value = outside / "retain"
        outside_value.write_text("retain-outside", encoding="ascii")
        os.symlink(outside, self.private_root, target_is_directory=True)
        store = CredentialStore(
            self.private_root,
            runner=self.runner,
            filesystem=filesystem,
        )

        with self.assertRaises(CredentialStoreError):
            store.remove()

        self.assertEqual(
            (moved_root / "session").read_text(encoding="ascii"),
            "retain-inside",
        )
        self.assertEqual(outside_value.read_text(encoding="ascii"), "retain-outside")

    @unittest.skipUnless(os.name == "posix", "requires Linux directory descriptors")
    def test_linux_boundary_rejects_gpg_id_identity_replacement(self):
        from proton_backup.credentials import CredentialStoreError, _LinuxPrivateFilesystem

        filesystem = _LinuxPrivateFilesystem(self.private_root)
        filesystem.prepare()
        gpg_id = self.private_root / "pass" / ".gpg-id"
        gpg_id.write_text(FINGERPRINT + "\n", encoding="ascii")
        self.assertTrue(filesystem.gpg_id_exists())
        # Give the replacement its inode while the original still exists.
        replacement = gpg_id.with_name(".gpg-id.new")
        replacement.write_text(FINGERPRINT + "\n", encoding="ascii")
        replacement.replace(gpg_id)

        with self.assertRaises((CredentialStoreError, OSError)):
            filesystem.read_gpg_id()

    def test_bootstrap_fails_closed_on_ambiguous_gpg_fingerprint(self):
        class AmbiguousRunner(FakeCredentialRunner):
            def run(self, args, *, timeout, cancel, on_stdout_line=None):
                result = super().run(
                    args,
                    timeout=timeout,
                    cancel=cancel,
                    on_stdout_line=on_stdout_line,
                )
                if "--list-secret-keys" in tuple(args):
                    return CommandResult(
                        tuple(args),
                        0,
                        result.stdout + f"fpr:::::::::{'F' * 40}:\n",
                        "",
                    )
                return result

        from proton_backup.credentials import CredentialStore, CredentialStoreError

        store = CredentialStore(
            self.private_root,
            runner=AmbiguousRunner(self.private_root),
            filesystem=SafeTestPrivateFilesystem(self.private_root),
        )

        with self.assertRaisesRegex(CredentialStoreError, "initialize"):
            store.bootstrap()
        self.assertFalse((self.private_root / "pass" / ".gpg-id").exists())

    def test_bootstrap_reports_nonzero_command_without_exposing_output(self):
        class FailingRunner(FakeCredentialRunner):
            def run(self, args, *, timeout, cancel, on_stdout_line=None):
                return CommandResult(tuple(args), 7, "fake-sensitive-output", "fake-error")

        from proton_backup.credentials import CredentialStore, CredentialStoreError

        store = CredentialStore(
            self.private_root,
            runner=FailingRunner(self.private_root),
            filesystem=SafeTestPrivateFilesystem(self.private_root),
        )

        with self.assertRaises(CredentialStoreError) as raised:
            store.bootstrap()
        self.assertNotIn("fake-sensitive", str(raised.exception))
        self.assertNotIn("fake-error", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
