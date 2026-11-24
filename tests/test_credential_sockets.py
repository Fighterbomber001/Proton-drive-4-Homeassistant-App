"""Only GnuPG's private agent sockets are safe credential-tree entries."""
import tests
import os
import socket
import stat
import sys
from contextlib import ExitStack
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from proton_backup.credentials import _LinuxPrivateFilesystem


NAMES = ("S.gpg-agent", "S.gpg-agent.extra", "S.gpg-agent.browser", "S.gpg-agent.ssh")


def metadata(mode, inode, uid=42):
    return SimpleNamespace(st_mode=mode, st_dev=1, st_ino=inode, st_uid=uid)


class Scan:
    def __init__(self, names):
        self.entries = [SimpleNamespace(name=name) for name in names]

    def __enter__(self):
        return self.entries

    def __exit__(self, *args):
        return False


class CredentialSocketBoundaryTests(unittest.TestCase):
    def check_tree(self, *, name="S.gpg-agent", parent="gnupg", mode=stat.S_IFSOCK | 0o700,
                   uid=42, parent_uid=42, opened=None, final=None, o_path=0o10000000):
        directory = metadata(stat.S_IFDIR | 0o700, 2, parent_uid)
        initial = metadata(mode, 3, uid)
        opened = opened or initial
        final = final or initial
        observations = iter((initial, final))
        filesystem = _LinuxPrivateFilesystem(Path.cwd() / "not-accessed")

        def fake_stat(entry, *, dir_fd, follow_symlinks):
            self.assertFalse(follow_symlinks)
            return directory if dir_fd == 10 else next(observations)

        with ExitStack() as stack:
            stack.enter_context(patch("proton_backup.credentials.os.scandir", side_effect=lambda fd: Scan([parent] if fd == 10 else [name])))
            stack.enter_context(patch("proton_backup.credentials.os.stat", side_effect=fake_stat))
            stack.enter_context(patch("proton_backup.credentials.os.fstat", side_effect=lambda fd: directory if fd == 11 else opened))
            chmod = stack.enter_context(patch("proton_backup.credentials.os.fchmod", create=True))
            close = stack.enter_context(patch("proton_backup.credentials.os.close"))
            open_socket = stack.enter_context(patch("proton_backup.credentials.os.open", return_value=12))
            stack.enter_context(patch.object(filesystem, "_open_directory", return_value=11))
            stack.enter_context(patch("proton_backup.credentials.os.geteuid", return_value=42, create=True))
            stack.enter_context(patch("proton_backup.credentials.os.O_PATH", o_path, create=True))
            stack.enter_context(patch("proton_backup.credentials.os.O_NOFOLLOW", 0o400000, create=True))
            filesystem._secure_directory(10, [0])
            self.assertNotIn(12, [call.args[0] for call in chmod.call_args_list])
            self.assertEqual(open_socket.call_args.kwargs["dir_fd"], 11)
            self.assertTrue(open_socket.call_args.args[1] & o_path)
            self.assertIn(((12,), {}), close.call_args_list)

    def test_expected_private_agent_sockets_are_accepted_without_chmod(self):
        for name in NAMES:
            with self.subTest(name=name):
                self.check_tree(name=name)

    def test_socket_exception_does_not_apply_outside_gnupg(self):
        for parent in ("pass", "home", "proton", "nested"):
            with self.subTest(parent=parent), self.assertRaises(OSError):
                self.check_tree(parent=parent)

    def test_unknown_socket_name_remains_rejected(self):
        with self.assertRaises(OSError):
            self.check_tree(name="untrusted.sock")

    def test_socket_and_parent_must_belong_to_current_user(self):
        for changes in ({"uid": 99}, {"parent_uid": 99}):
            with self.subTest(changes=changes), self.assertRaises(OSError):
                self.check_tree(**changes)

    def test_socket_must_not_grant_group_or_other_access(self):
        for bit in (0o040, 0o020, 0o010, 0o004, 0o002, 0o001):
            with self.subTest(bit=bit), self.assertRaises(OSError):
                self.check_tree(mode=stat.S_IFSOCK | 0o700 | bit)

    def test_special_entries_and_symlinks_remain_rejected(self):
        for kind in (stat.S_IFLNK, stat.S_IFIFO, stat.S_IFCHR, stat.S_IFBLK):
            with self.subTest(kind=kind), self.assertRaises(OSError):
                self.check_tree(mode=kind | 0o700)

    def test_opened_socket_identity_type_owner_and_mode_are_rechecked(self):
        replacements = (metadata(stat.S_IFSOCK | 0o700, 4), metadata(stat.S_IFLNK | 0o700, 3),
                        metadata(stat.S_IFSOCK | 0o700, 3, 99), metadata(stat.S_IFSOCK | 0o777, 3))
        for opened in replacements:
            with self.subTest(opened=opened), self.assertRaises(OSError):
                self.check_tree(opened=opened)

    def test_socket_path_is_rechecked_after_open(self):
        replacements = (metadata(stat.S_IFSOCK | 0o700, 4), metadata(stat.S_IFLNK | 0o700, 3),
                        metadata(stat.S_IFSOCK | 0o700, 3, 99), metadata(stat.S_IFSOCK | 0o777, 3))
        for final in replacements:
            with self.subTest(final=final), self.assertRaises(OSError):
                self.check_tree(final=final)

    def test_missing_o_path_fails_closed(self):
        with self.assertRaises(OSError):
            self.check_tree(o_path=0)


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "O_PATH"), "requires real Linux O_PATH and AF_UNIX sockets")
class CredentialRealSocketTests(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory(prefix="gpg-socket-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "private"
        self.filesystem = _LinuxPrivateFilesystem(self.root)
        self.filesystem.prepare()

    def bind(self, path, mode=0o700):
        agent = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(agent.close)
        agent.bind(str(path))
        os.chmod(path, mode)
        return path.stat()

    def test_real_gpg_sockets_survive_hardening_unchanged(self):
        before = {name: self.bind(self.root / "gnupg" / name) for name in NAMES}
        value = self.root / "gnupg" / "ordinary-key-file"
        value.write_text("not a real key", encoding="ascii")
        os.chmod(value, 0o644)
        self.filesystem.secure_tree()
        self.assertEqual(stat.S_IMODE(value.stat().st_mode), 0o600)
        for name, original in before.items():
            current = (self.root / "gnupg" / name).stat()
            self.assertEqual((current.st_dev, current.st_ino, current.st_mode),
                             (original.st_dev, original.st_ino, original.st_mode))

    def test_real_socket_outside_direct_gnupg_is_rejected(self):
        nested = self.root / "gnupg" / "nested"
        nested.mkdir()
        self.bind(nested / "S.gpg-agent")
        with self.assertRaises(OSError):
            self.filesystem.secure_tree()

    def test_real_agent_name_symlink_is_rejected_and_target_preserved(self):
        target = self.root.parent / "outside"
        target.write_text("retain", encoding="ascii")
        os.chmod(target, 0o644)
        os.symlink(target, self.root / "gnupg" / "S.gpg-agent")
        with self.assertRaises(OSError):
            self.filesystem.secure_tree()
        self.assertEqual(target.read_text(encoding="ascii"), "retain")
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)

    def test_real_world_accessible_agent_socket_is_rejected(self):
        self.bind(self.root / "gnupg" / "S.gpg-agent", 0o777)
        with self.assertRaises(OSError):
            self.filesystem.secure_tree()
