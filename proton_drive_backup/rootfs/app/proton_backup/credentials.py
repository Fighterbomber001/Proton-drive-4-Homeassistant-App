from __future__ import annotations

import os
import re
import stat
from collections.abc import Sequence
from pathlib import Path
from threading import Event
from typing import Protocol

from .config import PRIVATE_ROOT
from .events import EventLog, startup_step
from .models import CommandResult
from .process import ProcessRunner


_LOCAL_KEY_IDENTITY = "Home Assistant Proton Drive Backup <local@invalid>"
_FINGERPRINT = re.compile(r"^[0-9A-F]{40}$")
_COMMAND_TIMEOUT_SECONDS = 60


class CredentialStoreError(RuntimeError):
    """A neutral credential-store failure suitable for safe diagnostics."""


class _Runner(Protocol):
    def run(
        self,
        args: Sequence[str],
        *,
        timeout: int,
        cancel: Event,
        on_stdout_line=None,
    ) -> CommandResult: ...


class _PrivateFilesystem(Protocol):
    def prepare(self) -> None: ...
    def verify(self) -> None: ...
    def gpg_id_exists(self) -> bool: ...
    def read_gpg_id(self) -> str: ...
    def secure_tree(self) -> None: ...
    def remove_children(self) -> None: ...


class _UnsupportedPrivateFilesystem:
    @staticmethod
    def _fail() -> None:
        raise CredentialStoreError("Private filesystem operations are unsupported")

    prepare = verify = gpg_id_exists = read_gpg_id = secure_tree = remove_children = _fail


class _LinuxPrivateFilesystem:
    _DIRECTORY_FLAGS = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    _FILE_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    _MAX_TREE_ENTRIES = 10_000
    _GPG_AGENT_SOCKETS = frozenset((
        "S.gpg-agent", "S.gpg-agent.extra", "S.gpg-agent.browser", "S.gpg-agent.ssh",
    ))

    def __init__(self, root: Path):
        self._root = root
        self._identity: tuple[int, int] | None = None
        self._gpg_id_identity: tuple[int, int] | None = None
        if not root.is_absolute() or root == Path(root.anchor):
            raise CredentialStoreError("Invalid private credential root")
        if any(part in ("", ".", "..") for part in root.parts[1:]):
            raise CredentialStoreError("Invalid private credential root")

    def prepare(self) -> None:
        root_fd = self._open_root(create=True)
        try:
            os.fchmod(root_fd, 0o700)
            for name in ("gnupg", "pass", "home", "proton"):
                child_fd = self._open_or_create_directory(root_fd, name)
                try:
                    os.fchmod(child_fd, 0o700)
                finally:
                    os.close(child_fd)
        finally:
            os.close(root_fd)

    def verify(self) -> None:
        root_fd = self._open_root()
        os.close(root_fd)

    def gpg_id_exists(self) -> bool:
        root_fd = self._open_root()
        try:
            pass_fd = self._open_directory(root_fd, "pass")
            try:
                try:
                    metadata = os.stat(".gpg-id", dir_fd=pass_fd, follow_symlinks=False)
                except FileNotFoundError:
                    self._gpg_id_identity = None
                    return False
                if not stat.S_ISREG(metadata.st_mode):
                    raise OSError("Unsafe credential store entry")
                self._gpg_id_identity = (metadata.st_dev, metadata.st_ino)
                return True
            finally:
                os.close(pass_fd)
        finally:
            os.close(root_fd)

    def read_gpg_id(self) -> str:
        root_fd = self._open_root()
        try:
            pass_fd = self._open_directory(root_fd, "pass")
            try:
                file_fd = os.open(".gpg-id", self._FILE_FLAGS, dir_fd=pass_fd)
                try:
                    metadata = os.fstat(file_fd)
                    if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= 128:
                        raise OSError("Unsafe credential store entry")
                    identity = (metadata.st_dev, metadata.st_ino)
                    if (
                        self._gpg_id_identity is not None
                        and identity != self._gpg_id_identity
                    ):
                        raise OSError("Credential store entry identity changed")
                    value = os.read(file_fd, 129)
                    if len(value) > 128:
                        raise OSError("Unsafe credential store entry")
                    os.fchmod(file_fd, 0o600)
                    self._gpg_id_identity = identity
                    return value.decode("ascii")
                finally:
                    os.close(file_fd)
            finally:
                os.close(pass_fd)
        finally:
            os.close(root_fd)

    def secure_tree(self) -> None:
        root_fd = self._open_root()
        try:
            counter = [0]
            self._secure_directory(root_fd, counter)
        finally:
            os.close(root_fd)

    def remove_children(self) -> None:
        root_fd = self._open_root(create=True)
        try:
            self._remove_directory_children(root_fd, [0])
            os.fchmod(root_fd, 0o700)
        finally:
            os.close(root_fd)

    def _open_root(self, *, create: bool = False) -> int:
        current_fd = os.open(self._root.anchor, self._DIRECTORY_FLAGS)
        try:
            parts = self._root.parts[1:]
            for index, part in enumerate(parts):
                try:
                    next_fd = os.open(part, self._DIRECTORY_FLAGS, dir_fd=current_fd)
                except FileNotFoundError:
                    if not create or index != len(parts) - 1:
                        raise
                    os.mkdir(part, 0o700, dir_fd=current_fd)
                    next_fd = os.open(part, self._DIRECTORY_FLAGS, dir_fd=current_fd)
                os.close(current_fd)
                current_fd = next_fd
            metadata = os.fstat(current_fd)
            identity = (metadata.st_dev, metadata.st_ino)
            if self._identity is None:
                self._identity = identity
            elif identity != self._identity:
                raise OSError("Private root identity changed")
            return current_fd
        except Exception:
            os.close(current_fd)
            raise

    def _open_or_create_directory(self, parent_fd: int, name: str) -> int:
        try:
            return self._open_directory(parent_fd, name)
        except FileNotFoundError:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
            return self._open_directory(parent_fd, name)

    def _open_directory(self, parent_fd: int, name: str) -> int:
        child_fd = os.open(name, self._DIRECTORY_FLAGS, dir_fd=parent_fd)
        metadata = os.fstat(child_fd)
        if not stat.S_ISDIR(metadata.st_mode):
            os.close(child_fd)
            raise OSError("Unsafe private directory")
        return child_fd

    def _secure_directory(
        self, directory_fd: int, counter: list[int], relative_path: tuple[str, ...] = (),
    ) -> None:
        os.fchmod(directory_fd, 0o700)
        with os.scandir(directory_fd) as entries:
            names = [entry.name for entry in entries]
        for name in names:
            self._count_entry(counter)
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                child_fd = self._open_directory(directory_fd, name)
                try:
                    opened = os.fstat(child_fd)
                    if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                        raise OSError("Private entry identity changed")
                    self._secure_directory(child_fd, counter, relative_path + (name,))
                finally:
                    os.close(child_fd)
            elif stat.S_ISREG(metadata.st_mode):
                file_fd = os.open(name, self._FILE_FLAGS, dir_fd=directory_fd)
                try:
                    opened = os.fstat(file_fd)
                    if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                        raise OSError("Private entry identity changed")
                    os.fchmod(file_fd, 0o600)
                finally:
                    os.close(file_fd)
            elif stat.S_ISSOCK(metadata.st_mode):
                # GnuPG falls back to GNUPGHOME for its local agent sockets.
                # Never grant the exception to another location or socket name.
                if relative_path != ("gnupg",) or name not in self._GPG_AGENT_SOCKETS:
                    raise OSError("Unsafe private entry")
                self._verify_agent_socket(directory_fd, name, metadata)
            else:
                raise OSError("Unsafe private entry")

    @staticmethod
    def _verify_agent_socket(directory_fd: int, name: str, original: os.stat_result) -> None:
        # O_PATH pins a socket without opening a connection. O_PATH | O_NOFOLLOW
        # can pin a symlink, so every observation must still be a private socket.
        path_flag = getattr(os, "O_PATH", 0)
        nofollow_flag = getattr(os, "O_NOFOLLOW", 0)
        if not path_flag or not nofollow_flag:
            raise OSError("Socket identity checks are unsupported")
        uid = os.geteuid()
        parent = os.fstat(directory_fd)
        if parent.st_uid != uid or parent.st_mode & 0o077:
            raise OSError("Unsafe private directory")

        def is_private_socket(value: os.stat_result) -> bool:
            return (stat.S_ISSOCK(value.st_mode) and value.st_uid == uid
                    and not value.st_mode & 0o077)

        if not is_private_socket(original):
            raise OSError("Unsafe private entry")
        socket_fd = os.open(
            name, path_flag | nofollow_flag | getattr(os, "O_CLOEXEC", 0),
            dir_fd=directory_fd,
        )
        try:
            opened = os.fstat(socket_fd)
            current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            identity = (original.st_dev, original.st_ino)
            if (not is_private_socket(opened) or not is_private_socket(current)
                    or (opened.st_dev, opened.st_ino) != identity
                    or (current.st_dev, current.st_ino) != identity):
                raise OSError("Private entry identity changed")
        finally:
            os.close(socket_fd)

    def _remove_directory_children(self, directory_fd: int, counter: list[int]) -> None:
        with os.scandir(directory_fd) as entries:
            names = [entry.name for entry in entries]
        for name in names:
            self._count_entry(counter)
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                child_fd = self._open_directory(directory_fd, name)
                try:
                    opened = os.fstat(child_fd)
                    identity = (opened.st_dev, opened.st_ino)
                    if identity != (metadata.st_dev, metadata.st_ino):
                        raise OSError("Private entry identity changed")
                    self._remove_directory_children(child_fd, counter)
                    current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if identity != (current.st_dev, current.st_ino):
                        raise OSError("Private entry identity changed")
                finally:
                    os.close(child_fd)
                os.rmdir(name, dir_fd=directory_fd)
            else:
                os.unlink(name, dir_fd=directory_fd)

    def _count_entry(self, counter: list[int]) -> None:
        counter[0] += 1
        if counter[0] > self._MAX_TREE_ENTRIES:
            raise OSError("Private tree is too large")


def _default_private_filesystem(root: Path) -> _PrivateFilesystem:
    required_dir_fd = (os.open, os.mkdir, os.stat, os.unlink, os.rmdir)
    supported = (
        os.name == "posix"
        and bool(getattr(os, "O_NOFOLLOW", 0))
        and bool(getattr(os, "O_DIRECTORY", 0))
        and all(function in os.supports_dir_fd for function in required_dir_fd)
        and os.stat in os.supports_follow_symlinks
    )
    return _LinuxPrivateFilesystem(root) if supported else _UnsupportedPrivateFilesystem()


class CredentialStore:
    def __init__(
        self,
        private_root: Path = PRIVATE_ROOT,
        *,
        runner: _Runner | None = None,
        filesystem: _PrivateFilesystem | None = None,
    ):
        raw_root = str(private_root).replace("\\", "/")
        requested_root = Path(os.path.abspath(private_root))
        self._root = requested_root
        if self._root == Path(self._root.anchor):
            raise CredentialStoreError("Invalid private credential root")
        self._environment_root = (
            "/data/private"
            if raw_root == "/data/private"
            else str(self._root)
        )
        environment = self.environment()
        self._runner = runner or ProcessRunner(
            environment={**os.environ, **environment}
        )
        self._filesystem = (
            filesystem
            if filesystem is not None
            else _default_private_filesystem(self._root)
            if raw_root == "/data/private"
            else _UnsupportedPrivateFilesystem()
        )

    def environment(self) -> dict[str, str]:
        root = self._environment_root.rstrip("/\\")
        separator = "/" if root == "/data/private" else os.sep
        return {
            "HOME": f"{root}{separator}home",
            "GNUPGHOME": f"{root}{separator}gnupg",
            "PASSWORD_STORE_DIR": f"{root}{separator}pass",
            "PROTON_DRIVE_CREDENTIALS_STORE": "pass",
            "PROTON_DRIVE_CACHE_DIR": f"{root}{separator}proton",
            "PROTON_DRIVE_LOG_LEVEL": "ERROR",
        }

    def bootstrap(self) -> None:
        events = EventLog()
        try:
            os.umask(0o077)
            with startup_step(events, "startup_credential_paths"):
                self._filesystem.prepare()
                initialized = self._filesystem.gpg_id_exists()
            if initialized:
                with startup_step(events, "startup_credential_existing"):
                    self._validate_gpg_id(self._filesystem.read_gpg_id())
                with startup_step(events, "startup_credential_permissions"):
                    self._filesystem.secure_tree()
                return

            with startup_step(events, "startup_gpg_generate"):
                self._run_checked(
                    (
                        "gpg",
                        "--batch",
                        "--pinentry-mode",
                        "loopback",
                        "--passphrase",
                        "",
                        "--quick-generate-key",
                        _LOCAL_KEY_IDENTITY,
                        "default",
                        "default",
                        "never",
                    )
                )
            with startup_step(events, "startup_gpg_fingerprint"):
                result = self._run_checked(
                    (
                        "gpg",
                        "--batch",
                        "--with-colons",
                        "--fingerprint",
                        "--list-secret-keys",
                        _LOCAL_KEY_IDENTITY,
                    )
                )
                fingerprint = self._parse_single_fingerprint(result.stdout)
            with startup_step(events, "startup_pass_init"):
                self._run_checked(("pass", "init", fingerprint))
                self._validate_gpg_id(
                    self._filesystem.read_gpg_id(), expected=fingerprint
                )
            with startup_step(events, "startup_credential_permissions"):
                self._filesystem.secure_tree()
        except CredentialStoreError:
            raise
        except (OSError, ValueError):
            raise CredentialStoreError("Unable to initialize credential store") from None

    def remove(self) -> None:
        try:
            self._filesystem.remove_children()
        except CredentialStoreError:
            raise
        except OSError:
            raise CredentialStoreError("Unable to remove credential store") from None

    def _run_checked(self, args: Sequence[str]) -> CommandResult:
        self._filesystem.verify()
        result = self._runner.run(
            args,
            timeout=_COMMAND_TIMEOUT_SECONDS,
            cancel=Event(),
        )
        if (
            result.returncode != 0
            or result.timed_out
            or result.cancelled
        ):
            raise CredentialStoreError("Unable to initialize credential store")
        self._filesystem.verify()
        return result

    @staticmethod
    def _parse_single_fingerprint(output: str) -> str:
        primary_fingerprints = []
        expected_fingerprint: str | None = None
        for line in output.splitlines():
            fields = line.split(":")
            record_type = fields[0] if fields else ""
            if record_type == "sec":
                if expected_fingerprint is not None:
                    raise CredentialStoreError("Unable to initialize credential store")
                expected_fingerprint = "primary"
            elif record_type == "ssb":
                if expected_fingerprint is not None:
                    raise CredentialStoreError("Unable to initialize credential store")
                expected_fingerprint = "subkey"
            elif record_type == "fpr":
                if (
                    expected_fingerprint is None
                    or len(fields) != 11
                    or not _FINGERPRINT.fullmatch(fields[9])
                ):
                    raise CredentialStoreError("Unable to initialize credential store")
                if expected_fingerprint == "primary":
                    primary_fingerprints.append(fields[9])
                expected_fingerprint = None
        if expected_fingerprint is not None or len(primary_fingerprints) != 1:
            raise CredentialStoreError("Unable to initialize credential store")
        return primary_fingerprints[0]

    @staticmethod
    def _validate_gpg_id(value: str, expected: str | None = None) -> str:
        if not isinstance(value, str) or len(value) > 128:
            raise CredentialStoreError("Unable to initialize credential store")
        value = value.strip()
        if not _FINGERPRINT.fullmatch(value) or (expected is not None and value != expected):
            raise CredentialStoreError("Unable to initialize credential store")
        return value
