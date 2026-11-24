"""HA-native backups: immutable archive plus a remote, self-contained commit record.

The caller serializes all calls on the Proton I/O lane. A private spool file
belongs to the caller before upload and after a successful download.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from functools import wraps
from pathlib import Path

from .proton_cli import ProtonAuthenticationRequired, ProtonCliError, _load_json

MAX_METADATA_BYTES = 24576
MAX_ARCHIVE_BYTES = 100 * 1024**3
_MAX_MANIFEST_BYTES = MAX_METADATA_BYTES + 2048
_MAX_INSTALLATIONS = 128
_MAX_MANIFESTS = 1024
_PARENT = "/my-files/HomeAssistant-Backups"
_INSTALL = re.compile(r"[0-9a-f]{32}")
_ID = re.compile(r"[A-Za-z0-9_-]{1,128}")
_HASH = re.compile(r"[0-9a-f]{64}")
_MANIFEST = re.compile(r"ha1-([0-9a-f]{64})-([0-9a-f]{32})\.json")
_SPOOL_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,126}[A-Za-z0-9_]|[A-Za-z0-9_]")
_FIELDS = {"addons", "backup_id", "date", "database_included", "extra_metadata",
           "folders", "homeassistant_included", "homeassistant_version", "name", "protected", "size"}


class NativeStorageError(RuntimeError):
    code = "storage_failed"

    def __init__(self):
        super().__init__(self.code)


class NativeBackupNotFound(NativeStorageError):
    code = "backup_not_found"


class NativeDeleteUnsupported(NativeStorageError):
    code = "delete_not_supported"


class NativeAuthenticationRequired(NativeStorageError):
    code = "authentication_required"


@dataclass(frozen=True)
class NativeDownload:
    path: Path
    size: int


def _require(condition):
    if not condition:
        raise NativeStorageError()


def _boundary(method):
    """Do not send paths, metadata or subprocess details to API callers."""
    @wraps(method)
    def wrapped(*args, **kwargs):
        try:
            return method(*args, **kwargs)
        except ProtonAuthenticationRequired:
            raise NativeAuthenticationRequired() from None
        except (ProtonCliError, OSError, ValueError, TypeError, RecursionError):
            raise NativeStorageError() from None
    return wrapped


def validate_backup_id(backup_id):
    _require(isinstance(backup_id, str) and _ID.fullmatch(backup_id))
    return backup_id


def _encode(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


@_boundary
def validate_metadata(backup_id, metadata):
    validate_backup_id(backup_id)
    d = metadata
    _require(type(d) is dict and d.keys() == _FIELDS and d["backup_id"] == backup_id)
    _require(type(d["name"]) is str and type(d["date"]) is str and "T" in d["date"])
    datetime.fromisoformat(d["date"])
    _require(d["homeassistant_version"] is None or type(d["homeassistant_version"]) is str)
    _require(all(type(d[k]) is bool for k in ("database_included", "homeassistant_included", "protected")))
    _require(type(d["size"]) is int and 0 <= d["size"] <= MAX_ARCHIVE_BYTES)
    _require(type(d["folders"]) is list and all(type(f) is str and f in ("share", "addons/local", "ssl", "media")
                                                 for f in d["folders"]))
    _require(type(d["extra_metadata"]) is dict and all(type(k) is str and type(v) in (str, bool)
                                                       for k, v in d["extra_metadata"].items()))
    _require(type(d["addons"]) is list)
    for item in d["addons"]:
        _require(type(item) is dict and item.keys() == {"name", "slug", "version"}
                 and type(item["slug"]) is str
                 and all(item[k] is None or type(item[k]) is str for k in ("name", "version")))
    _require(len(_encode(d)) <= MAX_METADATA_BYTES)
    return d


def _unique(pairs):
    result = dict(pairs)
    _require(len(result) == len(pairs))
    return result


def _digest_id(backup_id):
    return hashlib.sha256(backup_id.encode("ascii")).hexdigest()


def _safe_spool_name(name):
    return (type(name) is str and _SPOOL_NAME.fullmatch(name)
            and not re.fullmatch(r"(?i:con|prn|aux|nul|com[0-9]|lpt[0-9])", name.partition(".")[0]))


def _active(cancel):
    _require(not cancel.is_set())


def _fingerprint(st):
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns


@contextmanager
def _regular(path, size):
    st = path.lstat()
    _require(stat.S_ISREG(st.st_mode) and st.st_size == size and path.resolve() == path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        _require(_fingerprint(os.fstat(stream.fileno())) == _fingerprint(st))
        yield stream
        _require(_fingerprint(os.fstat(stream.fileno())) == _fingerprint(st)
                 and _fingerprint(path.lstat()) == _fingerprint(st))


def _digest(stream, cancel, expected_size):
    digest = hashlib.sha256()
    count = 0
    while True:
        _active(cancel)
        chunk = stream.read(1024 * 1024)
        if not chunk:
            break
        count += len(chunk)
        _require(count <= expected_size)
        digest.update(chunk)
    _require(count == expected_size)
    return digest.hexdigest()


class NativeStorage:
    def __init__(self, client, installation_id, private_root):
        _require(type(installation_id) is str and _INSTALL.fullmatch(installation_id))
        self._client = client
        self._installation_id = installation_id
        self._root = Path(private_root) / "native"
        _require(self._root.is_absolute() and ".." not in self._root.parts)

    @property
    def installation_id(self):
        return self._installation_id

    def _private_dir(self):
        _require(self._root.resolve() == self._root)
        self._root.mkdir(mode=0o700, parents=True, exist_ok=True)
        _require(self._root.is_dir() and self._root.resolve(strict=True) == self._root)
        return self._root

    def _ls(self, path, cancel):
        _active(cancel)
        out = self._client._run_json(("filesystem", "list", path, "--json"), cancel=cancel)
        _active(cancel)
        return self._client._parse_list(out.stdout, expected_parent=path)

    def _folder_exists(self, parent, name, cancel):
        for node in self._ls(parent, cancel):
            if node.name == name:
                _require(node.kind == "folder" and node.path == f"{parent}/{name}")
                return True
        return False

    def _info(self, path, cancel, *, size, uid):
        _active(cancel)
        node = self._client._run_node(("filesystem", "info", path, "--json"), cancel=cancel)
        _active(cancel)
        _require(node.kind == "file" and node.path == path and node.size == size and node.uid == uid)
        return node

    def _upload(self, local, remote_dir, size, cancel):
        _active(cancel)
        node = self._client._run_node(("filesystem", "upload", local.as_posix(), remote_dir,
                                       "--conflict-strategy", "skip", "--skip-thumbnails", "--json"), cancel=cancel)
        path = f"{remote_dir}/{local.name}"
        _require(node.path == path and node.kind == "file" and node.size == size)
        return self._info(path, cancel, size=size, uid=node.uid)

    @contextmanager
    def _download(self, node, cancel):
        # Only internally generated and validated manifest/archive names reach the CLI.
        self._info(node.path, cancel, size=node.size, uid=node.uid)
        with tempfile.TemporaryDirectory(dir=self._private_dir()) as tmp:
            directory = Path(tmp)
            out = self._client._run_json(("filesystem", "download", node.path, directory.as_posix(),
                                          "--conflict-strategy", "skip", "--json"), cancel=cancel)
            summary = _load_json(out.stdout)
            expected = {"transferredItems": 1, "transferredBytes": node.size, "skippedItems": 0, "failedItems": 0}
            _require(type(summary) is dict and summary.keys() == expected.keys() | {"failures"}
                     and summary["failures"] == [] and all(type(summary[k]) is int and summary[k] == v
                                                          for k, v in expected.items()))
            path = directory / node.name
            _require(list(directory.iterdir()) == [path])
            self._info(node.path, cancel, size=node.size, uid=node.uid)
            yield path

    def _read_record(self, node, base, match, cancel):
        _require(node.kind == "file" and 0 < node.size <= _MAX_MANIFEST_BYTES)
        with self._download(node, cancel) as path, _regular(path, node.size) as stream:
            doc = json.loads(stream.read(_MAX_MANIFEST_BYTES + 1).decode("utf-8"), object_pairs_hook=_unique)
        _require(type(doc) is dict and doc.keys() == {"v", "metadata", "archive"}
                 and type(doc["v"]) is int and doc["v"] == 1 and type(doc["metadata"]) is dict)
        metadata = doc["metadata"]
        backup_id = validate_backup_id(metadata.get("backup_id"))
        validate_metadata(backup_id, metadata)
        _require(_digest_id(backup_id) == match[1])
        a = doc["archive"]
        _require(type(a) is dict and a.keys() == {"name", "uid", "sha256", "size"}
                 and _safe_spool_name(a["name"]) and type(a["uid"]) is str
                 and type(a["size"]) is int and a["size"] == metadata["size"]
                 and type(a["sha256"]) is str and _HASH.fullmatch(a["sha256"]))
        archive = self._info(f"{base}/archives/{match[2]}/{a['name']}", cancel, size=a["size"], uid=a["uid"])
        return metadata, archive, a["sha256"]

    def _records(self, cancel, backup_id=None):
        records = {}
        if not self._folder_exists("/my-files", "HomeAssistant-Backups", cancel):
            return records
        installations = [n for n in self._ls(_PARENT, cancel) if n.kind == "folder" and _INSTALL.fullmatch(n.name)]
        _require(len(installations) <= _MAX_INSTALLATIONS)
        seen = 0
        key = _digest_id(backup_id) if backup_id else None
        for install in installations:
            base = f"{install.path}/native"
            if not self._folder_exists(install.path, "native", cancel) or not self._folder_exists(base, "manifests", cancel):
                continue
            for node in self._ls(f"{base}/manifests", cancel):
                match = _MANIFEST.fullmatch(node.name)
                if match is None or (key and match[1] != key):
                    continue
                seen += 1
                _require(seen <= _MAX_MANIFESTS)
                rec = self._read_record(node, base, match, cancel)
                id_ = rec[0]["backup_id"]
                _require(id_ not in records and (not backup_id or id_ == backup_id))
                records[id_] = rec
        return records

    def _lookup(self, backup_id, cancel):
        validate_backup_id(backup_id)
        rec = self._records(cancel, backup_id).get(backup_id)
        if rec is None:
            raise NativeBackupNotFound()
        return rec

    @_boundary
    def list_backups(self, cancel):
        return [rec[0] for rec in self._records(cancel).values()]

    @_boundary
    def get_backup(self, backup_id, cancel):
        return self._lookup(backup_id, cancel)[0]

    @_boundary
    def upload_backup(self, backup_id, metadata, path, cancel):
        validate_metadata(backup_id, metadata)
        _active(cancel)
        path = Path(path)
        _require(self._root in path.parents and path.resolve(strict=True) == path and _safe_spool_name(path.name))
        size = metadata["size"]
        nonce = uuid.uuid4().hex
        with _regular(path, size) as stream, tempfile.TemporaryDirectory(dir=self._private_dir()) as temp:
            initial = _fingerprint(os.fstat(stream.fileno()))
            digest = _digest(stream, cancel, size)
            existing = self._records(cancel, backup_id).get(backup_id)
            if existing is not None:
                _require(existing[0] == metadata and existing[2] == digest)
                # Proton revisions may replace the bytes while keeping UID and size.
                # An idempotent retry confirms the actual stored archive, not its label.
                with self._download(existing[1], cancel) as saved, _regular(saved, size) as check:
                    _require(_digest(check, cancel, size) == digest)
                _active(cancel)
                return metadata
            base = f"{_PARENT}/{self.installation_id}/native"
            for parent, name in (("/my-files", "HomeAssistant-Backups"), (_PARENT, self.installation_id),
                                 (f"{_PARENT}/{self.installation_id}", "native"), (base, "archives"), (base, "manifests")):
                _active(cancel)
                self._client._ensure_folder(parent, name, cancel=cancel)
            # Upload the caller's existing spool into a fresh namespace. This avoids
            # a second archive-sized local copy and keeps cancelled attempts distinct.
            slot = f"{base}/archives/{nonce}"
            _active(cancel)
            folder = self._client._run_node(("filesystem", "create-folder", base + "/archives", nonce, "--json"), cancel=cancel)
            _require(folder.kind == "folder" and folder.path == slot)
            archive = self._upload(path, slot, size, cancel)
            _require(_fingerprint(path.lstat()) == _fingerprint(os.fstat(stream.fileno())) == initial)
            # The manifest is the commit marker: discovery ignores an archive
            # without one. First upload checks remote identity and size; restore
            # and idempotent retry verify the bytes against this recorded hash.
            doc = {"v": 1, "metadata": metadata, "archive": {
                "name": archive.name, "uid": archive.uid, "size": size, "sha256": digest}}
            manifest = Path(temp) / f"ha1-{_digest_id(backup_id)}-{nonce}.json"
            blob = _encode(doc)
            _require(len(blob) <= _MAX_MANIFEST_BYTES)
            with manifest.open("xb") as file:
                file.write(blob)
            committed = self._upload(manifest, base + "/manifests", len(blob), cancel)
            with self._download(committed, cancel) as downloaded, _regular(downloaded, len(blob)) as check:
                _require(check.read(_MAX_MANIFEST_BYTES + 1) == blob)
            _active(cancel)
            return metadata

    @_boundary
    def download_backup(self, backup_id, cancel) -> NativeDownload:
        _, archive, digest = self._lookup(backup_id, cancel)
        with self._download(archive, cancel) as downloaded:
            with _regular(downloaded, archive.size) as stream:
                _require(_digest(stream, cancel, archive.size) == digest)
            _active(cancel)
            # Reserve our return name exclusively; replace only our empty placeholder.
            fd, name = tempfile.mkstemp(dir=self._private_dir(), prefix="restore-", suffix=".tar")
            os.close(fd)
            result = Path(name)
            try:
                downloaded.replace(result)
            except BaseException:
                result.unlink(missing_ok=True)
                raise
        return NativeDownload(result, archive.size)

    def delete_backup(self, backup_id, cancel):
        raise NativeDeleteUnsupported()
