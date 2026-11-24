from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from threading import Event
from typing import Callable

from .config import STABLE_OBSERVATIONS
from .models import StableBackup
from .state import ObservationSnapshot, ObservationUpdate, StateStore


_HASH_CHUNK_SIZE = 1024 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int
    file_type: int
    size: int
    mtime_ns: int


@dataclass(frozen=True)
class ScanBaseline:
    generation: int
    seen_at: datetime
    observations: tuple[ObservationSnapshot, ...]
    enqueued: tuple[tuple[Path, FileIdentity], ...]


@dataclass(frozen=True)
class CandidateEvidence:
    path: Path
    display_name: str
    size: int
    mtime_ns: int
    identity: FileIdentity
    sha256: str | None
    reset_observation: bool
    retain_enqueued: bool


class ScanDisposition(StrEnum):
    COMPLETE = "complete"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class ScanEvidence:
    generation: int
    seen_at: datetime
    disposition: ScanDisposition
    candidates: tuple[CandidateEvidence, ...]


@dataclass(frozen=True)
class ValidatedScanEvidence:
    evidence: ScanEvidence
    _nonce: object


class ScanValidation:
    """Lane-owned descriptors proving evidence until the owner acknowledges it."""

    def __init__(
        self,
        evidence: ScanEvidence,
        descriptors: tuple[int, ...],
        finalizer: Callable[[], bool] | None = None,
        issuer: Callable[[ScanValidation, ScanEvidence], ValidatedScanEvidence]
        | None = None,
    ) -> None:
        self.evidence = evidence
        self._descriptors = descriptors
        self._finalizer = finalizer
        self._issuer = issuer
        self._finished = False

    def close(self) -> bool:
        succeeded = True
        for descriptor in reversed(self._descriptors):
            try:
                os.close(descriptor)
            except OSError:
                succeeded = False
        self._descriptors = ()
        return succeeded

    def finish(self, cancel: Event) -> ValidatedScanEvidence:
        if self._finished:
            raise ValueError("scan validation was already finished")
        self._finished = True
        disposition = self.evidence.disposition
        if cancel.is_set():
            disposition = ScanDisposition.CANCELLED
        elif disposition is ScanDisposition.COMPLETE and self._finalizer is not None:
            try:
                if not self._finalizer():
                    disposition = ScanDisposition.FAILED
            except OSError:
                disposition = ScanDisposition.FAILED
        close_succeeded = self.close()
        if not close_succeeded and disposition is not ScanDisposition.CANCELLED:
            disposition = ScanDisposition.FAILED
        evidence = self.evidence
        if disposition is not self.evidence.disposition:
            evidence = ScanEvidence(
                self.evidence.generation,
                self.evidence.seen_at,
                disposition,
                () if disposition is not ScanDisposition.COMPLETE else self.evidence.candidates,
            )
        if self._issuer is None:
            return ValidatedScanEvidence(evidence, object())
        return self._issuer(self, evidence)


def _file_identity(value: os.stat_result) -> FileIdentity:
    return FileIdentity(
        value.st_dev,
        value.st_ino,
        stat.S_IFMT(value.st_mode),
        value.st_size,
        value.st_mtime_ns,
    )


def _same_file_state(left: os.stat_result, right: os.stat_result) -> bool:
    return _file_identity(left) == _file_identity(right)


def _secure_directory_descriptors_available() -> bool:
    return (
        hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NOFOLLOW")
        and os.open in os.supports_dir_fd
        and os.stat in os.supports_dir_fd
        and os.stat in os.supports_follow_symlinks
        and os.listdir in os.supports_fd
    )


class BackupScanner:
    """Collect filesystem evidence off-thread and apply it on the store owner."""

    def __init__(self, root: Path, store: StateStore) -> None:
        self.root = Path(os.path.abspath(root))
        self.store = store
        self._enqueued_identities: dict[Path, FileIdentity] = {}
        self._last_applied_generation = 0
        self._collected_evidence: dict[int, ScanEvidence] = {}
        self._pending_validations: dict[int, ScanValidation] = {}
        self._validated_evidence: dict[int, ValidatedScanEvidence] = {}

    def scan(self, now: datetime) -> list[StableBackup]:
        """Synchronous compatibility wrapper around the split scan contract."""
        generation = self._last_applied_generation + 1
        baseline = self.prepare_scan(generation, now)
        evidence = self.collect_scan(baseline, Event())
        validation_cancel = Event()
        validation = self.validate_scan(evidence, validation_cancel)
        return self.apply_scan(validation.finish(validation_cancel), generation)

    def prepare_scan(self, generation: int, now: datetime) -> ScanBaseline:
        if (
            type(generation) is not int
            or generation <= self._last_applied_generation
            or not isinstance(now, datetime)
            or now.tzinfo is None
        ):
            raise ValueError("invalid scan generation")
        observations = self.store.observation_snapshot()
        return ScanBaseline(
            generation,
            now,
            observations,
            tuple(sorted(self._enqueued_identities.items(), key=lambda item: str(item[0]))),
        )

    def collect_scan(self, baseline: ScanBaseline, cancel: Event) -> ScanEvidence:
        if type(baseline) is not ScanBaseline or not isinstance(cancel, Event):
            raise ValueError("invalid scan collection request")
        if cancel.is_set():
            return self._evidence(baseline, ScanDisposition.CANCELLED, ())
        if not _secure_directory_descriptors_available():
            return self._evidence(baseline, ScanDisposition.FAILED, ())
        opened_root = self._open_root()
        if opened_root is None:
            return self._evidence(baseline, ScanDisposition.FAILED, ())
        root_descriptor, root_state = opened_root
        disposition = ScanDisposition.COMPLETE
        candidates: list[CandidateEvidence] = []
        observations = {item.path: item for item in baseline.observations}
        enqueued = dict(baseline.enqueued)
        try:
            if cancel.is_set():
                disposition = ScanDisposition.CANCELLED
                names: list[str] = []
            else:
                try:
                    names = sorted(os.listdir(root_descriptor))
                except OSError:
                    disposition = ScanDisposition.FAILED
                    names = []
            if disposition is ScanDisposition.COMPLETE and cancel.is_set():
                disposition = ScanDisposition.CANCELLED
            if disposition is ScanDisposition.COMPLETE:
                for name in names:
                    if cancel.is_set():
                        disposition = ScanDisposition.CANCELLED
                        break
                    candidate_disposition, candidate = self._collect_candidate(
                        root_descriptor,
                        name,
                        observations,
                        enqueued,
                        cancel,
                    )
                    if candidate_disposition is not ScanDisposition.COMPLETE:
                        disposition = candidate_disposition
                        break
                    if candidate is not None:
                        candidates.append(candidate)
                    if cancel.is_set():
                        disposition = ScanDisposition.CANCELLED
                        break
            if disposition is ScanDisposition.COMPLETE:
                if cancel.is_set():
                    disposition = ScanDisposition.CANCELLED
                elif not self._root_still_valid(root_state):
                    disposition = ScanDisposition.FAILED
                elif cancel.is_set():
                    disposition = ScanDisposition.CANCELLED
        finally:
            try:
                os.close(root_descriptor)
            except OSError:
                disposition = ScanDisposition.FAILED
        return self._evidence(baseline, disposition, tuple(candidates))

    def validate_scan(
        self, evidence: ScanEvidence, cancel: Event
    ) -> ScanValidation:
        """Revalidate collected evidence and hold descriptors through owner apply."""
        if type(evidence) is not ScanEvidence or not isinstance(cancel, Event):
            raise ValueError("invalid scan validation request")
        if self._collected_evidence.pop(evidence.generation, None) is not evidence:
            raise ValueError("scan evidence was not collected by this scanner")
        if evidence.disposition is not ScanDisposition.COMPLETE:
            return self._new_validation(evidence, ())
        if cancel.is_set() or not _secure_directory_descriptors_available():
            return self._new_validation(
                ScanEvidence(
                    evidence.generation,
                    evidence.seen_at,
                    ScanDisposition.CANCELLED
                    if cancel.is_set()
                    else ScanDisposition.FAILED,
                    (),
                ),
                (),
            )
        opened_root = self._open_root()
        if opened_root is None:
            return self._new_validation(
                ScanEvidence(
                    evidence.generation,
                    evidence.seen_at,
                    ScanDisposition.FAILED,
                    (),
                ),
                (),
            )
        root_descriptor, root_state = opened_root
        descriptors = [root_descriptor]
        disposition = ScanDisposition.COMPLETE
        try:
            for candidate in evidence.candidates:
                if cancel.is_set():
                    disposition = ScanDisposition.CANCELLED
                    break
                try:
                    before = os.stat(
                        candidate.display_name,
                        dir_fd=root_descriptor,
                        follow_symlinks=False,
                    )
                    if _file_identity(before) != candidate.identity:
                        disposition = ScanDisposition.FAILED
                        break
                    flags = (
                        os.O_RDONLY
                        | os.O_NOFOLLOW
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_BINARY", 0)
                    )
                    descriptor = os.open(
                        candidate.display_name,
                        flags,
                        dir_fd=root_descriptor,
                    )
                    descriptors.append(descriptor)
                    opened = os.fstat(descriptor)
                except OSError:
                    disposition = ScanDisposition.FAILED
                    break
                if _file_identity(opened) != candidate.identity:
                    disposition = ScanDisposition.FAILED
                    break
                if candidate.sha256 is not None:
                    digest = hashlib.sha256()
                    while True:
                        if cancel.is_set():
                            disposition = ScanDisposition.CANCELLED
                            break
                        try:
                            chunk = os.read(descriptor, _HASH_CHUNK_SIZE)
                        except OSError:
                            disposition = ScanDisposition.FAILED
                            break
                        if cancel.is_set():
                            disposition = ScanDisposition.CANCELLED
                            break
                        if not chunk:
                            break
                        digest.update(chunk)
                    if (
                        disposition is ScanDisposition.COMPLETE
                        and digest.hexdigest() != candidate.sha256
                    ):
                        disposition = ScanDisposition.FAILED
                if disposition is not ScanDisposition.COMPLETE:
                    break
                try:
                    finished = os.fstat(descriptor)
                    rebound = os.stat(
                        candidate.display_name,
                        dir_fd=root_descriptor,
                        follow_symlinks=False,
                    )
                except OSError:
                    disposition = ScanDisposition.FAILED
                    break
                if (
                    _file_identity(finished) != candidate.identity
                    or _file_identity(rebound) != candidate.identity
                ):
                    disposition = ScanDisposition.FAILED
                    break
            if disposition is ScanDisposition.COMPLETE:
                if cancel.is_set():
                    disposition = ScanDisposition.CANCELLED
                elif not self._root_still_valid(root_state):
                    disposition = ScanDisposition.FAILED
        except BaseException:
            for descriptor in reversed(descriptors):
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            raise
        if disposition is ScanDisposition.COMPLETE:
            def finalize() -> bool:
                if not self._root_still_valid(root_state):
                    return False
                for descriptor, candidate in zip(
                    descriptors[1:], evidence.candidates, strict=True
                ):
                    current = os.fstat(descriptor)
                    rebound = os.stat(
                        candidate.display_name,
                        dir_fd=root_descriptor,
                        follow_symlinks=False,
                    )
                    if (
                        _file_identity(current) != candidate.identity
                        or _file_identity(rebound) != candidate.identity
                    ):
                        return False
                return True

            return self._new_validation(evidence, tuple(descriptors), finalize)
        close_failed = False
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                close_failed = True
        if close_failed and disposition is not ScanDisposition.CANCELLED:
            disposition = ScanDisposition.FAILED
        return self._new_validation(
            ScanEvidence(evidence.generation, evidence.seen_at, disposition, ()),
            (),
        )

    def apply_scan(
        self, validated: ValidatedScanEvidence, current_generation: int
    ) -> list[StableBackup]:
        if (
            type(validated) is not ValidatedScanEvidence
            or type(validated.evidence) is not ScanEvidence
            or type(current_generation) is not int
        ):
            raise ValueError("invalid scan evidence")
        evidence = validated.evidence
        registered = self._validated_evidence.get(evidence.generation)
        if registered is not validated or registered._nonce is not validated._nonce:
            raise ValueError("scan validation capability is invalid")
        del self._validated_evidence[evidence.generation]
        if (
            evidence.generation != current_generation
            or evidence.generation <= self._last_applied_generation
        ):
            return []
        if evidence.disposition is ScanDisposition.CANCELLED:
            self._last_applied_generation = evidence.generation
            return []
        if evidence.disposition is ScanDisposition.FAILED:
            self.store.apply_observation_batch((), (), evidence.seen_at)
            self._enqueued_identities.clear()
            self._last_applied_generation = evidence.generation
            return []
        if evidence.disposition is not ScanDisposition.COMPLETE:
            raise ValueError("invalid scan disposition")
        candidates = self._validate_candidates(evidence.candidates)
        updates = tuple(
            ObservationUpdate(
                candidate.path,
                candidate.size,
                candidate.mtime_ns,
                candidate.reset_observation,
            )
            for candidate in candidates
        )
        ready = tuple(
            StableBackup(
                candidate.path,
                candidate.display_name,
                candidate.size,
                candidate.mtime_ns,
                candidate.sha256,
            )
            for candidate in candidates
            if candidate.sha256 is not None
        )
        self.store.apply_observation_batch(updates, ready, evidence.seen_at)
        self._enqueued_identities = {
            candidate.path: candidate.identity
            for candidate in candidates
            if candidate.retain_enqueued or candidate.sha256 is not None
        }
        self._last_applied_generation = evidence.generation
        return list(ready)

    def _collect_candidate(
        self,
        root_descriptor: int,
        name: str,
        observations: dict[Path, ObservationSnapshot],
        enqueued: dict[Path, FileIdentity],
        cancel: Event,
    ) -> tuple[ScanDisposition, CandidateEvidence | None]:
        if not isinstance(name, str) or Path(name).name != name or Path(name).suffix != ".tar":
            return ScanDisposition.COMPLETE, None
        if cancel.is_set():
            return ScanDisposition.CANCELLED, None
        candidate = self.root / name
        try:
            before = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
        except OSError:
            return ScanDisposition.FAILED, None
        if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
            return ScanDisposition.COMPLETE, None
        if cancel.is_set():
            return ScanDisposition.CANCELLED, None
        try:
            flags = (
                os.O_RDONLY
                | os.O_NOFOLLOW
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_BINARY", 0)
            )
            file_descriptor = os.open(name, flags, dir_fd=root_descriptor)
        except OSError:
            return ScanDisposition.FAILED, None

        disposition = ScanDisposition.COMPLETE
        evidence: CandidateEvidence | None = None
        try:
            if cancel.is_set():
                disposition = ScanDisposition.CANCELLED
            else:
                try:
                    opened = os.fstat(file_descriptor)
                except OSError:
                    disposition = ScanDisposition.FAILED
                    opened = None
                if (
                    disposition is ScanDisposition.COMPLETE
                    and (
                        opened is None
                        or not stat.S_ISREG(opened.st_mode)
                        or not _same_file_state(before, opened)
                    )
                ):
                    disposition = ScanDisposition.FAILED
                if disposition is ScanDisposition.COMPLETE and cancel.is_set():
                    disposition = ScanDisposition.CANCELLED
                if disposition is ScanDisposition.COMPLETE and opened is not None:
                    identity = _file_identity(opened)
                    cached = enqueued.get(candidate)
                    retain_enqueued = cached == identity
                    reset_observation = cached is not None and not retain_enqueued
                    observation = observations.get(candidate)
                    needs_hash = (
                        not retain_enqueued
                        and not reset_observation
                        and observation is not None
                        and observation.size == opened.st_size
                        and observation.mtime_ns == opened.st_mtime_ns
                        and observation.count + 1 >= STABLE_OBSERVATIONS
                    )
                    digest_value: str | None = None
                    finished = opened
                    if needs_hash:
                        digest = hashlib.sha256()
                        while True:
                            if cancel.is_set():
                                disposition = ScanDisposition.CANCELLED
                                break
                            try:
                                chunk = os.read(file_descriptor, _HASH_CHUNK_SIZE)
                            except OSError:
                                disposition = ScanDisposition.FAILED
                                break
                            if cancel.is_set():
                                disposition = ScanDisposition.CANCELLED
                                break
                            if not chunk:
                                break
                            digest.update(chunk)
                        if disposition is ScanDisposition.COMPLETE:
                            try:
                                finished = os.fstat(file_descriptor)
                            except OSError:
                                disposition = ScanDisposition.FAILED
                            if (
                                disposition is ScanDisposition.COMPLETE
                                and not _same_file_state(opened, finished)
                            ):
                                disposition = ScanDisposition.FAILED
                            if disposition is ScanDisposition.COMPLETE and cancel.is_set():
                                disposition = ScanDisposition.CANCELLED
                            if disposition is ScanDisposition.COMPLETE:
                                digest_value = digest.hexdigest()
                    if disposition is ScanDisposition.COMPLETE:
                        evidence = CandidateEvidence(
                            candidate,
                            name,
                            finished.st_size,
                            finished.st_mtime_ns,
                            _file_identity(finished),
                            digest_value,
                            reset_observation,
                            retain_enqueued,
                        )
        finally:
            try:
                os.close(file_descriptor)
            except OSError:
                disposition = ScanDisposition.FAILED
                evidence = None
        return disposition, evidence

    def _open_root(self) -> tuple[int, os.stat_result] | None:
        try:
            before = self.root.lstat()
            if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
                return None
            if self.root.resolve(strict=True) != self.root:
                return None
            flags = (
                os.O_RDONLY
                | os.O_DIRECTORY
                | os.O_NOFOLLOW
                | getattr(os, "O_CLOEXEC", 0)
            )
            descriptor = os.open(self.root, flags)
        except OSError:
            return None
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISDIR(opened.st_mode) or not _same_file_state(before, opened):
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                return None
            return descriptor, opened
        except OSError:
            try:
                os.close(descriptor)
            except OSError:
                pass
            return None

    def _root_still_valid(self, opened: os.stat_result) -> bool:
        try:
            current = self.root.lstat()
            return (
                stat.S_ISDIR(current.st_mode)
                and not stat.S_ISLNK(current.st_mode)
                and self.root.resolve(strict=True) == self.root
                and _same_file_state(opened, current)
            )
        except OSError:
            return False

    def _validate_candidates(
        self, candidates: tuple[CandidateEvidence, ...]
    ) -> tuple[CandidateEvidence, ...]:
        if not isinstance(candidates, tuple) or any(
            type(candidate) is not CandidateEvidence
            or not isinstance(candidate.path, Path)
            or candidate.path.parent != self.root
            or candidate.path.name != candidate.display_name
            or candidate.path.suffix != ".tar"
            or type(candidate.identity) is not FileIdentity
            or candidate.identity.file_type != stat.S_IFREG
            or candidate.identity.size != candidate.size
            or candidate.identity.mtime_ns != candidate.mtime_ns
            or (candidate.sha256 is not None and _SHA256.fullmatch(candidate.sha256) is None)
            or type(candidate.reset_observation) is not bool
            or type(candidate.retain_enqueued) is not bool
            or (candidate.reset_observation and candidate.retain_enqueued)
            for candidate in candidates
        ):
            raise ValueError("invalid scan candidate evidence")
        if len({candidate.path for candidate in candidates}) != len(candidates):
            raise ValueError("duplicate scan candidate evidence")
        return candidates

    def _evidence(
        self,
        baseline: ScanBaseline,
        disposition: ScanDisposition,
        candidates: tuple[CandidateEvidence, ...],
    ) -> ScanEvidence:
        evidence = ScanEvidence(
            baseline.generation,
            baseline.seen_at,
            disposition,
            candidates,
        )
        self._collected_evidence[baseline.generation] = evidence
        return evidence

    def _new_validation(
        self,
        evidence: ScanEvidence,
        descriptors: tuple[int, ...],
        finalizer: Callable[[], bool] | None = None,
    ) -> ScanValidation:
        validation = ScanValidation(
            evidence,
            descriptors,
            finalizer,
            self._mint_validated_evidence,
        )
        self._pending_validations[id(validation)] = validation
        return validation

    def _mint_validated_evidence(
        self, validation: ScanValidation, evidence: ScanEvidence
    ) -> ValidatedScanEvidence:
        if self._pending_validations.pop(id(validation), None) is not validation:
            raise ValueError("scan validation capability is invalid")
        nonce = object()
        validated = ValidatedScanEvidence(evidence, nonce)
        self._validated_evidence[evidence.generation] = validated
        return validated
