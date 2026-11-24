from __future__ import annotations

import os
import re
import signal
import subprocess
import time
import math
from collections.abc import Mapping, Sequence
from threading import Event, Lock, Thread, current_thread
from typing import Callable
from urllib.parse import unquote, urlsplit

from .models import CommandResult
from .redaction import REDACTED, redact


_SENSITIVE_OPTION = re.compile(
    r"(?i)^--?(?:password|passwd|passphrase|otp|2fa(?:-code)?|token|"
    r"access-token|refresh-token|cookie|authorization|login-url)$"
)
_SENSITIVE_HEADER_LINE = re.compile(
    r"(?i)\b(?:authorization|proxy-authorization|cookie|set-cookie)\s*:"
)
_PRIVATE_ROOT = "/data/private"
_MAX_CAPTURE_CHARS = 2_097_152
_MAX_STREAM_LINE_CHARS = 4_097
_TERMINATE_GRACE_SECONDS = 10
_LOCALE_ENVIRONMENT_NAMES = ("LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE")
_LOGIN_URL = re.compile(r"(?i)https?://[^\s<>\"']+")
_INVALID_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_LOGIN_URL_MAX_CHARS = 4_096
_MAX_SECRET_STREAM_LINE_CHARS = _LOGIN_URL_MAX_CHARS + 256
_LOGIN_URL_MAX_LIFETIME_SECONDS = 600
_ACTIVE_READER_LOCK = Lock()
_ACTIVE_READER_THREADS: set[Thread] = set()


def _error_hint(chunk: str) -> str:
    """Return a fixed hint, never an excerpt of possibly secret stderr."""
    lowered = chunk.casefold()
    for category, markers in (
        ("certificate", ("certificate", "unable to verify")),
        ("network", ("enotfound", "eai_again", "econnrefused", "econnreset", "network is unreachable", "fetch failed")),
        ("permissions", ("eacces", "eperm", "permission denied", "read-only file system", "erofs")),
        ("runtime", ("error loading shared library", "cannot find module", "symbol not found", "illegal instruction")),
        ("usage", ("unknown command", "unknown option", "unexpected argument")),
        ("credentials", ("credential", "password store", "password-store", "gnupg", "gpg:", "pinentry")),
    ):
        if any(marker in lowered for marker in markers):
            return category
    return "unknown"


def active_process_reader_threads() -> tuple[Thread, ...]:
    """Return every live pipe reader so service shutdown cannot claim clean."""
    with _ACTIVE_READER_LOCK:
        return tuple(
            reader for reader in _ACTIVE_READER_THREADS if reader.is_alive()
        )


class ProtonLoginSecretEvent:
    """Deliver one allowlisted Proton login URL without exposing its source line."""

    def __init__(
        self,
        consumer: Callable[[str], None],
        *,
        expires_at: float,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        now = monotonic()
        if (
            not callable(consumer)
            or not callable(monotonic)
            or isinstance(expires_at, bool)
            or not isinstance(expires_at, (int, float))
            or expires_at <= now
            or expires_at > now + _LOGIN_URL_MAX_LIFETIME_SECONDS
        ):
            raise ValueError("Invalid Proton login secret event")
        self._consumer = consumer
        self._expires_at = float(expires_at)
        self._monotonic = monotonic
        self._delivered = False

    def inspect(self, raw_line: str, *, truncated: bool = False) -> None:
        if truncated or self._monotonic() >= self._expires_at:
            raise _SecretEventError
        value = _extract_proton_login_url(raw_line)
        if value is None:
            return
        if self._delivered or not isinstance(value, str) or not value:
            raise _SecretEventError
        self._consumer(value)
        self._delivered = True

    def finish(self) -> None:
        if not self._delivered:
            raise _SecretEventError


class _SecretEventError(RuntimeError):
    pass


def _extract_proton_login_url(raw_line: str) -> str | None:
    if (
        not isinstance(raw_line, str)
        or len(raw_line) > _LOGIN_URL_MAX_CHARS + 256
        or any(ord(character) < 32 or ord(character) > 126 for character in raw_line)
    ):
        raise _SecretEventError
    candidates = _LOGIN_URL.findall(raw_line)
    if not candidates:
        return None
    if len(candidates) != 1:
        raise _SecretEventError
    url = candidates[0]
    if len(url) > _LOGIN_URL_MAX_CHARS or _INVALID_PERCENT_ESCAPE.search(url):
        raise _SecretEventError
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        username = parsed.username
        password = parsed.password
        port = parsed.port
    except ValueError:
        raise _SecretEventError from None
    if (
        parsed.scheme != "https"
        or hostname is None
        or not (hostname == "proton.me" or hostname.endswith(".proton.me"))
        or username is not None
        or password is not None
        or port not in (None, 443)
        or "%" in parsed.netloc
        or "%" in parsed.path
    ):
        raise _SecretEventError
    decoded_path = unquote(parsed.path)
    decoded_query = unquote(parsed.query)
    allowed_path = (
        decoded_path == "/login"
        or decoded_path.startswith("/login/")
        or decoded_path == "/auth"
        or decoded_path.startswith("/auth/")
        or decoded_path == "/oauth/authorize"
        or re.fullmatch(r"/u/[0-9]+/authorize", decoded_path) is not None
    )
    # CLI 0.7.0 carries a session-fork code and 32-byte base64 key in
    # this exact account route. Fragments remain forbidden on other routes.
    allowed_desktop = (
        hostname == "account.proton.me"
        and decoded_path == "/desktop/login"
        and parsed.query == "app=drive&pv=3"
        and re.fullmatch(
            r"payload=0:[A-Za-z0-9_+/=-]+:[A-Za-z0-9+/]{43}=:(?:cli-drive|external-drive)",
            unquote(parsed.fragment),
        ) is not None
    )
    if (not (allowed_path or allowed_desktop)
        or (parsed.fragment and not allowed_desktop)
        or "%" in decoded_query or any(
        ord(character) < 32 or ord(character) > 126
        for character in decoded_path + decoded_query
    )):
        raise _SecretEventError
    return url


def _private_value(value: object, default: str) -> str:
    if not isinstance(value, str) or "\0" in value:
        return default
    normalized = value.rstrip("/")
    if not normalized.startswith(f"{_PRIVATE_ROOT}/"):
        return default
    if ".." in normalized.split("/"):
        return default
    return normalized


class ProcessRunner:
    def __init__(self, environment: Mapping[str, str] | None = None):
        source = dict(os.environ if environment is None else environment)
        self._environment = _safe_environment(source)

    def run(
        self,
        args: Sequence[str],
        *,
        timeout: float,
        cancel: Event,
        on_stdout_line: Callable[[str], None] | None = None,
        secret_event: ProtonLoginSecretEvent | None = None,
    ) -> CommandResult:
        command = _validate_args(args)
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("Invalid process timeout")
        if secret_event is not None and type(secret_event) is not ProtonLoginSecretEvent:
            raise ValueError("Invalid secret event")
        safe_args, secrets = _sanitize_args(command)
        try:
            process = subprocess.Popen(
                command,
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                start_new_session=True,
                env=self._environment,
                creationflags=(
                    subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
                ),
            )
        except (OSError, ValueError):
            raise ProcessExecutionError("Unable to start process", failure_kind="spawn_failed") from None

        force_output_redaction = bool(secrets) or secret_event is not None
        stdout_capture = _OutputCapture(
            on_stdout_line,
            force_output_redaction,
            secret_event=secret_event,
            discard_capture=secret_event is not None,
        )
        stderr_capture = _OutputCapture(
            force_redaction=force_output_redaction,
            discard_capture=secret_event is not None,
            classify_errors=secret_event is not None,
        )
        readers = (
            _PipeReader(stdout_capture, process.stdout, "process-stdout"),
            _PipeReader(stderr_capture, process.stderr, "process-stderr"),
        )
        for reader in readers:
            reader.start()

        timed_out = False
        cancelled = False
        cleanup_succeeded = True
        deadline = time.monotonic() + timeout
        while True:
            if stdout_capture.failure.is_set():
                cleanup_succeeded = _terminate_process_group(process)
                break
            leader_exited = _safe_poll(process) is not None
            readers_finished = (
                stdout_capture.done.is_set() and stderr_capture.done.is_set()
            )
            if leader_exited and readers_finished:
                break
            if cancel.is_set():
                cancelled = True
                cleanup_succeeded = _terminate_process_group(process)
                break
            if time.monotonic() >= deadline:
                timed_out = True
                cleanup_succeeded = _terminate_process_group(process)
                break
            cancel.wait(min(0.05, max(0.0, deadline - time.monotonic())))

        if _safe_poll(process) is None:
            cleanup_succeeded = _safe_wait(process, 1) and cleanup_succeeded
        for reader in readers:
            reader.join(1)
        failure_details = {
            "exit_code": _safe_poll(process),
            "stdout_seen": stdout_capture.had_output,
            "stderr_seen": stderr_capture.had_output,
            "stderr_hint": stderr_capture.error_hint,
        }
        if any(reader.is_alive() for reader in readers) or not cleanup_succeeded:
            raise ProcessExecutionError("Unable to clean up process", failure_kind="cleanup_failed", **failure_details)
        if stdout_capture.failure.is_set():
            raise ProcessExecutionError("Unable to process secret event", failure_kind=stdout_capture.failure_kind, **failure_details)
        if secret_event is not None and not (cancelled or timed_out):
            try:
                secret_event.finish()
            except Exception:
                raise ProcessExecutionError("Unable to process secret event", failure_kind="no_url", **failure_details) from None

        returncode = _safe_poll(process)
        stdout = stdout_capture.text()
        stderr = stderr_capture.text()
        if secret_event is not None:
            stdout = REDACTED if stdout_capture.had_output else ""
            stderr = REDACTED if stderr_capture.had_output else ""
        return CommandResult(
            safe_args,
            returncode if returncode is not None else -1,
            _redact_known_secrets(stdout, secrets, max_chars=_MAX_CAPTURE_CHARS),
            _redact_known_secrets(stderr, secrets),
            timed_out=timed_out,
            cancelled=cancelled,
        )


class ProcessExecutionError(RuntimeError):
    """A neutral process-boundary failure that contains no command details."""

    def __init__(self, message, *, failure_kind="unknown", exit_code=None,
                 stdout_seen=False, stderr_seen=False, stderr_hint="unknown"):
        super().__init__(message)
        self.failure_kind = (failure_kind if type(failure_kind) is str and failure_kind in
                             {"spawn_failed", "cleanup_failed", "secret_rejected", "reader_failed", "no_url"}
                             else "unknown")
        self.exit_code = exit_code if type(exit_code) is int and -255 <= exit_code <= 255 else None
        self.stdout_seen = stdout_seen is True
        self.stderr_seen = stderr_seen is True
        self.stderr_hint = (stderr_hint if type(stderr_hint) is str and stderr_hint in
                            {"certificate", "network", "permissions", "runtime", "usage", "credentials"}
                            else "unknown")


class _PipeReader:
    """Own one pipe descriptor and expose its daemon thread to shutdown."""

    def __init__(self, capture: _OutputCapture, stream: object, name: str) -> None:
        self._capture = capture
        self._stream = stream
        self._thread = Thread(target=self._run, name=name, daemon=True)

    def start(self) -> None:
        with _ACTIVE_READER_LOCK:
            _ACTIVE_READER_THREADS.add(self._thread)
        try:
            self._thread.start()
        except BaseException:
            with _ACTIVE_READER_LOCK:
                _ACTIVE_READER_THREADS.discard(self._thread)
            raise

    def join(self, timeout: float) -> None:
        self._thread.join(timeout)

    def is_alive(self) -> bool:
        return self._thread.is_alive()

    def _run(self) -> None:
        try:
            self._capture.read(self._stream)
        finally:
            try:
                if self._stream is not None:
                    self._stream.close()
            except Exception:
                pass
            self._capture.done.set()
            with _ACTIVE_READER_LOCK:
                _ACTIVE_READER_THREADS.discard(current_thread())


class _OutputCapture:
    def __init__(
        self,
        on_line: Callable[[str], None] | None = None,
        force_redaction: bool = False,
        secret_event: ProtonLoginSecretEvent | None = None,
        discard_capture: bool = False,
        classify_errors: bool = False,
    ):
        self._chunks: list[str] = []
        self._captured = 0
        self._truncated = False
        self._on_line = on_line
        self._line = ""
        self._discard_line_tail = False
        self._previous_line_was_sensitive_header = False
        self._force_redaction = force_redaction
        self._secret_event = secret_event
        self._discard_capture = discard_capture
        self._classify_errors = classify_errors
        self.error_hint = "unknown"
        self.failure_kind = "reader_failed"
        self.had_output = False
        self.done = Event()
        self.failure = Event()

    def read(self, stream: object) -> None:
        try:
            if stream is None:
                return
            while True:
                chunk = stream.readline(4_096)
                if not chunk:
                    break
                self.had_output = True
                if self._classify_errors and self.error_hint == "unknown":
                    self.error_hint = _error_hint(chunk)
                if not self._discard_capture:
                    remaining = _MAX_CAPTURE_CHARS - self._captured
                    if len(chunk) > remaining:
                        self._truncated = True
                    if remaining > 0:
                        kept = chunk[:remaining]
                        self._chunks.append(kept)
                        self._captured += len(kept)
                if self._on_line is not None or self._secret_event is not None:
                    self._feed_lines(chunk)
            if (
                self._on_line is not None or self._secret_event is not None
            ) and (self._line or self._discard_line_tail):
                self._emit_line()
        except _SecretEventError:
            self.failure_kind = "secret_rejected"
            self.failure.set()
        except Exception:
            self.failure.set()

    def _feed_lines(self, chunk: str) -> None:
        for character in chunk:
            if character == "\n":
                self._emit_line()
            elif not self._discard_line_tail:
                line_limit = (
                    _MAX_SECRET_STREAM_LINE_CHARS
                    if self._secret_event is not None
                    else _MAX_STREAM_LINE_CHARS
                )
                if len(self._line) < line_limit:
                    self._line += character
                else:
                    self._discard_line_tail = True

    def _emit_line(self) -> None:
        line = self._line[:-1] if self._line.endswith("\r") else self._line
        if self._secret_event is not None:
            self._secret_event.inspect(line, truncated=self._discard_line_tail)
        is_continuation = line.startswith((" ", "\t"))
        if self._force_redaction:
            safe_line = REDACTED
        elif is_continuation and self._previous_line_was_sensitive_header:
            safe_line = REDACTED
        else:
            safe_line = redact(line)
        if not is_continuation:
            self._previous_line_was_sensitive_header = bool(
                _SENSITIVE_HEADER_LINE.search(line)
            )
        try:
            self._on_line(safe_line)  # type: ignore[misc]
        except Exception:
            # A consumer cannot be allowed to strand the child or its pipe readers.
            pass
        self._line = ""
        self._discard_line_tail = False

    def text(self) -> str:
        return "".join(self._chunks) + ("[TRUNCATED]" if self._truncated else "")


def _terminate_process_group(process: subprocess.Popen[str]) -> bool:
    if os.name == "nt":
        return _terminate_windows_tree(process)

    process_group = process.pid
    term_sent = _signal_process_group(process_group, signal.SIGTERM)
    if not term_sent:
        _safe_terminate(process)
        _safe_wait(process, 1)
    else:
        deadline = time.monotonic() + _TERMINATE_GRACE_SECONDS
        _safe_wait(process, _TERMINATE_GRACE_SECONDS)
        while time.monotonic() < deadline:
            if _process_group_exists(process_group) is False:
                break
            time.sleep(0.05)
    group_exists = _process_group_exists(process_group)
    if group_exists is not False:
        if not _signal_process_group(process_group, signal.SIGKILL):
            _safe_kill(process)
    if _safe_poll(process) is None:
        if not _safe_wait(process, 1):
            _safe_kill(process)
    return _safe_wait(process, 1)


def _signal_process_group(process_group: int, sig: int) -> bool:
    try:
        os.killpg(process_group, sig)
    except ProcessLookupError:
        return True
    except OSError:
        return False
    return True


def _process_group_exists(process_group: int) -> bool | None:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return None
    return True


def _terminate_windows_tree(process: subprocess.Popen[str]) -> bool:
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    system_directory = os.path.join(system_root, "System32")
    try:
        subprocess.run(
            [
                os.path.join(system_directory, "taskkill.exe"),
                "/PID",
                str(process.pid),
                "/T",
                "/F",
            ],
            shell=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=_TERMINATE_GRACE_SECONDS,
            check=False,
            env={"PATH": system_directory, "SystemRoot": system_root},
        )
    except (OSError, subprocess.SubprocessError):
        pass
    if _safe_poll(process) is None:
        _safe_kill(process)
    return _safe_wait(process, 1)


def _safe_poll(process: subprocess.Popen[str]) -> int | None:
    try:
        return process.poll()
    except (OSError, subprocess.SubprocessError):
        return None


def _safe_wait(process: subprocess.Popen[str], timeout: float) -> bool:
    try:
        process.wait(timeout=timeout)
        return True
    except subprocess.TimeoutExpired:
        return False
    except (OSError, subprocess.SubprocessError):
        return _safe_poll(process) is not None


def _safe_terminate(process: subprocess.Popen[str]) -> bool:
    try:
        process.terminate()
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def _safe_kill(process: subprocess.Popen[str]) -> bool:
    try:
        process.kill()
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def _validate_args(args: Sequence[str]) -> list[str]:
    if isinstance(args, (str, bytes)) or not args:
        raise ValueError("Invalid process arguments")
    if any(not isinstance(arg, str) or "\0" in arg for arg in args):
        raise ValueError("Invalid process arguments")
    command = list(args)
    if not command[0]:
        raise ValueError("Invalid process arguments")
    return command


def _safe_environment(source: Mapping[str, str]) -> dict[str, str]:
    environment: dict[str, str] = {
        "PATH": source.get("PATH", os.defpath),
        "HOME": f"{_PRIVATE_ROOT}/home",
        "GNUPGHOME": _private_value(
            source.get("GNUPGHOME"), f"{_PRIVATE_ROOT}/gnupg"
        ),
        "PASSWORD_STORE_DIR": _private_value(
            source.get("PASSWORD_STORE_DIR"), f"{_PRIVATE_ROOT}/pass"
        ),
        "PROTON_DRIVE_CREDENTIALS_STORE": "pass",
        "PROTON_DRIVE_CACHE_DIR": _private_value(
            source.get("PROTON_DRIVE_CACHE_DIR"), f"{_PRIVATE_ROOT}/proton"
        ),
        "PROTON_DRIVE_LOG_LEVEL": "ERROR",
    }
    for name in _LOCALE_ENVIRONMENT_NAMES:
        value = source.get(name)
        if isinstance(value, str) and "\0" not in value:
            environment[name] = value
    return environment


def _sanitize_args(args: Sequence[str]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    safe: list[str] = []
    secrets: list[str] = []
    redact_next = False
    for arg in args:
        if redact_next:
            secrets.append(arg)
            safe.append(REDACTED)
            redact_next = False
            continue
        option, separator, value = arg.partition("=")
        if _SENSITIVE_OPTION.fullmatch(option):
            safe.append(f"{option}={REDACTED}" if separator else option)
            if separator:
                secrets.append(value)
            else:
                redact_next = True
            continue
        safe.append(redact(arg))
    return tuple(safe), tuple(secret for secret in secrets if secret)


def _redact_known_secrets(text: str, secrets: Sequence[str], *, max_chars: int = 16_384) -> str:
    if secrets:
        return REDACTED if text else ""
    safe = text
    return redact(safe, max_chars=max_chars)
