from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Mapping
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from queue import Full, Queue
from threading import RLock
from urllib.parse import urlsplit

from .redaction import redact
from .worker import MAX_RETRY_REVISION, ServiceSnapshot


MAX_REQUEST_BODY = 16 * 1024
CSRF_TTL_SECONDS = 30 * 60
DEFAULT_INGRESS_PEERS = frozenset({"172.30.32.2"})
_MAX_IDEMPOTENCY_RECORDS_PER_USER = 256
_MAX_IDEMPOTENCY_USERS = 128
_IDEMPOTENCY_TTL_SECONDS = 30 * 60
_MAX_CSRF_USERS = 128
_MAX_DIAGNOSTIC_EVENTS = 100
_MAX_DIAGNOSTIC_TEXT = 512
_MAX_STATUS_FILES = 14
_MAX_LOGIN_HANDOFF_USERS = 128
_LOGIN_HANDOFF_TTL_SECONDS = 120
_USER_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")
_SAFE_CODE = re.compile(r"^[a-z0-9_]{1,64}$")
_ENCODED_SEPARATOR = re.compile(r"%(?:2f|5c)", re.IGNORECASE)
_ENCODED_DOT = re.compile(r"%2e", re.IGNORECASE)
_INVALID_PERCENT = re.compile(r"%(?![0-9a-f]{2})", re.IGNORECASE)
_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; "
    "img-src 'self'; connect-src 'self'; frame-ancestors 'self'; "
    "base-uri 'none'; form-action 'self'"
)
_SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": _CSP,
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}
_POST_ROUTES = {
    "/api/auth/connect": "connect",
    "/api/auth/disconnect": "disconnect",
    "/api/auth/renew": "renew",
    "/api/scan": "scan",
    "/api/upload/cancel": "cancel_upload",
    "/api/upload/retry": "retry_upload",
    "/api/worker/restart": "restart_worker",
}
_GET_ROUTES = frozenset(
    {
        "/",
        "/static/app.js",
        "/static/app.css",
        "/api/status",
        "/api/diagnostics",
    }
)
_STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/static/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/static/app.css": ("app.css", "text/css; charset=utf-8"),
}


class ControlAction(StrEnum):
    CONNECT = "connect"
    DISCONNECT = "disconnect"
    RENEW = "renew"
    SCAN = "scan"
    CANCEL_UPLOAD = "cancel_upload"
    RETRY_UPLOAD = "retry_upload"
    RESTART_WORKER = "restart_worker"


@dataclass(frozen=True)
class ControlCommand:
    command_id: str
    action: ControlAction
    user_id: str
    sha256: str | None = None
    retry_revision: int | None = None
    login_deadline: float | None = None


class CommandQueue(Queue[ControlCommand]):
    """Bounded queue with an atomic, synchronously closeable admission gate."""

    def __init__(self, maxsize: int) -> None:
        super().__init__(maxsize=maxsize)
        self._admission_lock = RLock()
        self._admission_closed = False

    @contextmanager
    def admission(self):
        with self._admission_lock:
            yield not self._admission_closed

    @contextmanager
    def execution_lease(self):
        """Linearize one short owner-side command effect against close."""
        with self._admission_lock:
            yield not self._admission_closed

    def close_admission(self) -> None:
        with self._admission_lock:
            self._admission_closed = True

    def has_pending_auth_command(self) -> bool:
        """Inspect the queued controls without consuming them."""
        with self.mutex:
            return any(
                type(command) is ControlCommand
                and command.action in (ControlAction.CONNECT, ControlAction.RENEW, ControlAction.DISCONNECT)
                for command in self.queue
            )

    @property
    def admission_closed(self) -> bool:
        with self._admission_lock:
            return self._admission_closed


@dataclass(frozen=True)
class _PendingLoginUrl:
    command_id: str
    url: str | None
    expires_at: float
    consumed: bool = False


@dataclass(frozen=True)
class LoginUrlHandoff:
    command_id: str
    url: str
    remaining_ms: int


@dataclass(frozen=True)
class LoginUrlView:
    command_id: str
    active: bool
    remaining_ms: int
    url: str | None = None


class LoginUrlBroker:
    """One-shot in-memory handoff for an already validated login URL."""

    def __init__(
        self,
        *,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if not callable(monotonic):
            raise ValueError("Invalid login URL broker clock")
        self._monotonic = monotonic
        self._pending: OrderedDict[str, _PendingLoginUrl] = OrderedDict()
        self._lock = RLock()

    def begin(self, command: ControlCommand) -> Callable[[str], None]:
        if (
            type(command) is not ControlCommand
            or command.action not in {ControlAction.CONNECT, ControlAction.RENEW}
            or _USER_ID.fullmatch(command.user_id) is None
            or re.fullmatch(r"[0-9a-f]{32}", command.command_id) is None
        ):
            raise ValueError("Invalid login command")
        with self._lock:
            now = self._monotonic()
            self._sweep(now)
            if (
                command.user_id not in self._pending
                and len(self._pending) >= _MAX_LOGIN_HANDOFF_USERS
            ):
                raise RuntimeError("Login URL handoff is busy")
            deadline = command.login_deadline
            if deadline is None:
                deadline = now + _LOGIN_HANDOFF_TTL_SECONDS
            if (
                isinstance(deadline, bool)
                or not isinstance(deadline, (int, float))
                or deadline <= now
                or deadline > now + _LOGIN_HANDOFF_TTL_SECONDS
            ):
                raise ValueError("Invalid login deadline")
            self._pending[command.user_id] = _PendingLoginUrl(
                command.command_id,
                None,
                float(deadline),
            )
            self._pending.move_to_end(command.user_id)

        def publish(url: str) -> None:
            self._publish(command.user_id, command.command_id, url)

        return publish

    def consume(self, user_id: str) -> LoginUrlHandoff | None:
        view = self.view(user_id)
        if view is None or view.url is None:
            return None
        return LoginUrlHandoff(view.command_id, view.url, view.remaining_ms)

    def view(self, user_id: str) -> LoginUrlView | None:
        if not isinstance(user_id, str) or _USER_ID.fullmatch(user_id) is None:
            return None
        with self._lock:
            now = self._monotonic()
            self._sweep(now)
            record = self._pending.get(user_id)
            if record is None:
                return None
            remaining_ms = max(0, int((record.expires_at - now) * 1000))
            url = None if record.consumed else record.url
            if url is not None:
                self._pending[user_id] = _PendingLoginUrl(
                    record.command_id,
                    record.url,
                    record.expires_at,
                    True,
                )
            return LoginUrlView(
                record.command_id,
                True,
                remaining_ms,
                url,
            )

    def cancel(self, user_id: str, command_id: str | None = None) -> None:
        if not isinstance(user_id, str):
            return
        with self._lock:
            record = self._pending.get(user_id)
            if record is not None and (
                command_id is None or record.command_id == command_id
            ):
                self._pending.pop(user_id, None)

    def _publish(self, user_id: str, command_id: str, url: str) -> None:
        if not isinstance(url, str) or not url:
            raise ValueError("Invalid login URL handoff")
        with self._lock:
            now = self._monotonic()
            self._sweep(now)
            record = self._pending.get(user_id)
            if (
                record is None
                or record.command_id != command_id
                or record.url is not None
                or now >= record.expires_at
            ):
                raise RuntimeError("Login URL handoff is no longer active")
            self._pending[user_id] = _PendingLoginUrl(
                command_id,
                url,
                record.expires_at,
                False,
            )

    def _sweep(self, now: float) -> None:
        expired = [
            user_id
            for user_id, record in self._pending.items()
            if now >= record.expires_at
        ]
        for user_id in expired:
            self._pending.pop(user_id, None)


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> object:
        return json.loads(self.body.decode("utf-8"))


@dataclass(frozen=True)
class DiagnosticEvent:
    timestamp: str
    code: str
    message: str
    attempt: int | None
    backup_name: str | None


class DiagnosticBuffer:
    """Keep only bounded, already-redacted diagnostic records."""

    def __init__(self) -> None:
        self._events: deque[DiagnosticEvent] = deque(maxlen=_MAX_DIAGNOSTIC_EVENTS)
        self._lock = RLock()

    def append(
        self,
        *,
        timestamp: datetime,
        code: str,
        message: str,
        attempt: int | None = None,
        backup_name: str | None = None,
    ) -> None:
        event = DiagnosticEvent(
            timestamp=_iso8601(timestamp),
            code=_safe_code(code),
            message=_safe_text(message, _MAX_DIAGNOSTIC_TEXT),
            attempt=(
                attempt
                if type(attempt) is int and 0 <= attempt <= 1_000_000
                else None
            ),
            backup_name=(
                None
                if backup_name is None
                else _safe_text(backup_name, _MAX_DIAGNOSTIC_TEXT)
            ),
        )
        with self._lock:
            self._events.append(event)

    def snapshot(self) -> tuple[DiagnosticEvent, ...]:
        with self._lock:
            return tuple(self._events)


@dataclass(frozen=True)
class _CsrfRecord:
    token: str
    expires_at: float


@dataclass(frozen=True)
class _IdempotencyRecord:
    fingerprint: tuple[ControlAction, str | None, int | None]
    response: HttpResponse
    csrf_digest: bytes
    expires_at: float


@dataclass
class _UserIdempotency:
    records: OrderedDict[str, _IdempotencyRecord]
    last_seen: float


class _DuplicateJsonKey(ValueError):
    pass


class _CapacityError(RuntimeError):
    pass


class WebController:
    """Validate the Ingress boundary and enqueue work for the service thread."""

    def __init__(
        self,
        *,
        snapshot_provider: Callable[[], ServiceSnapshot],
        command_queue: Queue[ControlCommand],
        diagnostics: DiagnosticBuffer | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        token_factory: Callable[[], str] = lambda: secrets.token_urlsafe(32),
        command_id_factory: Callable[[], str] = lambda: secrets.token_hex(16),
        allowed_ingress_peers: frozenset[str] = DEFAULT_INGRESS_PEERS,
        allowed_origins: set[str] | frozenset[str] | None = None,
        static_root: Path | None = None,
        login_url_broker: LoginUrlBroker | None = None,
    ) -> None:
        if not callable(snapshot_provider) or not callable(monotonic):
            raise ValueError("Invalid web controller dependency")
        if not callable(token_factory) or not callable(command_id_factory):
            raise ValueError("Invalid web controller factory")
        if not isinstance(command_queue, Queue) or command_queue.maxsize <= 0:
            raise ValueError("Control command queue must be bounded")
        peers = frozenset(allowed_ingress_peers)
        if not peers or any(_invalid_peer(peer) for peer in peers):
            raise ValueError("Invalid Ingress peer allowlist")
        origins = frozenset(allowed_origins or ())
        if any(_canonical_origin(origin) != origin for origin in origins):
            raise ValueError("Invalid allowed origin")
        if login_url_broker is not None and type(login_url_broker) is not LoginUrlBroker:
            raise ValueError("Invalid login URL broker")
        self._snapshot_provider = snapshot_provider
        self._commands = command_queue
        self._diagnostics = diagnostics or DiagnosticBuffer()
        self._monotonic = monotonic
        self._token_factory = token_factory
        self._command_id_factory = command_id_factory
        self._allowed_ingress_peers = peers
        self._allowed_origins = origins
        self._static_root = static_root or Path(__file__).with_name("static")
        self._login_url_broker = login_url_broker
        self._csrf: OrderedDict[str, _CsrfRecord] = OrderedDict()
        self._idempotency: OrderedDict[str, _UserIdempotency] = OrderedDict()
        self._retry_revision_high_water = 0
        self._accepted_retry_revision: int | None = None
        self._state_lock = RLock()

    def handle(
        self,
        *,
        method: str,
        target: str,
        peer: str,
        headers: Mapping[str, str],
        body: bytes = b"",
    ) -> HttpResponse:
        try:
            return self._handle(
                method=method,
                target=target,
                peer=peer,
                headers=headers,
                body=body,
            )
        except Exception:
            return _error(500, "internal_error")

    def _handle(
        self,
        *,
        method: str,
        target: str,
        peer: str,
        headers: Mapping[str, str],
        body: bytes,
    ) -> HttpResponse:
        normalized_headers = _normalize_headers(headers)
        if peer not in self._allowed_ingress_peers:
            return _error(403, "access_denied")
        user_id = normalized_headers.get("x-remote-user-id", "")
        if not _USER_ID.fullmatch(user_id):
            return _error(403, "access_denied")
        path = _normalize_target(target)
        if path is None:
            return _error(400, "invalid_request")
        if not isinstance(method, str):
            return _error(400, "invalid_request")
        method = method.upper()
        if method == "GET":
            if body or normalized_headers.get("transfer-encoding") or _nonzero_length(
                normalized_headers.get("content-length")
            ):
                return _error(400, "invalid_request")
            if path in _POST_ROUTES:
                return _error(405, "method_not_allowed", extra_headers={"Allow": "POST"})
            return self._get(path, user_id)
        if method == "POST":
            if path in _GET_ROUTES:
                return _error(405, "method_not_allowed", extra_headers={"Allow": "GET"})
            if path not in _POST_ROUTES:
                return _error(404, "not_found")
            access_error = self._validate_mutation_access(normalized_headers)
            if access_error is not None:
                return access_error
            parsed, parse_error = _parse_json_body(normalized_headers, body)
            if parse_error is not None:
                return parse_error
            return self._post(
                path, user_id, normalized_headers, parsed
            )
        allow = "POST" if path in _POST_ROUTES else "GET" if path in _GET_ROUTES else None
        return _error(
            405,
            "method_not_allowed",
            extra_headers={} if allow is None else {"Allow": allow},
        )

    def _get(self, path: str, user_id: str) -> HttpResponse:
        if path == "/api/status":
            snapshot = self._snapshot_provider()
            if type(snapshot) is not ServiceSnapshot:
                raise ValueError("Invalid service snapshot")
            try:
                payload = self._status_payload(snapshot, user_id)
            except _CapacityError:
                return _error(503, "service_busy")
            if self._login_url_broker is not None:
                login_view = (
                    None
                    if snapshot.connected
                    else self._login_url_broker.view(user_id)
                )
                payload["login_active"] = login_view is not None
                if login_view is not None:
                    payload["login_generation"] = login_view.command_id
                    payload["login_remaining_ms"] = login_view.remaining_ms
                    if login_view.url is not None:
                        payload["login_url"] = login_view.url
            return _json_response(200, payload)
        if path == "/api/diagnostics":
            events = [
                {
                    "timestamp": event.timestamp,
                    "code": event.code,
                    "message": event.message,
                    "attempt": event.attempt,
                    "backup_name": event.backup_name,
                }
                for event in self._diagnostics.snapshot()
            ]
            return _json_response(200, {"events": events})
        static = _STATIC_FILES.get(path)
        if static is not None:
            filename, content_type = static
            return self._static_response(filename, content_type)
        return _error(404, "not_found")

    def _post(
        self,
        path: str,
        user_id: str,
        headers: Mapping[str, str],
        body: object,
    ) -> HttpResponse:
        if type(body) is not dict:
            return _error(400, "invalid_body")
        action = ControlAction(_POST_ROUTES[path])
        sha256: str | None = None
        retry_revision: int | None = None
        if action is ControlAction.RETRY_UPLOAD:
            if set(body) != {"sha256", "retry_revision"}:
                return _error(400, "invalid_body")
            value = body.get("sha256")
            if not isinstance(value, str) or not _SHA256.fullmatch(value):
                return _error(400, "invalid_body")
            sha256 = value
            revision_value = body.get("retry_revision")
            if (
                type(revision_value) is not int
                or revision_value < 0
                or revision_value > MAX_RETRY_REVISION
            ):
                return _error(400, "invalid_body")
            retry_revision = revision_value
        elif body:
            return _error(400, "invalid_body")

        idempotency_key = headers.get("idempotency-key")
        if idempotency_key is not None and not _IDEMPOTENCY_KEY.fullmatch(
            idempotency_key
        ):
            return _error(400, "invalid_request")
        fingerprint = (action, sha256, retry_revision)
        supplied_csrf = headers.get("x-csrf-token")
        retry_snapshot: ServiceSnapshot | None = None
        admission_snapshot: ServiceSnapshot | None = None
        if action is ControlAction.RETRY_UPLOAD:
            with self._command_admission() as admitted, self._state_lock:
                if not admitted:
                    return _error(409, "service_busy")
                now = self._monotonic()
                self._sweep_csrf(now)
                self._sweep_idempotency(now)
                bucket = self._idempotency.get(user_id)
                previous = (
                    None
                    if bucket is None or idempotency_key is None
                    else bucket.records.get(idempotency_key)
                )
                current = self._csrf.get(user_id)
                supplied_digest = (
                    _csrf_digest(supplied_csrf)
                    if isinstance(supplied_csrf, str)
                    else None
                )
                original_token = (
                    previous is not None
                    and supplied_digest is not None
                    and hmac.compare_digest(previous.csrf_digest, supplied_digest)
                )
                current_token = (
                    current is not None
                    and isinstance(supplied_csrf, str)
                    and hmac.compare_digest(current.token, supplied_csrf)
                )
                if previous is not None:
                    if previous.fingerprint == fingerprint:
                        if not original_token:
                            return _error(403, "csrf_rejected")
                        bucket.records.move_to_end(idempotency_key)
                        self._idempotency.move_to_end(user_id)
                        return previous.response
                    if original_token or current_token:
                        return _error(409, "idempotency_conflict")
                    return _error(403, "csrf_rejected")
                if (
                    current is None
                    or not isinstance(supplied_csrf, str)
                    or not current_token
                ):
                    return _error(403, "csrf_rejected")
                if bucket is None:
                    return _error(503, "service_busy")
            retry_snapshot = self._snapshot_provider()
            if type(retry_snapshot) is not ServiceSnapshot:
                raise ValueError("Invalid service snapshot")
            admission_snapshot = retry_snapshot

        with self._command_admission() as admitted, self._state_lock:
            if not admitted:
                return _error(409, "service_busy")
            now = self._monotonic()
            self._sweep_csrf(now)
            self._sweep_idempotency(now)
            bucket = self._idempotency.get(user_id)
            previous = (
                None
                if bucket is None or idempotency_key is None
                else bucket.records.get(idempotency_key)
            )
            current = self._csrf.get(user_id)
            supplied_digest = (
                _csrf_digest(supplied_csrf)
                if isinstance(supplied_csrf, str)
                else None
            )
            original_token = (
                previous is not None
                and supplied_digest is not None
                and hmac.compare_digest(previous.csrf_digest, supplied_digest)
            )
            current_token = (
                current is not None
                and isinstance(supplied_csrf, str)
                and hmac.compare_digest(current.token, supplied_csrf)
            )
            if previous is not None:
                if previous.fingerprint == fingerprint:
                    if not original_token:
                        return _error(403, "csrf_rejected")
                    bucket.records.move_to_end(idempotency_key)
                    self._idempotency.move_to_end(user_id)
                    return previous.response
                if original_token or current_token:
                    return _error(409, "idempotency_conflict")
                return _error(403, "csrf_rejected")
            if (
                current is None
                or not isinstance(supplied_csrf, str)
                or not current_token
            ):
                return _error(403, "csrf_rejected")
            if bucket is None:
                return _error(503, "service_busy")
            if admission_snapshot is None:
                admission_snapshot = self._snapshot_provider()
            if type(admission_snapshot) is not ServiceSnapshot:
                raise ValueError("Invalid service snapshot")
            if admission_snapshot.web_ready is not True:
                return _error(409, "service_busy")

            if action is ControlAction.RETRY_UPLOAD:
                if (
                    retry_snapshot is None
                    or retry_snapshot.web_ready is not True
                    or retry_snapshot.retry_sha256 != sha256
                    or retry_snapshot.retry_revision != retry_revision
                    or not self._retry_snapshot_is_actionable_locked(retry_snapshot)
                ):
                    return _error(409, "service_busy")

            command_id = self._command_id_factory()
            if not isinstance(command_id, str) or not re.fullmatch(
                r"[0-9a-f]{32}", command_id
            ):
                raise ValueError("Invalid command identity")
            command = ControlCommand(
                command_id,
                action,
                user_id,
                sha256,
                retry_revision,
                now + _LOGIN_HANDOFF_TTL_SECONDS
                if action in {ControlAction.CONNECT, ControlAction.RENEW}
                else None,
            )
            next_csrf = self._new_csrf_token(supplied_csrf)
            next_csrf_record = _CsrfRecord(
                next_csrf, now + CSRF_TTL_SECONDS
            )
            response = _json_response(
                202,
                {
                    "accepted": True,
                    "command_id": command.command_id,
                    "csrf_token": next_csrf,
                },
            )
            prepared_records = OrderedDict(bucket.records.items())
            if idempotency_key is not None:
                prepared_records[idempotency_key] = _IdempotencyRecord(
                    fingerprint,
                    response,
                    _csrf_digest(supplied_csrf),
                    now + _IDEMPOTENCY_TTL_SECONDS,
                )
                prepared_records.move_to_end(idempotency_key)
                while len(prepared_records) > _MAX_IDEMPOTENCY_RECORDS_PER_USER:
                    prepared_records.popitem(last=False)
            prepared_bucket = _UserIdempotency(prepared_records, now)

            try:
                self._commands.put_nowait(command)
            except Full:
                return _error(503, "service_busy")

            self._csrf[user_id] = next_csrf_record
            self._csrf.move_to_end(user_id)
            self._idempotency[user_id] = prepared_bucket
            self._idempotency.move_to_end(user_id)
            if action is ControlAction.RETRY_UPLOAD:
                self._accepted_retry_revision = retry_revision
            return response

    def _command_admission(self):
        admission = getattr(self._commands, "admission", None)
        return admission() if callable(admission) else nullcontext(True)

    def _validate_mutation_access(
        self, headers: Mapping[str, str]
    ) -> HttpResponse | None:
        origin = headers.get("origin")
        if not self._origin_allowed(origin):
            return _error(403, "origin_rejected")
        return None

    def _origin_allowed(self, origin: str | None) -> bool:
        canonical = _canonical_origin(origin)
        if canonical is None:
            return False
        return origin == canonical and canonical in self._allowed_origins

    def _csrf_token(self, user_id: str) -> str:
        now = self._monotonic()
        with self._state_lock:
            self._sweep_csrf(now)
            self._sweep_idempotency(now)
            record = self._csrf.get(user_id)
            if record is not None and now < record.expires_at:
                bucket = self._idempotency.get(user_id)
                if bucket is None:
                    if len(self._idempotency) >= _MAX_IDEMPOTENCY_USERS:
                        raise _CapacityError("Idempotency user capacity reached")
                    bucket = _UserIdempotency(OrderedDict(), now)
                    self._idempotency[user_id] = bucket
                bucket.last_seen = now
                self._csrf.move_to_end(user_id)
                self._idempotency.move_to_end(user_id)
                return record.token
            return self._rotate_csrf(user_id, now, None)

    def _rotate_csrf(
        self, user_id: str, now: float, previous: str | None
    ) -> str:
        if user_id not in self._csrf and len(self._csrf) >= _MAX_CSRF_USERS:
            raise _CapacityError("CSRF user capacity reached")
        if (
            user_id not in self._idempotency
            and len(self._idempotency) >= _MAX_IDEMPOTENCY_USERS
        ):
            raise _CapacityError("Idempotency user capacity reached")
        token = self._new_csrf_token(previous)
        new_bucket = (
            _UserIdempotency(OrderedDict(), now)
            if user_id not in self._idempotency
            else None
        )
        self._csrf[user_id] = _CsrfRecord(token, now + CSRF_TTL_SECONDS)
        if new_bucket is not None:
            self._idempotency[user_id] = new_bucket
        else:
            self._idempotency[user_id].last_seen = now
        self._csrf.move_to_end(user_id)
        self._idempotency.move_to_end(user_id)
        return token

    def _new_csrf_token(self, previous: str | None) -> str:
        for _attempt in range(4):
            token = self._token_factory()
            if (
                isinstance(token, str)
                and 8 <= len(token) <= 256
                and (previous is None or not hmac.compare_digest(token, previous))
            ):
                return token
        raise ValueError("Invalid CSRF token")

    def _sweep_csrf(self, now: float) -> None:
        expired = [
            user_id
            for user_id, record in self._csrf.items()
            if now >= record.expires_at
        ]
        for user_id in expired:
            self._csrf.pop(user_id, None)

    def _sweep_idempotency(self, now: float) -> None:
        expired_users: list[str] = []
        for existing_user, bucket in self._idempotency.items():
            expired_records = [
                key
                for key, record in bucket.records.items()
                if now >= record.expires_at
            ]
            for key in expired_records:
                bucket.records.pop(key, None)
            if (
                not bucket.records
                and now - bucket.last_seen >= _IDEMPOTENCY_TTL_SECONDS
            ):
                expired_users.append(existing_user)
        for existing_user in expired_users:
            self._idempotency.pop(existing_user, None)

    def _status_payload(
        self, snapshot: ServiceSnapshot, user_id: str
    ) -> dict[str, object]:
        active_sha256 = (
            snapshot.active_sha256
            if isinstance(snapshot.active_sha256, str)
            and _SHA256.fullmatch(snapshot.active_sha256)
            else None
        )
        with self._state_lock:
            retry_actionable = self._retry_snapshot_is_actionable_locked(snapshot)
        retry_sha256 = (
            snapshot.retry_sha256
            if retry_actionable
            and isinstance(snapshot.retry_sha256, str)
            and _SHA256.fullmatch(snapshot.retry_sha256)
            else None
        )
        retry_revision = snapshot.retry_revision if retry_sha256 is not None else None
        remote_files = []
        for remote in snapshot.remote_files[:_MAX_STATUS_FILES]:
            remote_files.append(
                {
                    "uid": _safe_text(remote.uid, 128),
                    "name": _safe_text(remote.name, 255),
                    "size": remote.size if type(remote.size) is int and remote.size >= 0 else 0,
                    "modified_at": _optional_iso8601(remote.modified_at),
                }
            )
        payload: dict[str, object] = {
            "csrf_token": self._csrf_token(user_id),
            "service": {
                "web_ready": snapshot.web_ready is True,
                "connected": snapshot.connected is True,
                "scanner_state": _safe_text(snapshot.scanner_state, 64),
                "native_mode": snapshot.native_mode is True,
            },
            "upload": {
                "sha256": active_sha256,
                "name": (
                    None
                    if snapshot.active_name is None
                    else _safe_text(snapshot.active_name, 255)
                ),
                "started_at": _optional_iso8601(snapshot.active_started_at),
                "native_operation": snapshot.native_operation if snapshot.native_operation in {
                    "list", "get", "upload", "download", "delete"} else None,
            },
            "queue": {
                "size": (
                    snapshot.queue_size
                    if type(snapshot.queue_size) is int and snapshot.queue_size >= 0
                    else 0
                ),
                "next_retry_at": _optional_iso8601(snapshot.next_retry_at),
            },
            "last_success_at": _optional_iso8601(snapshot.last_success_at),
            "last_error_code": (
                None
                if snapshot.last_error_code is None
                else _safe_code(snapshot.last_error_code)
            ),
            "retry_sha256": retry_sha256,
            "retry_revision": retry_revision,
            "remote_files": remote_files,
        }
        if snapshot.native_mode is True:
            history_state = getattr(snapshot, "native_history_state", None)
            if snapshot.connected is not True or history_state not in (
                "loading", "ready", "stale", "unavailable"
            ):
                history_state = "unavailable"
            files = []
            if history_state in ("ready", "stale"):
                for item in snapshot.native_history[:_MAX_STATUS_FILES]:
                    files.append({
                        "name": _safe_text(item.name, 255),
                        "size": item.size,
                        "date": _iso8601(item.date),
                    })
            payload["backup_history"] = {"state": history_state, "files": files}
        return payload

    def _retry_snapshot_is_actionable_locked(
        self, snapshot: ServiceSnapshot
    ) -> bool:
        retry_revision = snapshot.retry_revision
        if (
            type(retry_revision) is not int
            or retry_revision < 0
            or retry_revision > MAX_RETRY_REVISION
        ):
            return False
        has_retry_target = (
            isinstance(snapshot.retry_sha256, str)
            and _SHA256.fullmatch(snapshot.retry_sha256) is not None
            and isinstance(snapshot.next_retry_at, datetime)
            and snapshot.next_retry_at.tzinfo is not None
        )
        has_no_retry_target = (
            snapshot.retry_sha256 is None and snapshot.next_retry_at is None
        )
        if not has_retry_target and not has_no_retry_target:
            return False
        if retry_revision < self._retry_revision_high_water:
            return False
        if retry_revision > self._retry_revision_high_water:
            self._retry_revision_high_water = retry_revision
            if (
                self._accepted_retry_revision is not None
                and retry_revision > self._accepted_retry_revision
            ):
                self._accepted_retry_revision = None
        if (
            self._accepted_retry_revision is not None
            and retry_revision <= self._accepted_retry_revision
        ):
            return False
        return retry_revision > 0 and has_retry_target

    def _static_response(self, filename: str, content_type: str) -> HttpResponse:
        candidate = self._static_root / filename
        try:
            data = candidate.read_bytes()
        except (FileNotFoundError, IsADirectoryError, PermissionError, OSError):
            return _error(404, "not_found")
        if len(data) > 1024 * 1024:
            return _error(500, "internal_error")
        return _response(200, data, content_type)


class IngressRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ProtonBackup"
    sys_version = ""

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_HEAD(self) -> None:
        self._dispatch("HEAD")

    def do_OPTIONS(self) -> None:
        self._dispatch("OPTIONS")

    def do_PUT(self) -> None:
        self._dispatch("PUT")

    def do_PATCH(self) -> None:
        self._dispatch("PATCH")

    def do_DELETE(self) -> None:
        self._dispatch("DELETE")

    def do_TRACE(self) -> None:
        self._dispatch("TRACE")

    def do_CONNECT(self) -> None:
        self._dispatch("CONNECT")

    def send_error(
        self,
        code: int,
        message: str | None = None,
        explain: str | None = None,
    ) -> None:
        del message, explain
        if code == 413:
            response = _error(413, "body_too_large")
        elif code in {400, 414, 431}:
            response = _error(400, "invalid_request")
        elif code == 501:
            response = _error(405, "method_not_allowed")
        else:
            response = _error(500, "internal_error")
        self.close_connection = True
        self.send_response(response.status)
        for name, value in response.headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(response.body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if getattr(self, "command", None) != "HEAD":
            try:
                self.wfile.write(response.body)
            except (BrokenPipeError, ConnectionResetError):
                return

    def _dispatch(self, method: str) -> None:
        self.close_connection = True
        headers: dict[str, str] = {}
        for key in self.headers:
            values = self.headers.get_all(key, failobj=[])
            lowered = key.casefold()
            if lowered not in headers:
                headers[lowered] = ",".join(values)
        body = self._read_body(method, headers)
        controller = getattr(self.server, "controller", None)
        if not isinstance(controller, WebController):
            response = _error(500, "internal_error")
        else:
            response = controller.handle(
                method=method,
                target=self.path,
                peer=self.client_address[0],
                headers=headers,
                body=body,
            )
        self.send_response(response.status)
        for name, value in response.headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(response.body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if method != "HEAD":
            try:
                self.wfile.write(response.body)
            except (BrokenPipeError, ConnectionResetError):
                return

    def _read_body(self, method: str, headers: Mapping[str, str]) -> bytes:
        if method != "POST" or headers.get("transfer-encoding") is not None:
            return b""
        raw_length = headers.get("content-length")
        if raw_length is None or not raw_length.isascii() or not raw_length.isdigit():
            return b""
        length = int(raw_length)
        if length > MAX_REQUEST_BODY:
            return b""
        return self.rfile.read(length)

    def log_message(self, _format: str, *args: object) -> None:
        # Request targets may include login URLs or attacker-controlled secrets.
        return


class IngressServer(ThreadingHTTPServer):
    daemon_threads = False
    block_on_close = True
    allow_reuse_address = False
    request_queue_size = 16

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8099,
        controller: WebController | None = None,
    ) -> None:
        if host not in {"0.0.0.0", "127.0.0.1"}:
            raise ValueError("Ingress server must bind an intended IPv4 interface")
        if type(port) is not int or not 0 <= port <= 65_535:
            raise ValueError("Invalid Ingress port")
        if not isinstance(controller, WebController):
            raise ValueError("Ingress server requires a web controller")
        self.controller = controller
        super().__init__((host, port), IngressRequestHandler, bind_and_activate=True)

    def get_request(self):
        request, client_address = super().get_request()
        request.settimeout(0.05)
        return request, client_address


def _normalize_headers(headers: Mapping[str, str]) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for key, value in headers.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ValueError("Invalid request header")
        lowered = key.casefold()
        if lowered in normalized:
            normalized[lowered] = normalized[lowered] + "," + value
        else:
            normalized[lowered] = value
    return normalized


def _normalize_target(target: str) -> str | None:
    if (
        not isinstance(target, str)
        or not target.startswith("/")
        or target.startswith("//")
        or "\x00" in target
        or "\\" in target
        or _ENCODED_SEPARATOR.search(target)
        or _ENCODED_DOT.search(target)
        or _INVALID_PERCENT.search(target)
    ):
        return None
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
        return None
    if any(part in {".", ".."} for part in parsed.path.split("/")):
        return None
    return parsed.path


def _parse_json_body(
    headers: Mapping[str, str], body: bytes
) -> tuple[object | None, HttpResponse | None]:
    if headers.get("transfer-encoding") is not None:
        return None, _error(400, "invalid_request")
    raw_length = headers.get("content-length")
    if (
        raw_length is None
        or not raw_length.isascii()
        or not raw_length.isdigit()
        or len(raw_length) > 8
    ):
        return None, _error(400, "invalid_request")
    declared = int(raw_length)
    if declared > MAX_REQUEST_BODY or len(body) > MAX_REQUEST_BODY:
        return None, _error(413, "body_too_large")
    if declared != len(body):
        return None, _error(400, "invalid_request")
    if headers.get("content-type") != "application/json":
        return None, _error(415, "unsupported_media_type")
    try:
        text = body.decode("utf-8", errors="strict")
        parsed = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
        _DuplicateJsonKey,
        RecursionError,
    ):
        return None, _error(400, "invalid_json")
    return parsed, None


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey()
        result[key] = value
    return result


def _csrf_digest(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


def _canonical_origin(origin: str | None) -> str | None:
    if (
        not isinstance(origin, str)
        or len(origin) > 512
        or "%" in origin
        or any(ord(character) <= 0x20 or ord(character) == 0x7F for character in origin)
    ):
        return None
    try:
        parsed = urlsplit(origin)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.path
            or parsed.query
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None
        ):
            return None
        hostname = parsed.hostname
        port = parsed.port
    except (ValueError, UnicodeError):
        return None
    if (
        hostname is None
        or not hostname.isascii()
        or hostname.endswith(".")
        or hostname.startswith(".")
        or ".." in hostname
        or any(character.isspace() for character in hostname)
    ):
        return None
    default_port = 80 if parsed.scheme == "http" else 443
    if port == default_port:
        return None
    normalized_host = hostname.casefold()
    if any(label.startswith("xn--") for label in normalized_host.split(".")):
        return None
    if ":" in normalized_host:
        try:
            normalized_host = f"[{ipaddress.IPv6Address(normalized_host).compressed}]"
        except ipaddress.AddressValueError:
            return None
    elif not re.fullmatch(r"[a-z0-9._-]+", normalized_host):
        return None
    authority = normalized_host if port is None else f"{normalized_host}:{port}"
    return f"{parsed.scheme}://{authority}"


def _invalid_peer(peer: object) -> bool:
    if not isinstance(peer, str):
        return True
    try:
        return ipaddress.ip_address(peer).version != 4
    except ValueError:
        return True


def _nonzero_length(value: str | None) -> bool:
    if value is None:
        return False
    return value != "0"


def _safe_text(value: object, maximum: int) -> str:
    if not isinstance(value, str):
        return "[REDACTED]"
    return redact(value)[:maximum]


def _safe_code(value: object) -> str:
    return value if isinstance(value, str) and _SAFE_CODE.fullmatch(value) else "internal_error"


def _iso8601(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("Diagnostic timestamp must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _optional_iso8601(value: datetime | None) -> str | None:
    return None if value is None else _iso8601(value)


def _json_response(
    status: int,
    payload: object,
    *,
    extra_headers: Mapping[str, str] | None = None,
) -> HttpResponse:
    body = json.dumps(
        payload,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return _response(
        status,
        body,
        "application/json; charset=utf-8",
        extra_headers=extra_headers,
    )


def _error(
    status: int,
    code: str,
    *,
    extra_headers: Mapping[str, str] | None = None,
) -> HttpResponse:
    return _json_response(
        status,
        {"error": {"code": code}},
        extra_headers=extra_headers,
    )


def _response(
    status: int,
    body: bytes,
    content_type: str,
    *,
    extra_headers: Mapping[str, str] | None = None,
) -> HttpResponse:
    headers = dict(_SECURITY_HEADERS)
    headers["Content-Type"] = content_type
    if extra_headers is not None:
        headers.update(extra_headers)
    return HttpResponse(status, headers, body)
