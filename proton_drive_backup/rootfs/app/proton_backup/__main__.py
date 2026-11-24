"""Executable entry point for the Proton Drive backup add-on."""

from __future__ import annotations

import json
import os
import re
import signal
from pathlib import Path
from threading import Event

from .config import BACKUP_ROOT, INGRESS_PORT, PRIVATE_ROOT, STATE_DB
from .credentials import CredentialStore
from .events import EventLog, configure_logging, startup_step
from .process import ProcessRunner
from .proton_cli import ProtonDriveClient
from .retention import RetentionManager
from .scanner import BackupScanner
from .service import (
    BackupService,
    RuntimeComponents,
    ShutdownFailureError,
    ShutdownTimeoutError,
)
from .state import StateStore
from .worker import BackupWorker
from .web import DiagnosticBuffer, IngressServer, LoginUrlBroker, WebController, _canonical_origin


def prepare_data_directories(private_root: Path, state_root: Path) -> None:
    for path, mode in ((private_root, 0o700), (state_root, 0o750)):
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(mode)


def load_home_assistant_origin(options_path: Path) -> str:
    try:
        raw = options_path.read_text(encoding="utf-8")
        options = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError):
        EventLog().record("startup_options_invalid")
        raise ValueError("invalid local add-on options") from None
    if type(options) is not dict:
        EventLog().record("startup_options_invalid")
        raise ValueError("invalid local add-on options")
    origin = options.get("home_assistant_origin")
    if not isinstance(origin, str) or not origin:
        EventLog().record("startup_origin_missing")
        raise ValueError("home_assistant_origin is required")
    return origin


def load_allowed_origins(options_path: Path) -> frozenset[str]:
    origin = load_home_assistant_origin(options_path)
    try:
        options = json.loads(options_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        EventLog().record("startup_options_invalid")
        raise ValueError("invalid local add-on options") from None
    extra = options.get("additional_origins", [])
    if type(extra) is not list or len(extra) > 16:
        EventLog().record("startup_additional_origins_invalid")
        raise ValueError("additional_origins must be a list of origins")
    if _canonical_origin(origin) != origin:
        EventLog().record("startup_origin_invalid")
        raise ValueError("invalid Home Assistant origin")
    if any(type(item) is not str or _canonical_origin(item) != item for item in extra):
        EventLog().record("startup_additional_origins_invalid")
        raise ValueError("invalid Home Assistant origin")
    return frozenset([origin, *extra])


def load_native_options(options_path: Path) -> tuple[bool, str]:
    try:
        options = json.loads(options_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        EventLog().record("startup_options_invalid")
        raise ValueError("invalid local add-on options") from None
    if type(options) is not dict:
        EventLog().record("startup_options_invalid")
        raise ValueError("invalid local add-on options")
    enabled = options.get("native_mode", False)
    token = options.get("integration_token", "")
    if type(enabled) is not bool:
        EventLog().record("startup_native_mode_invalid")
        raise ValueError("invalid native backup options")
    if type(token) is not str:
        EventLog().record("startup_token_invalid")
        raise ValueError("invalid native backup options")
    if (enabled or token) and not 32 <= len(token) <= 128:
        EventLog().record("startup_token_length_invalid")
        raise ValueError("invalid native backup options")
    if (enabled or token) and re.fullmatch(r"[A-Za-z0-9._~-]{32,128}", token) is None:
        EventLog().record("startup_token_characters_invalid")
        raise ValueError("invalid native backup options")
    return enabled, token


def compose_runtime(
    *,
    private_root: Path = PRIVATE_ROOT,
    state_db: Path = STATE_DB,
    backup_root: Path = BACKUP_ROOT,
    credential_store_factory=CredentialStore,
    state_store_factory=StateStore,
    process_runner_factory=ProcessRunner,
    client_factory=ProtonDriveClient,
    retention_factory=RetentionManager,
    scanner_factory=BackupScanner,
    worker_factory=BackupWorker,
    event_log=None,
    native_mode: bool = False,
    native_storage_factory=None,
) -> RuntimeComponents:
    events = event_log if event_log is not None else EventLog()
    with startup_step(events, "startup_credentials"):
        credentials = credential_store_factory(private_root)
        credentials.bootstrap()
    with startup_step(events, "startup_state"):
        store = state_store_factory(state_db)
    events.record("startup_components_started")
    try:
        runner = process_runner_factory(
            environment={**os.environ, **credentials.environment()}
        )
        client = client_factory(
            runner=runner,
            credential_store=credentials,
        )
        retention = retention_factory(client, store)
        scanner = scanner_factory(backup_root, store)
        worker = worker_factory(store, client, retention, **({"event_log": event_log} if event_log is not None else {}))
        native_storage = None
        if native_mode:
            if native_storage_factory is None:
                from .native_storage import NativeStorage
                native_storage_factory = NativeStorage
            native_storage = native_storage_factory(client, store.installation_id(), private_root)
        runtime = RuntimeComponents(store, scanner, worker, client, native_storage=native_storage)
        events.record("startup_components_ready")
        return runtime
    except BaseException:
        events.record("startup_components_failed")
        store.close()
        raise


def compose_web_server(
    *,
    snapshot_provider,
    command_queue,
    home_assistant_origin: str,
    server_factory=IngressServer,
    login_url_broker: LoginUrlBroker | None = None,
    diagnostics=None,
    additional_origins=(),
):
    controller = WebController(
        snapshot_provider=snapshot_provider,
        command_queue=command_queue,
        allowed_origins=frozenset({home_assistant_origin, *additional_origins}),
        login_url_broker=login_url_broker,
        diagnostics=diagnostics,
    )
    return server_factory(
        host="0.0.0.0",
        port=INGRESS_PORT,
        controller=controller,
    )


def run_service(
    service: BackupService,
    *,
    signal_module=signal,
    stop_timeout: float = 20,
    force_exit=os._exit,
) -> int:
    stop_requested = Event()

    def request_stop(_number, _frame) -> None:
        stop_requested.set()
        service_request = getattr(service, "request_stop", None)
        if callable(service_request):
            service_request()

    previous: dict[object, object] = {}
    result = 0
    force_after_restore = False
    try:
        for number in (signal_module.SIGTERM, signal_module.SIGINT):
            previous[number] = signal_module.signal(number, request_stop)
        service.start()
        while not stop_requested.is_set() and not service.wait(0.1):
            pass
        snapshot = getattr(service, "snapshot", lambda: None)()
        if getattr(snapshot, "last_error_code", None) in {
            "web_failed",
            "worker_failed",
            "stop_failed",
        }:
            result = 1
    except Exception:
        result = 1
    finally:
        try:
            service.stop(timeout=stop_timeout)
        except Exception as error:
            result = 1
            force_after_restore = (
                stop_requested.is_set()
                and isinstance(error, (ShutdownTimeoutError, ShutdownFailureError))
            )
        finally:
            for number, handler in previous.items():
                try:
                    signal_module.signal(number, handler)
                except Exception:
                    result = 1
    if force_after_restore:
        # Container-only last resort: cooperative shutdown already failed and
        # surviving non-daemon dependency threads would prevent PID 1 exit.
        force_exit(1)
    return result


def build_service(
    *,
    options_path: Path = Path("/data/options.json"),
    private_root: Path = PRIVATE_ROOT,
    state_db: Path = STATE_DB,
) -> BackupService:
    diagnostics = DiagnosticBuffer()
    events = EventLog(diagnostics=diagnostics)
    with startup_step(events, "startup_options"):
        home_assistant_origin = load_home_assistant_origin(options_path)
        origins = load_allowed_origins(options_path)
        native_mode, integration_token = load_native_options(options_path)
    events.record("startup_native_enabled" if native_mode else "startup_legacy_enabled")
    with startup_step(events, "startup_private_storage"):
        prepare_data_directories(private_root, state_db.parent)
    login_url_broker = LoginUrlBroker()
    native_api_factory = None
    if native_mode:
        with startup_step(events, "startup_dependencies"):
            from .native_api import NativeApiServer
        native_api_factory = lambda service, runtime: NativeApiServer(
            submit=service.submit_native, snapshot=service.snapshot,
            installation_id=runtime.native_storage.installation_id,
            token=integration_token, private_root=private_root,
        )
    service = BackupService(
        runtime_factory=lambda: compose_runtime(
            private_root=private_root,
            state_db=state_db,
            event_log=events,
            native_mode=native_mode,
        ),
        web_server_factory=lambda snapshot, commands: compose_web_server(
            snapshot_provider=snapshot,
            command_queue=commands,
            home_assistant_origin=home_assistant_origin,
            login_url_broker=login_url_broker,
            additional_origins=origins,
            diagnostics=diagnostics,
        ),
        login_url_broker=login_url_broker,
        event_log=events,
        native_mode=native_mode,
        native_api_factory=native_api_factory,
    )
    events.record("startup_configuration_ready")
    return service


def main(
    *,
    service_factory=build_service,
    service_runner=run_service,
) -> int:
    os.umask(0o077)
    configure_logging()
    EventLog().record("startup_started")
    try:
        result = service_runner(service_factory())
        if result != 0:
            EventLog().record("service_failed")
        return result
    except Exception:
        EventLog().record("startup_failed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
