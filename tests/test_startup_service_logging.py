from __future__ import annotations

import io
import logging
import unittest

import tests
from proton_backup.events import EventLog
from proton_backup.redaction import SafeLogger
from proton_backup.service import BackupService, RuntimeComponents
from tests.test_native_service import FakeNativeApi
from tests.test_service import NOW, FakeScanner, FakeServer, FakeStore, FakeWorker


_PRIVATE_VALUES = (
    "fake-password-7741",
    "fake-otp-8822",
    "fake-login-token-9933",
    "fake-private-file-6644",
    "fake-user-data-5511",
)
_PRIVATE_PAYLOAD = (
    "password=fake-password-7741 otp=fake-otp-8822 "
    "https://account.proton.me/login?token=fake-login-token-9933 "
    "/data/private/fake-private-file-6644 fake-user-data-5511"
)


class PrivateStartupFailure(RuntimeError):
    pass


def fail_startup(*_args):
    raise PrivateStartupFailure(_PRIVATE_PAYLOAD)


class StartupServiceLoggingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.output = io.StringIO()
        logger = logging.Logger("startup-service-test", level=logging.DEBUG)
        logger.addHandler(logging.StreamHandler(self.output))
        self.event_log = EventLog(logger=SafeLogger(logger), clock=lambda: NOW)
        self.events = []
        self.store = FakeStore(self.events)
        self.scanner = FakeScanner(self.events)
        self.worker = FakeWorker(self.events)
        self.server = FakeServer()
        self.native_api = FakeNativeApi()

    def make_service(
        self, *, runtime_factory=None, web_factory=None,
        native_mode=False, native_api_factory=None,
    ) -> BackupService:
        return BackupService(
            runtime_factory=runtime_factory or (
                lambda: RuntimeComponents(
                    self.store, self.scanner, self.worker,
                    native_storage=object() if native_mode else None,
                )
            ),
            web_server_factory=web_factory or (lambda *_: self.server),
            native_mode=native_mode,
            native_api_factory=native_api_factory,
            event_log=self.event_log,
            clock=lambda: NOW,
        )

    def codes(self) -> list[str]:
        return [line.partition(":")[0] for line in self.output.getvalue().splitlines()]

    def assert_private_values_absent(self) -> None:
        output = self.output.getvalue()
        for private_value in (*_PRIVATE_VALUES, "PrivateStartupFailure"):
            self.assertNotIn(private_value, output)
        self.assertNotIn("https://account.proton.me/login", output)
        self.assertNotIn("/data/private/", output)

    def assert_clean_stop(self, service: BackupService, *, constructed=True) -> None:
        service.stop(timeout=2)
        if constructed:
            self.assertTrue(self.store.closed)
            self.assertTrue(self.worker.cancelled)
        for thread in (
            service._runtime_thread, service._web_thread,
            service._scan_thread, service._proton_thread,
        ):
            if thread is not None:
                self.assertFalse(thread.is_alive(), thread.name)
        self.assertFalse(service.snapshot().web_ready)

    def assert_failed_stage(
        self, service: BackupService, failure_code: str, *, constructed=True,
    ) -> list[str]:
        try:
            with self.assertRaisesRegex(RuntimeError, "backup service startup failed"):
                service.start()
        finally:
            self.assert_clean_stop(service, constructed=constructed)
        codes = self.codes()
        self.assertIn(failure_code, codes)
        self.assertEqual(
            [code for code in codes if code.startswith("startup_") and code.endswith("_failed")],
            [failure_code],
        )
        self.assertNotIn("service_started", codes)
        self.assert_private_values_absent()
        return codes

    def test_runtime_construction_failure_logs_only_fixed_runtime_stage(self) -> None:
        service = self.make_service(runtime_factory=fail_startup)

        codes = self.assert_failed_stage(service, "startup_runtime_failed", constructed=False)

        self.assertIn("startup_runtime_started", codes)
        self.assertNotIn("startup_runtime_ready", codes)
        self.assertNotIn("startup_recovery_started", codes)
        self.assertNotIn("startup_web_started", codes)

    def test_missing_native_storage_logs_runtime_failure_before_recovery(self) -> None:
        service = self.make_service(
            native_mode=True,
            runtime_factory=lambda: RuntimeComponents(self.store, self.scanner, self.worker),
        )

        codes = self.assert_failed_stage(service, "startup_runtime_failed")

        self.assertNotIn("startup_runtime_ready", codes)
        self.assertNotIn("startup_recovery_started", codes)

    def test_recovery_exception_logs_only_fixed_recovery_failure(self) -> None:
        class FailingWorker(FakeWorker):
            recover_startup = staticmethod(fail_startup)

        self.worker = FailingWorker(self.events)

        codes = self.assert_failed_stage(self.make_service(), "startup_recovery_failed")

        self.assertIn("startup_recovery_started", codes)
        self.assertNotIn("startup_recovery_ready", codes)
        self.assertNotIn("startup_runtime_ready", codes)
        self.assertNotIn("startup_web_started", codes)

    def test_recovery_lookup_failure_logs_fixed_recovery_failure(self) -> None:
        class FailingWorker(FakeWorker):
            @property
            def recover_startup(self):
                return fail_startup()

        self.worker = FailingWorker(self.events)

        codes = self.assert_failed_stage(self.make_service(), "startup_recovery_failed")

        self.assertIn("startup_recovery_started", codes)
        self.assertNotIn("startup_recovery_ready", codes)
        self.assertNotIn("startup_runtime_ready", codes)

    def test_unserialized_recovery_logs_fixed_recovery_failure(self) -> None:
        class UnserializedWorker(FakeWorker):
            def recover_startup(self):
                return False

        self.worker = UnserializedWorker(self.events)

        codes = self.assert_failed_stage(self.make_service(), "startup_recovery_failed")

        self.assertNotIn("startup_recovery_ready", codes)
        self.assertNotIn("startup_runtime_ready", codes)

    def test_web_factory_failure_logs_only_fixed_web_failure(self) -> None:
        service = self.make_service(web_factory=fail_startup)

        codes = self.assert_failed_stage(service, "startup_web_failed")

        self.assertIn("startup_runtime_ready", codes)
        self.assertIn("startup_web_started", codes)
        self.assertNotIn("startup_web_ready", codes)
        self.assertNotIn("startup_native_api_started", codes)

    def test_web_probe_failure_logs_only_fixed_web_failure(self) -> None:
        class FailingServer(FakeServer):
            handle_request = staticmethod(fail_startup)

        self.server = FailingServer()

        codes = self.assert_failed_stage(self.make_service(), "startup_web_failed")

        self.assertNotIn("startup_web_ready", codes)
        self.assertTrue(self.server.closed.is_set())

    def test_native_api_factory_failure_is_not_logged_as_web_failure(self) -> None:
        service = self.make_service(native_mode=True, native_api_factory=fail_startup)

        codes = self.assert_failed_stage(service, "startup_native_api_failed")

        self.assertIn("startup_web_ready", codes)
        self.assertIn("startup_native_api_started", codes)
        self.assertNotIn("startup_native_api_ready", codes)
        self.assertTrue(self.server.closed.is_set())

    def test_native_api_start_failure_is_not_logged_as_web_failure(self) -> None:
        self.native_api.start = fail_startup
        service = self.make_service(
            native_mode=True, native_api_factory=lambda *_: self.native_api,
        )

        codes = self.assert_failed_stage(service, "startup_native_api_failed")

        self.assertIn("startup_web_ready", codes)
        self.assertNotIn("startup_native_api_ready", codes)
        self.assertTrue(self.native_api.stopped)

    def test_ready_stages_follow_recovery_and_precede_service_started(self) -> None:
        observed_recovery_codes = []
        observed_scan_codes = []

        class ObservedWorker(FakeWorker):
            def recover_startup(worker) -> bool:
                observed_recovery_codes.append(self.codes())
                return super().recover_startup()

        class ObservedScanner(FakeScanner):
            def apply_scan(scanner, evidence, generation):
                observed_scan_codes.append(self.codes())
                return super().apply_scan(evidence, generation)

        self.worker = ObservedWorker(self.events)
        self.scanner = ObservedScanner(self.events)
        service = self.make_service()
        try:
            service.start()
        finally:
            self.assert_clean_stop(service)

        self.assertEqual(
            observed_recovery_codes,
            [["startup_runtime_started", "startup_recovery_started"]],
        )
        self.assertEqual(
            observed_scan_codes,
            [["startup_runtime_started", "startup_recovery_started", "startup_recovery_ready"]],
        )
        self.assertEqual(
            self.codes(),
            [
                "startup_runtime_started", "startup_recovery_started",
                "startup_recovery_ready", "startup_runtime_ready",
                "startup_web_started", "startup_web_ready",
                "service_started", "service_stopped",
            ],
        )
        self.assert_private_values_absent()

    def test_native_api_ready_is_recorded_before_service_started(self) -> None:
        service = self.make_service(
            native_mode=True, native_api_factory=lambda *_: self.native_api,
        )
        try:
            service.start()
        finally:
            self.assert_clean_stop(service)

        self.assertEqual(
            self.codes(),
            [
                "startup_runtime_started", "startup_recovery_started",
                "startup_recovery_ready", "startup_runtime_ready",
                "startup_web_started", "startup_web_ready",
                "startup_native_api_started", "startup_native_api_ready",
                "service_started", "service_stopped",
            ],
        )
        self.assertTrue(self.native_api.started)
        self.assertTrue(self.native_api.stopped)


if __name__ == "__main__":
    unittest.main()
