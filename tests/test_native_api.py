import tests
import asyncio
import base64
from concurrent.futures import Future
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

import aiohttp

from proton_backup.native_storage import NativeDownload


METADATA = {"addons": [], "backup_id": "abc12345", "date": "2026-11-22T12:00:00Z",
            "database_included": True, "extra_metadata": {}, "folders": [],
            "homeassistant_included": True, "homeassistant_version": "2026.11.2",
            "name": "Test", "protected": True, "size": 4}
TOKEN = "a" * 64


class NativeApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from proton_backup.native_api import NativeApiServer
        self.temporary = TemporaryDirectory()
        self.private = Path(self.temporary.name)
        self.calls = []
        self.download_path = self.private / "native" / "download.tar"
        self.download_path.parent.mkdir()
        self.download_path.write_bytes(b"data")
        self.pending = None
        self.pending_cancel = None
        def submit(operation, backup_id=None, metadata=None, path=None, cancel=None):
            self.calls.append((operation, backup_id, metadata, path))
            future = Future()
            if self.pending is not None:
                self.pending_cancel = cancel
                self.pending.set_result(future)
                return future
            if operation == "list":
                future.set_result([METADATA])
            elif operation == "download":
                future.set_result(NativeDownload(self.download_path, METADATA["size"]))
            else:
                if path is not None:
                    self.assertEqual(path.read_bytes(), b"data")
                future.set_result(METADATA)
            return future
        self.api = NativeApiServer(submit=submit, snapshot=lambda: SimpleNamespace(connected=True),
                                   installation_id="b" * 32, token=TOKEN, private_root=self.private,
                                   host="127.0.0.1", port=0)
        await self.api.async_start()
        self.url = f"http://127.0.0.1:{self.api.port}"
        self.session = aiohttp.ClientSession(headers={"Authorization": "Bearer " + TOKEN})

    async def asyncTearDown(self):
        await self.session.close()
        await self.api.async_stop()
        self.temporary.cleanup()

    async def test_authentication_precedes_all_operations_and_never_echoes_token(self):
        async with self.session.get(self.url + "/v1/status", headers={"Authorization": "Bearer wrong-secret"}) as response:
            self.assertEqual(response.status, 401)
            self.assertNotIn("wrong-secret", await response.text())
        self.assertEqual(self.calls, [])
        async with self.session.get(self.url + "/v1/status") as response:
            self.assertEqual(response.status, 200)
            self.assertEqual((await response.json())["installation_id"], "b" * 32)

    async def test_streamed_upload_is_confirmed_and_temporary_file_removed(self):
        async def chunks():
            yield b"da"
            yield b"ta"
        encoded = base64.b64encode(json.dumps(METADATA).encode()).decode()
        async with self.session.put(self.url + "/v1/backups/abc12345", data=chunks(),
                                    headers={"X-Backup-Metadata": encoded}) as response:
            self.assertEqual(response.status, 200, await response.text())
            self.assertEqual(await response.json(), METADATA)
        self.assertEqual(self.calls[0][0], "upload")
        self.assertFalse(self.calls[0][3].exists())

    async def test_short_upload_fails_before_cli_submission(self):
        encoded = base64.b64encode(json.dumps(METADATA).encode()).decode()
        async with self.session.put(self.url + "/v1/backups/abc12345", data=b"bad",
                                    headers={"X-Backup-Metadata": encoded}) as response:
            self.assertEqual(response.status, 400)
        self.assertEqual(self.calls, [])

    async def test_delete_is_explicitly_unsupported_before_any_submission(self):
        async with self.session.delete(self.url + "/v1/backups/abc12345") as response:
            self.assertEqual(response.status, 501)
            self.assertEqual((await response.json())["error"], "delete_not_supported")
        self.assertEqual(self.calls, [])

    async def test_download_stream_has_exact_length_and_cache_is_removed(self):
        async with self.session.get(self.url + "/v1/backups/abc12345/download") as response:
            self.assertEqual(response.status, 200, await response.text())
            self.assertEqual(response.content_length, 4)
            self.assertEqual(await response.read(), b"data")
        self.assertFalse(self.download_path.exists())

    async def test_restore_does_not_request_metadata_in_a_separate_proton_job(self):
        async with self.session.get(self.url + "/v1/backups/abc12345/download") as response:
            self.assertEqual(response.status, 200, await response.text())
            await response.read()
        self.assertEqual([(operation, identity) for operation, identity, _, _ in self.calls],
                         [("download", "abc12345")])

    async def test_truncated_download_spool_is_rejected_and_removed(self):
        self.download_path.write_bytes(b"bad")
        async with self.session.get(self.url + "/v1/backups/abc12345/download") as response:
            self.assertEqual(response.status, 502)
        self.assertFalse(self.download_path.exists())

    async def test_download_cannot_read_outside_private_native_cache(self):
        outside = self.private / "outside.txt"
        outside.write_bytes(b"data")
        self.download_path = outside
        async with self.session.get(self.url + "/v1/backups/abc12345/download") as response:
            self.assertEqual(response.status, 502)
        self.assertTrue(outside.exists())

    async def test_failed_upload_removes_its_spool_and_returns_safe_error(self):
        from proton_backup.native_storage import NativeStorageError
        def fail(*args):
            self.calls.append(args)
            future = Future()
            future.set_exception(NativeStorageError())
            return future
        self.api._submit = fail
        encoded = base64.b64encode(json.dumps(METADATA).encode()).decode()
        async with self.session.put(self.url + "/v1/backups/abc12345", data=b"data",
                                    headers={"X-Backup-Metadata": encoded}) as response:
            self.assertEqual(response.status, 502)
            self.assertEqual(await response.json(), {"error": "storage_failed"})
        self.assertFalse(self.calls[0][3].exists())

    async def test_invalid_id_is_rejected_without_submission(self):
        async with self.session.get(self.url + "/v1/backups/invalid.id/metadata") as response:
            self.assertEqual(response.status, 400)
        self.assertEqual(self.calls, [])

    async def test_cancelled_request_signals_pending_cli_job(self):
        self.pending = Future()
        request = asyncio.create_task(self.session.get(self.url + "/v1/backups"))
        pending_rpc = await asyncio.wait_for(asyncio.wrap_future(self.pending), 2)
        request.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await request
        for _ in range(100):
            if self.pending_cancel.is_set():
                break
            await asyncio.sleep(0.005)
        self.assertTrue(self.pending_cancel.is_set())
        if not pending_rpc.done():
            pending_rpc.set_result([])

    async def test_cancelling_restore_removes_a_spool_returned_after_cancellation(self):
        self.pending = Future()
        request = asyncio.create_task(self.session.get(self.url + "/v1/backups/abc12345/download"))
        pending_rpc = await asyncio.wait_for(asyncio.wrap_future(self.pending), 2)
        self.assertTrue(pending_rpc.set_running_or_notify_cancel())
        request.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await request
        for _ in range(100):
            if self.pending_cancel.is_set():
                break
            await asyncio.sleep(0.005)
        self.assertTrue(self.pending_cancel.is_set())
        pending_rpc.set_result(NativeDownload(self.download_path, METADATA["size"]))
        self.assertFalse(self.download_path.exists())
