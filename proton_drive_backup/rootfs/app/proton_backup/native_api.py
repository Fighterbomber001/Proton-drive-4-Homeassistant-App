"""Private HA BackupAgent bridge. All Proton work is submitted to its owner."""
from __future__ import annotations

import asyncio
import base64
import hmac
import json
import logging
import os
from pathlib import Path
import re
import stat
from threading import Event, Thread
import uuid

from aiohttp import web

from .native_storage import (
    MAX_METADATA_BYTES, NativeDownload, NativeStorageError, validate_backup_id, validate_metadata,
)

_TOKEN = re.compile(r"[A-Za-z0-9._~-]{32,128}")


def _compact_json(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


class NativeApiServer:
    def __init__(self, *, submit, snapshot, installation_id, token, private_root,
                 host="0.0.0.0", port=8100):
        if not isinstance(token, str) or _TOKEN.fullmatch(token) is None:
            raise ValueError("invalid integration token")
        if not isinstance(installation_id, str) or re.fullmatch(r"[a-f0-9]{32}", installation_id) is None:
            raise ValueError("invalid installation identity")
        self._submit = submit
        self._snapshot = snapshot
        self._installation_id = installation_id
        self._token = token
        self._private = Path(private_root).absolute()
        self._native = self._private / "native"
        if self._private.is_symlink() or self._native.is_symlink():
            raise ValueError("invalid native storage root")
        self._native.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._host = host
        self.port = port
        self._runner = None
        self._thread = None
        self._loop = None
        self._async_stop = None
        self._ready = Event()
        self._failure = None
        self._closing = False
        self._active = 0

    def start(self):
        self._thread = Thread(target=self._thread_main, name="proton-backup-native-api")
        self._thread.start()
        if not self._ready.wait(5) or self._failure is not None:
            raise RuntimeError("native API startup failed")

    def stop(self, timeout=20):
        self._closing = True
        if self._loop is not None and self._async_stop is not None and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._async_stop.set)
        if self._thread is not None:
            self._thread.join(max(0, timeout))
            if self._thread.is_alive():
                raise TimeoutError("native API shutdown timed out")
        if self._failure is not None:
            raise RuntimeError("native API failed")

    def _thread_main(self):
        async def serve():
            self._loop = asyncio.get_running_loop()
            self._async_stop = asyncio.Event()
            try:
                await self.async_start()
                self._ready.set()
                await self._async_stop.wait()
            finally:
                await self.async_stop()
        try:
            asyncio.run(serve())
        except BaseException as error:
            self._failure = error
        finally:
            self._ready.set()

    async def async_start(self):
        app = web.Application(middlewares=[self._boundary])
        app.router.add_get("/v1/status", self._status)
        app.router.add_get("/v1/backups", self._list)
        app.router.add_put("/v1/backups/{backup_id}", self._upload)
        app.router.add_delete("/v1/backups/{backup_id}", self._delete)
        app.router.add_get("/v1/backups/{backup_id}/metadata", self._metadata)
        app.router.add_get("/v1/backups/{backup_id}/download", self._download)
        silent = logging.Logger("native-http", level=logging.CRITICAL)
        silent.addHandler(logging.NullHandler())
        silent.propagate = False
        self._runner = web.AppRunner(app, access_log=None, logger=silent,
                                    shutdown_timeout=1, handler_cancellation=True,
                                    max_field_size=32768)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self._host, self.port)
        await site.start()
        self.port = site._server.sockets[0].getsockname()[1]

    async def async_stop(self):
        self._closing = True
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None

    @web.middleware
    async def _boundary(self, request, handler):
        headers = request.headers.getall("Authorization", [])
        supplied = headers[0] if len(headers) == 1 else ""
        expected = "Bearer " + self._token
        if not supplied.isascii() or not hmac.compare_digest(supplied, expected):
            return self._error("invalid_auth", 401)
        if self._closing or self._active >= 4:
            return self._error("unavailable", 503)
        self._active += 1
        try:
            if request.query_string:
                return self._error("invalid_request", 400)
            if "backup_id" in request.match_info:
                try:
                    validate_backup_id(request.match_info["backup_id"])
                except NativeStorageError:
                    return self._error("invalid_backup_id", 400)
            return await handler(request)
        except asyncio.CancelledError:
            raise
        except web.HTTPException as error:
            return self._error("invalid_request", error.status)
        except NativeStorageError as error:
            code = getattr(error, "code", "storage_failed")
            statuses = {"backup_not_found": 404, "delete_not_supported": 501,
                        "authentication_required": 502, "storage_failed": 502,
                        "invalid_metadata": 400, "invalid_backup_id": 400}
            return self._error(code if code in statuses else "storage_failed", statuses.get(code, 502))
        except (ValueError, TypeError, json.JSONDecodeError):
            return self._error("invalid_request", 400)
        except Exception:
            return self._error("storage_failed", 502)
        finally:
            self._active -= 1

    @staticmethod
    def _error(code, status):
        return web.json_response({"error": code}, status=status,
                                 headers={"Cache-Control": "no-store"})

    @staticmethod
    def _json(value):
        return web.json_response(value, dumps=_compact_json,
                                 headers={"Cache-Control": "no-store"})

    async def _rpc(self, operation, backup_id=None, metadata=None, path=None, *, cleanup=None):
        cancel = Event()
        try:
            future = self._submit(operation, backup_id, metadata, path, cancel)
        except Exception:
            if cleanup is not None:
                cleanup()
            raise NativeStorageError() from None
        if cleanup is not None:
            future.add_done_callback(lambda _: cleanup())
        try:
            return await asyncio.wrap_future(future)
        except asyncio.CancelledError:
            cancel.set()
            if operation == "download":
                future.add_done_callback(self._cleanup_download_result)
            raise

    def _cleanup_download_result(self, future):
        try:
            if not future.cancelled():
                download = future.result()
                if isinstance(download, NativeDownload):
                    self._unlink_cache(download.path)
        except Exception:
            pass

    def _unlink_cache(self, path):
        try:
            path = Path(path)
            if not path.is_symlink() and path.resolve().is_relative_to(self._native.resolve()):
                path.unlink(missing_ok=True)
        except OSError:
            pass

    async def _status(self, request):
        return self._json({"api_version": 1, "installation_id": self._installation_id,
                                  "connected": self._snapshot().connected is True,
                                  "delete_supported": False})

    async def _list(self, request):
        return self._json({"backups": await self._rpc("list")})

    async def _metadata(self, request):
        metadata = await self._rpc("get", request.match_info["backup_id"])
        return self._json(metadata)

    async def _delete(self, request):
        return self._error("delete_not_supported", 501)

    async def _upload(self, request):
        identity = request.match_info["backup_id"]
        header = request.headers.getall("X-Backup-Metadata", [])
        if len(header) != 1 or len(header[0]) > 32768:
            return self._error("invalid_metadata", 400)
        try:
            raw = base64.b64decode(header[0], validate=True)
            if len(raw) > MAX_METADATA_BYTES:
                raise ValueError
            metadata = validate_metadata(identity, json.loads(raw))
        except (ValueError, TypeError, NativeStorageError):
            return self._error("invalid_metadata", 400)
        path = self._native / ("upload-" + uuid.uuid4().hex + ".tar")
        future_pending = False
        try:
            count = 0
            with path.open("xb") as stream:
                path.chmod(0o600)
                while chunk := await asyncio.wait_for(request.content.read(1024 * 1024), 60):
                    count += len(chunk)
                    if count > metadata["size"]:
                        return self._error("size_mismatch", 400)
                    await self._file_io(stream.write, chunk)
            if count != metadata["size"]:
                return self._error("size_mismatch", 400)
            future_pending = True
            try:
                confirmed = await self._rpc("upload", identity, metadata, path,
                                            cleanup=lambda: self._unlink_cache(path))
            except asyncio.CancelledError:
                raise
            else:
                future_pending = False
            return self._json(confirmed)
        finally:
            if not future_pending:
                self._unlink_cache(path)

    async def _download(self, request):
        identity = request.match_info["backup_id"]
        # Storage verifies the archive against the manifest in one Proton job.
        # Another lookup could see a different account after a credential change.
        download = await self._rpc("download", identity)
        if not isinstance(download, NativeDownload):
            raise NativeStorageError()
        path = download.path
        descriptor = None
        response = None
        try:
            if (not isinstance(path, Path) or path.is_symlink()
                    or not path.resolve().is_relative_to(self._native.resolve())):
                raise NativeStorageError()
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size != download.size:
                raise NativeStorageError()
            response = web.StreamResponse(headers={"Content-Type": "application/octet-stream",
                                                    "Content-Length": str(info.st_size),
                                                    "Cache-Control": "no-store"})
            await response.prepare(request)
            remaining = info.st_size
            while remaining:
                chunk = await self._file_io(os.read, descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    raise NativeStorageError()
                await response.write(chunk)
                remaining -= len(chunk)
            await response.write_eof()
            return response
        except BaseException:
            if response is not None and response.prepared:
                response.force_close()
                if request.transport is not None:
                    request.transport.close()
            raise
        finally:
            if descriptor is not None:
                os.close(descriptor)
            self._unlink_cache(path)

    @staticmethod
    async def _file_io(operation, *args):
        # A cancelled handler must not close a descriptor still used by its IO thread.
        task = asyncio.create_task(asyncio.to_thread(operation, *args))
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            try:
                await task
            finally:
                raise
