from __future__ import annotations

import json
from datetime import UTC, datetime
from html.parser import HTMLParser
from io import BytesIO
from pathlib import Path
from queue import Queue
import re
import shutil
import socket
import subprocess
import tempfile
import textwrap
from threading import Barrier, Event, Lock, Thread
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from proton_backup.models import RemoteFile
from proton_backup.web import (
    CommandQueue,
    ControlAction,
    ControlCommand,
    DiagnosticBuffer,
    IngressRequestHandler,
    IngressServer,
    WebController,
)
from proton_backup.worker import ServiceSnapshot


INGRESS_PEER = "172.30.32.2"
ORIGIN = "https://homeassistant.example"
USER_A = "0123456789abcdef0123456789abcdef"
USER_B = "fedcba9876543210fedcba9876543210"


class StatusPageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []
        self.buttons: list[dict[str, object]] = []
        self._button_index: int | None = None

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        attributes = dict(attrs)
        self.tags.append((tag, attributes))
        if tag == "button":
            self.buttons.append({"attrs": attributes, "text": ""})
            self._button_index = len(self.buttons) - 1

    def handle_endtag(self, tag: str) -> None:
        if tag == "button":
            self._button_index = None

    def handle_data(self, data: str) -> None:
        if self._button_index is not None:
            button = self.buttons[self._button_index]
            button["text"] = f"{button['text']} {data}".strip()


class ControllerClient:
    def __init__(self, controller: WebController) -> None:
        self.controller = controller

    def request(
        self,
        method: str,
        path: str,
        *,
        peer: str = INGRESS_PEER,
        headers: dict[str, str] | None = None,
        body: object | bytes | None = None,
    ):
        request_headers = dict(headers or {})
        if isinstance(body, bytes):
            encoded = body
        elif body is None:
            encoded = b""
        else:
            encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
        if method == "POST":
            request_headers.setdefault("Content-Length", str(len(encoded)))
        return self.controller.handle(
            method=method,
            target=path,
            peer=peer,
            headers=request_headers,
            body=encoded,
        )

    def get(self, path: str, **kwargs):
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs):
        return self.request("POST", path, **kwargs)


class SequentialCommandIds:
    def __init__(self) -> None:
        self.lock = Lock()
        self.value = 0

    def __call__(self) -> str:
        with self.lock:
            self.value += 1
            value = self.value
        return f"{value:032x}"


class SequentialValues:
    def __init__(self, prefix: str) -> None:
        self.prefix = prefix
        self.value = 0
        self.lock = Lock()

    def __call__(self) -> str:
        with self.lock:
            self.value += 1
            return f"{self.prefix}-{self.value:08d}"


class FailingRotationTokens:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self) -> str:
        self.calls += 1
        if self.calls == 1:
            return "csrf-before-failure"
        if self.calls == 2:
            raise RuntimeError("password=private-token-factory-detail")
        return f"csrf-after-failure-{self.calls}"


class FailAfterAcceptedFactories:
    def __init__(self) -> None:
        self.token_calls = 0
        self.command_id_calls = 0

    def token(self) -> str:
        self.token_calls += 1
        if self.token_calls == 1:
            return "csrf-before-accept"
        if self.token_calls == 2:
            return "csrf-after-accept"
        raise RuntimeError("password=unexpected-token-factory-call")

    def command_id(self) -> str:
        self.command_id_calls += 1
        if self.command_id_calls == 1:
            return "1" * 32
        raise RuntimeError("password=unexpected-command-id-factory-call")


class BlockingClock:
    def __init__(self, value: float) -> None:
        self.value = value
        self.block = False
        self.called = Event()
        self.release = Event()

    def __call__(self) -> float:
        sampled = self.value
        if self.block:
            self.called.set()
            self.release.wait(timeout=2)
        return sampled


class GatedSnapshot:
    def __init__(self, snapshot: ServiceSnapshot) -> None:
        self.snapshot = snapshot
        self.enabled = False
        self.barrier = Barrier(2)

    def __call__(self) -> ServiceSnapshot:
        if self.enabled:
            self.barrier.wait(timeout=2)
        return self.snapshot


class RawHttpResponse:
    def __init__(self, wire: bytes) -> None:
        head, separator, self.body = wire.partition(b"\r\n\r\n")
        if not separator:
            raise AssertionError(f"missing HTTP header terminator: {wire!r}")
        lines = head.split(b"\r\n")
        self.status = int(lines[0].split(b" ", 2)[1])
        self.headers: dict[str, str] = {}
        for line in lines[1:]:
            name, value = line.split(b":", 1)
            self.headers[name.decode("ascii")] = value.strip().decode("ascii")

    def json(self):
        return json.loads(self.body)


class LoopbackIngress:
    def __init__(self, controller: WebController) -> None:
        self.server = IngressServer("127.0.0.1", 0, controller)
        self.thread = Thread(
            target=self.server.serve_forever,
            kwargs={"poll_interval": 0.01},
        )
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        if self.thread.is_alive():
            raise AssertionError("loopback Ingress server did not stop")

    def request(self, request: bytes) -> RawHttpResponse:
        with socket.create_connection(self.server.server_address, timeout=2) as client:
            client.settimeout(2)
            client.sendall(request)
            client.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                chunk = client.recv(65_536)
                if not chunk:
                    break
                chunks.append(chunk)
        return RawHttpResponse(b"".join(chunks))


class WebControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.monotonic = 1_000.0
        self.tokens = iter(
            ("csrf-user-a", "csrf-user-b", "csrf-user-a-new", "csrf-fourth")
        )
        self.commands = Queue(maxsize=2)
        self.remote = RemoteFile(
            uid="remote-1",
            name="ha-v1--safe.tar",
            path="/my-files/private-should-not-be-returned/ha-v1--safe.tar",
            size=4096,
            modified_at=datetime(2026, 8, 11, 8, 0, tzinfo=UTC),
        )
        self.snapshot = ServiceSnapshot(
            web_ready=True,
            connected=True,
            scanner_state="idle",
            active_sha256="a" * 64,
            active_name="Home Assistant.tar",
            active_started_at=datetime(2026, 8, 11, 9, 0, tzinfo=UTC),
            queue_size=2,
            next_retry_at=datetime(2026, 8, 11, 9, 5, tzinfo=UTC),
            last_success_at=datetime(2026, 8, 11, 8, 0, tzinfo=UTC),
            last_error_code=None,
            remote_files=(self.remote,),
        )
        self.diagnostics = DiagnosticBuffer()
        self.controller = WebController(
            snapshot_provider=lambda: self.snapshot,
            command_queue=self.commands,
            diagnostics=self.diagnostics,
            monotonic=lambda: self.monotonic,
            token_factory=lambda: next(self.tokens),
            allowed_origins={ORIGIN},
        )
        self.client = ControllerClient(self.controller)
        self.ingress_headers = {"X-Remote-User-Id": USER_A}

    def status(self, *, user: str = USER_A):
        return self.client.get(
            "/api/status", headers={"X-Remote-User-Id": user}
        )

    def csrf(self, *, user: str = USER_A) -> str:
        return self.status(user=user).json()["csrf_token"]

    def mutation_headers(
        self, *, user: str = USER_A, csrf: str | None = None
    ) -> dict[str, str]:
        return {
            "X-Remote-User-Id": user,
            "Origin": ORIGIN,
            "X-CSRF-Token": csrf if csrf is not None else self.csrf(user=user),
        }

    def test_get_status_sets_security_headers(self) -> None:
        response = self.client.get(
            "/api/status", peer=INGRESS_PEER, headers=self.ingress_headers
        )
        self.assertEqual(response.status, 200)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertIn(
            "default-src 'self'", response.headers["Content-Security-Policy"]
        )
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "SAMEORIGIN")
        self.assertEqual(
            response.headers["Permissions-Policy"],
            "camera=(), microphone=(), geolocation=()",
        )
        self.assertNotIn("Access-Control-Allow-Origin", response.headers)

    def test_closed_command_admission_rejects_without_factories_or_state_commit(self) -> None:
        commands = CommandQueue(maxsize=2)
        token_calls = 0
        command_calls = 0

        def token_factory() -> str:
            nonlocal token_calls
            token_calls += 1
            return f"{token_calls:064x}"

        def command_factory() -> str:
            nonlocal command_calls
            command_calls += 1
            return f"{command_calls:032x}"

        controller = WebController(
            snapshot_provider=lambda: self.snapshot,
            command_queue=commands,
            monotonic=lambda: self.monotonic,
            token_factory=token_factory,
            command_id_factory=command_factory,
            allowed_origins={ORIGIN},
        )
        client = ControllerClient(controller)
        csrf = client.get(
            "/api/status", headers={"X-Remote-User-Id": USER_A}
        ).json()["csrf_token"]
        commands.close_admission()

        response = client.post(
            "/api/scan",
            headers={
                "X-Remote-User-Id": USER_A,
                "Origin": ORIGIN,
                "X-CSRF-Token": csrf,
            },
            body={},
        )

        self.assertEqual(response.status, 409)
        self.assertTrue(commands.empty())
        self.assertEqual(token_calls, 1)
        self.assertEqual(command_calls, 0)

    def test_status_page_has_required_german_controls(self) -> None:
        response = self.client.get("/", headers=self.ingress_headers)

        self.assertEqual(response.status, 200)
        for label in (
            "Mit Proton verbinden",
            "Jetzt prüfen",
            "Upload abbrechen",
            "Erneut versuchen",
            "Uploader neu starten",
            "Verbindung trennen",
        ):
            self.assertIn(label, response.text)

    def test_status_page_is_accessible_and_uses_only_relative_assets(self) -> None:
        html = self.client.get("/", headers=self.ingress_headers).text
        parser = StatusPageParser()
        parser.feed(html)

        html_tags = [attrs for tag, attrs in parser.tags if tag == "html"]
        self.assertEqual(len(html_tags), 1)
        self.assertEqual(html_tags[0].get("lang"), "de")
        self.assertGreaterEqual(len(parser.buttons), 7)
        for button in parser.buttons:
            attrs = button["attrs"]
            self.assertEqual(attrs.get("type"), "button")
            self.assertTrue(
                str(button["text"]).strip() or attrs.get("aria-label"),
                "button needs an accessible name",
            )

        self.assertFalse(any(tag == "style" for tag, _attrs in parser.tags))
        script_tags = [attrs for tag, attrs in parser.tags if tag == "script"]
        self.assertEqual(script_tags, [{"src": "static/app.js", "defer": None}])
        resource_urls = [
            value
            for _tag, attrs in parser.tags
            for name, value in attrs.items()
            if name in {"href", "src"} and value is not None
        ]
        self.assertIn("static/app.css", resource_urls)
        for url in resource_urls:
            self.assertNotRegex(url, r"^(?:/|https?:|//)")
        for _tag, attrs in parser.tags:
            self.assertNotIn("style", attrs)
            self.assertFalse(any(name.startswith("on") for name in attrs))

    def test_status_script_uses_safe_dom_updates_and_declared_relative_routes(self) -> None:
        response = self.client.get(
            "/static/app.js", headers=self.ingress_headers
        )

        self.assertEqual(response.status, 200)
        self.assertNotIn("innerHTML", response.text)
        self.assertNotIn("insertAdjacentHTML", response.text)
        self.assertNotIn("document.write", response.text)
        self.assertIn("textContent", response.text)
        api_routes = set(
            re.findall(r'["\']((?:/)?api/[a-z/]+)["\']', response.text)
        )
        self.assertEqual(
            api_routes,
            {
                "api/status",
                "api/diagnostics",
                "api/auth/connect",
                "api/auth/disconnect",
                "api/auth/renew",
                "api/scan",
                "api/upload/cancel",
                "api/upload/retry",
                "api/worker/restart",
            },
        )
        self.assertNotRegex(response.text, r"https?://")

    def test_stylesheet_contains_no_import_or_remote_url(self) -> None:
        css = self.client.get(
            "/static/app.css", headers=self.ingress_headers
        ).text

        self.assertNotIn("@import", css)
        self.assertNotRegex(css, r"url\s*\(")
        self.assertNotRegex(css, r"https?://")

    def test_status_script_runtime_safety_contract(self) -> None:
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node.js is unavailable for the browser-script contract")

        app_js = (
            Path(__file__).resolve().parents[1]
            / "proton_drive_backup"
            / "rootfs"
            / "app"
            / "proton_backup"
            / "static"
            / "app.js"
        )
        harness = textwrap.dedent(
            r"""
            "use strict";
            const assert = require("assert").strict;
            const fs = require("fs");
            const vm = require("vm");
            const source = fs.readFileSync(process.argv[2], "utf8");
            const SHA = "b".repeat(64);
            const NEXT_SHA = "c".repeat(64);

            class FakeClassList {
              add() {}
              remove() {}
              toggle() {}
            }

            class FakeElement {
              constructor() {
                this.attributes = new Map();
                this.classList = new FakeClassList();
                this.disabled = false;
                this.hidden = false;
                this.listeners = new Map();
                this.open = false;
                this.textContent = "";
                this.children = [];
              }
              addEventListener(name, callback) { this.listeners.set(name, callback); }
              append(...children) { this.children.push(...children); }
              click() {
                if (!this.disabled && this.listeners.has("click")) {
                  this.listeners.get("click")();
                }
              }
              close() { this.open = false; }
              focus() {}
              hasAttribute(name) { return this.attributes.has(name); }
              removeAttribute(name) { this.attributes.delete(name); }
              replaceChildren(...children) { this.children = children; }
              setAttribute(name, value) { this.attributes.set(name, value); }
              showModal() { this.open = true; }
            }

            function statusPayload(token, options = {}) {
              const payload = {
                csrf_token: token,
                service: {
                  web_ready: options.webReady !== false,
                  connected: options.connected === true,
                  scanner_state: "idle",
                },
                upload: {
                  sha256: options.activeSha || null,
                  name: options.activeSha ? "Home Assistant.tar" : null,
                  started_at: options.activeSha ? "2026-08-11T09:00:00Z" : null,
                },
                queue: { size: 1, next_retry_at: options.retryAt || null },
                last_success_at: null,
                last_error_code: options.lastError || null,
                retry_sha256: options.retrySha256 || null,
                retry_revision: options.retryRevision || null,
                remote_files: [],
              };
              payload.login_active = options.loginActive === true;
              if (options.loginActive === true) {
                payload.login_generation = options.loginGeneration || "d".repeat(32);
                payload.login_remaining_ms = options.loginRemainingMs;
              }
              if (options.loginActive === true && options.loginUrl) {
                payload.login_url = options.loginUrl;
              }
              return payload;
            }

            function response(options = {}) {
              const payload = options.payload === undefined ? {} : options.payload;
              const raw = options.raw === undefined ? JSON.stringify(payload) : options.raw;
              return {
                ok: options.ok !== false,
                async json() {
                  if (options.bodyError) throw new TypeError("body transport failed");
                  return JSON.parse(raw);
                },
                async text() {
                  if (options.bodyError) throw new TypeError("body transport failed");
                  return raw;
                },
              };
            }

            async function settle() {
              for (let index = 0; index < 30; index += 1) {
                await new Promise((resolve) => setTimeout(resolve, 0));
              }
            }

            async function runScenario(name) {
              const elements = new Map();
              const documentListeners = new Map();
              const windowListeners = new Map();
              const postCalls = [];
              let getCount = 0;
              let postCount = 0;
              let currentToken = "token-one";
              let retryAt = "2026-08-11T09:05:00Z";
              let releaseStatus = null;
              let retryRaceChanged = false;
              let serverRetryPending = false;
              let blockNativeStatus = false;
              let clock = 0;
              let nextInterval = 1;
              const intervals = new Map();
              let changePanelVisibility;
              let checkLoginHandoff;
              const loginTimerDelays = [];

              const document = {
                documentElement: {},
                visibilityState: "visible",
                addEventListener(event, callback) { documentListeners.set(event, callback); },
                createElement() { return new FakeElement(); },
                querySelector(selector) {
                  if (!elements.has(selector)) elements.set(selector, new FakeElement());
                  return elements.get(selector);
                },
              };
              const window = {
                addEventListener(event, callback) { windowListeners.set(event, callback); },
                clearTimeout,
                setInterval(callback, delay) {
                  const id = nextInterval++;
                  intervals.set(id, { callback, delay });
                  return id;
                },
                clearInterval(id) { intervals.delete(id); },
                setTimeout(callback, milliseconds) {
                  if (name === "auth-after-poll-window" && milliseconds === 2000) {
                    checkLoginHandoff = callback;
                    return 3;
                  }
                  if (milliseconds > 1000) loginTimerDelays.push(milliseconds);
                  return milliseconds > 1000 ? 2 : setTimeout(callback, 0);
                },
              };
              if (name === "status-poll-iframe") {
                window.IntersectionObserver = class {
                  constructor(callback) {
                    changePanelVisibility = (visible) => callback([
                      { isIntersecting: visible, intersectionRatio: visible ? 1 : 0 },
                    ]);
                  }
                  observe(element) { assert.equal(element, document.documentElement); }
                };
              }

              async function fetch(url, options = {}) {
                if (options.method !== "POST") {
                  getCount += 1;
                  if (name === "auth-after-poll-window") {
                    const payload = statusPayload(currentToken, {
                      loginActive: getCount >= 3,
                      loginRemainingMs: 30000,
                      loginUrl: getCount >= 3 ? "https://account.proton.me/desktop/login?app=drive" : null,
                    });
                    payload.service.native_mode = true;
                    return response({ payload });
                  }
                  if (name === "native-status" && getCount > 1) {
                    const denied = response({ ok: false, payload: { error: { code: "access_denied" } } });
                    if (!blockNativeStatus) return denied;
                    return new Promise((resolve) => { releaseStatus = () => resolve(denied); });
                  }
                  if (name === "readiness-race" && getCount === 2) {
                    return new Promise((resolve) => {
                      releaseStatus = () => resolve(response({
                        payload: statusPayload(currentToken, { webReady: false }),
                      }));
                    });
                  }
                  if (name === "retry-race" && getCount === 2) {
                    return new Promise((resolve) => {
                      releaseStatus = () => {
                        retryRaceChanged = true;
                        resolve(response({
                          payload: statusPayload(currentToken, {
                            connected: true,
                            retryAt: "2026-08-11T09:10:00Z",
                            retrySha256: NEXT_SHA,
                            retryRevision: 2,
                          }),
                        }));
                      };
                    });
                  }
                  if (
                    name === "stale"
                    || (name === "login-status" && getCount > 2)
                  ) {
                    throw new TypeError("status unavailable");
                  }
                  const retrySha256 = (
                    name === "retry-ack"
                    || (name === "retry-target" && getCount === 1)
                    || name === "retry-race"
                    || ([
                      "retry-malformed-accepted", "retry-empty-accepted",
                      "retry-missing-accepted", "retry-false-accepted",
                    ].includes(name)
                      && !serverRetryPending)
                  ) ? (retryRaceChanged ? NEXT_SHA : SHA) : null;
                  return response({
                    payload: statusPayload(currentToken, {
                      connected: [
                        "retry-target", "retry-ack", "retry-race",
                        "retry-malformed-accepted", "retry-empty-accepted",
                        "retry-missing-accepted", "retry-false-accepted", "not-ready",
                      ].includes(name),
                      webReady: name !== "not-ready"
                        && name !== "login-not-ready"
                        && !(name === "readiness-race" && getCount > 1),
                      activeSha: name === "not-ready" ? "a".repeat(64) : null,
                      lastError: retrySha256 ? "network_unavailable" : null,
                      retryAt: name === "retry-ack"
                        ? retryAt
                        : (name === "retry-race"
                          ? (retryRaceChanged
                            ? "2026-08-11T09:10:00Z"
                            : "2026-08-11T09:05:00Z")
                          : null),
                      retrySha256: name === "not-ready" ? SHA : retrySha256,
                      retryRevision: retrySha256 === null
                        ? null
                        : (retryRaceChanged || retryAt === "2026-08-11T09:10:00Z" ? 2 : 1),
                      loginUrl: ["login-status", "login-not-ready"].includes(name)
                        && getCount === 1
                        ? "https://account.proton.me/desktop/login?app=drive&pv=3#payload=0%3AFakeUserCode123%3AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D%3Acli-drive"
                        : null,
                      loginActive: [
                        "login-status", "login-expired", "login-not-ready",
                      ].includes(name),
                      loginGeneration: "d".repeat(32),
                      loginRemainingMs: name === "login-expired" ? 0 : 30000,
                    }),
                  });
                }

                postCount += 1;
                postCalls.push({ url, options });
                if (name === "fetch-reject" && postCount === 1) {
                  throw new TypeError("fetch failed");
                }
                if (name === "body-reject" && postCount === 1) {
                  return response({ bodyError: true });
                }
                if (name === "malformed") {
                  return response({ raw: "{not-json" });
                }
                if (name === "http-error") {
                  return response({ ok: false, payload: { error: { code: "service_busy" } } });
                }
                if ([
                  "retry-malformed-accepted", "retry-empty-accepted",
                  "retry-missing-accepted", "retry-false-accepted",
                ].includes(name)) {
                  serverRetryPending = true;
                  if (name === "retry-malformed-accepted") {
                    return response({ raw: "{not-json" });
                  }
                  if (name === "retry-empty-accepted") {
                    return response({ raw: "" });
                  }
                  if (name === "retry-missing-accepted") {
                    return response({ payload: { csrf_token: "token-two" } });
                  }
                  return response({ payload: { accepted: false, csrf_token: "token-two" } });
                }
                currentToken = postCount === 1 ? "token-two" : "token-three";
                const payload = { accepted: true, csrf_token: currentToken };
                return response({ payload });
              }

              const context = vm.createContext({
                Array,
                Date,
                Error,
                Intl,
                JSON,
                Map,
                Number,
                Object,
                Promise,
                Set,
                String,
                TypeError,
                URL,
                Uint8Array,
                console,
                crypto: require("crypto").webcrypto,
                document,
                fetch,
                performance: { now: () => clock },
                setTimeout,
                window,
              });
              vm.runInContext(source, context, { filename: "app.js" });
              await settle();

              if (name === "auth-after-poll-window") {
                clock = 600000;
                [...intervals.values()].forEach(({callback}) => callback());
                assert.equal(intervals.size, 0);
                elements.get("#connect-button").click();
                await settle();
                assert.equal(postCalls.length, 1);
                assert.equal(getCount, 2, "first check after action did not yet get the link");
                assert.equal(elements.get("#login-link").hasAttribute("href"), false);
                assert.equal(typeof checkLoginHandoff, "function");
                const followup = checkLoginHandoff;
                checkLoginHandoff = undefined;
                await followup();
                assert.equal(elements.get("#login-link").hasAttribute("href"), true);
                assert.equal(checkLoginHandoff, undefined, "handoff checks stop when the link appears");
                assert.equal(intervals.size, 0, "the explicit action does not reopen passive polling");
                return;
              }

              if (name === "status-poll-iframe") {
                assert.equal(getCount, 0, "a not-yet-visible panel issues no status reads");
                changePanelVisibility(true);
                await settle();
                assert.equal(getCount, 1);
                assert.equal(intervals.size, 1);
                changePanelVisibility(false);
                assert.equal(intervals.size, 0, "an invisible iframe stops without a tab switch");
                changePanelVisibility(true);
                await settle();
                assert.equal(getCount, 2, "reopening the embedded page refreshes immediately");
                return;
              }

              if (name === "status-poll-window") {
                assert.equal(getCount, 1, "opening reads once immediately");
                windowListeners.get("pageshow")();
                await settle();
                assert.equal(getCount, 1, "initial pageshow does not duplicate the first read");
                assert.equal(intervals.size, 1);
                assert.equal([...intervals.values()][0].delay, 30000);
                const tick = async (time) => {
                  clock = time;
                  [...intervals.values()].forEach(({callback}) => callback());
                  await settle();
                };
                for (let time = 30000; time < 600000; time += 30000) await tick(time);
                assert.equal(getCount, 20, "one read per interval within the ten-minute window");
                await tick(600000);
                assert.equal(intervals.size, 0, "polling stops after ten minutes");
                await tick(630000);
                assert.equal(getCount, 20, "no read after expiry");
                document.visibilityState = "hidden";
                documentListeners.get("visibilitychange")();
                document.visibilityState = "visible";
                documentListeners.get("visibilitychange")();
                await settle();
                assert.equal(getCount, 21, "returning to the page opens a new window");
                assert.equal(intervals.size, 1);
                windowListeners.get("pagehide")();
                assert.equal(intervals.size, 0, "leaving the page cancels polling");
                windowListeners.get("pageshow")();
                await settle();
                assert.equal(getCount, 22, "browser navigation back refreshes");
                document.visibilityState = "hidden";
                documentListeners.get("visibilitychange")();
                assert.equal(intervals.size, 0, "background tabs do not poll");
                await tick(660000);
                assert.equal(getCount, 22);
                return;
              }

              if (name === "native-status") {
                const native = statusPayload("native-token", { connected: true });
                native.service.native_mode = true;
                native.upload.native_operation = "download";
                native.upload.name = "Restore";
                vm.runInContext(`renderStatus(${JSON.stringify(native)}); state.statusFresh = true; updateControls();`, context);
                assert.equal(elements.get("#cancel-button").disabled, false);
                assert.equal(elements.get("#scan-button").disabled, true);
                assert.equal(elements.get("#retry-button").disabled, true);
                assert.equal(elements.get("#upload-name").textContent, "Download: Restore");
                const table = elements.get("#remote-files");
                const note = elements.get("#backup-history-note");
                const summary = elements.get("#last-success");
                const summaryHeading = elements.get("#last-success-heading");
                assert.match(summary.textContent, /nicht verfügbar/);
                native.backup_history = {
                  state: "ready",
                  files: [
                    { name: "<img> Test-Sicherung", size: 4096, date: "2026-08-11T08:00:00Z" },
                    { name: "Ältere Sicherung", size: 2048, date: "2026-08-08T08:00:00Z" },
                  ],
                };
                const renderNative = () => vm.runInContext(`renderStatus(${JSON.stringify(native)});`, context);
                renderNative();
                assert.equal(table.children[0].children[0].textContent, "<img> Test-Sicherung");
                assert.match(table.children[0].children[1].textContent, /KiB/);
                assert.match(table.children[0].children[2].textContent, /2026/);
                assert.equal(summaryHeading.textContent, "Letzte bestätigte Sicherung");
                assert.equal(summary.textContent, table.children[0].children[2].textContent);
                assert.notEqual(summary.textContent, table.children[1].children[2].textContent);
                native.last_success_at = "2026-08-12T11:00:00Z";
                renderNative();
                assert.equal(summary.textContent, table.children[0].children[2].textContent,
                  "use backup date consistently, not this app session's upload completion time");
                assert.equal(note.hidden, true);
                native.backup_history.state = "stale";
                renderNative();
                assert.equal(table.children[0].children[0].textContent, "<img> Test-Sicherung");
                assert.equal(note.hidden, false);
                assert.match(note.textContent, /nicht aktuell/);
                assert.equal(summary.textContent, table.children[0].children[2].textContent + " (Stand nicht aktuell)");
                native.backup_history = { state: "unavailable", files: [] };
                renderNative();
                assert.match(table.children[0].children[0].textContent, /nicht verfügbar/);
                assert.match(summary.textContent, /nicht verfügbar/);
                native.backup_history.state = "ready";
                renderNative();
                assert.match(table.children[0].children[0].textContent, /Noch keine/);
                assert.match(summary.textContent, /Noch keine/);
                native.backup_history.state = "stale";
                renderNative();
                assert.match(table.children[0].children[0].textContent, /nicht aktuell.*keine/);
                assert.match(summary.textContent, /keine.*nicht aktuell/i);
                assert.equal(note.hidden, true);
                native.backup_history.state = "ready";
                native.backup_history.files = [{ name: "Altes Konto", size: 4096, date: "2026-08-11T08:00:00Z" }];
                native.service.connected = false;
                renderNative();
                assert.match(summary.textContent, /nicht verfügbar/, "hide dates if disconnected");
                native.service.connected = true;
                renderNative();
                await vm.runInContext("refreshStatus()", context);
                assert.match(table.children[0].children[0].textContent, /nicht verfügbar/);
                assert.match(summary.textContent, /nicht verfügbar/);
                assert.equal(vm.runInContext("state.snapshot.backup_history.files.length", context), 0);
                assert.equal(note.hidden, true);

                renderNative();
                blockNativeStatus = true;
                const mutation = vm.runInContext(
                  "state.statusFresh = true; state.csrfToken = 'native-token'; mutate(routes.disconnect, {}, 'Getrennt')",
                  context,
                );
                await settle();
                assert.equal(postCalls.length, 1);
                assert.match(table.children[0].children[0].textContent, /nicht verfügbar/);
                assert.match(summary.textContent, /nicht verfügbar/);
                releaseStatus();
                await mutation;
                assert.match(table.children[0].children[0].textContent, /nicht verfügbar/);
                return;
              }

              if (name === "legacy-last-success") {
                const legacy = statusPayload("legacy-token", { connected: true });
                legacy.last_success_at = "2026-08-11T08:00:00Z";
                vm.runInContext(`renderStatus(${JSON.stringify(legacy)});`, context);
                assert.equal(elements.get("#last-success-heading").textContent, "Letzter Erfolg");
                assert.match(elements.get("#last-success").textContent, /2026/);
                return;
              }

              if (name === "login-status") {
                const link = elements.get("#login-link");
                assert.equal(link.attributes.has("href"), true);
                assert.equal(loginTimerDelays.length, 1);
                assert.ok(loginTimerDelays[0] > 0 && loginTimerDelays[0] <= 30000);
                documentListeners.get("visibilitychange")();
                await settle();
                assert.equal(
                  link.attributes.has("href"),
                  true,
                  "same active generation without repeated secret must retain href",
                );
                assert.ok(loginTimerDelays.at(-1) <= 30000);
                documentListeners.get("visibilitychange")();
                await settle();
                assert.equal(link.attributes.has("href"), false);
                return;
              }

              if (name === "login-expired") {
                assert.equal(
                  elements.get("#login-link").attributes.has("href"),
                  false,
                  "zero remaining server lifetime must never expose href",
                );
                return;
              }

              if (name === "login-not-ready") {
                assert.equal(
                  elements.get("#login-link").attributes.has("href"),
                  false,
                  "draining service must never expose an active login href",
                );
                return;
              }

              if (name === "not-ready") {
                for (const selector of [
                  "#connect-button", "#renew-button", "#disconnect-button",
                  "#scan-button", "#restart-button", "#cancel-button", "#retry-button",
                ]) {
                  assert.equal(elements.get(selector).disabled, true, `${selector} must fail closed`);
                }
                assert.equal(postCalls.length, 0);
                return;
              }

              if (name === "readiness-race") {
                const connectButton = elements.get("#connect-button");
                assert.equal(connectButton.disabled, false);
                documentListeners.get("visibilitychange")();
                await settle();
                assert.equal(typeof releaseStatus, "function");
                connectButton.click();
                releaseStatus();
                await settle();
                assert.equal(postCalls.length, 0, "not-ready refresh must cancel queued mutation");
                assert.equal(connectButton.disabled, true);
                return;
              }

              if (name === "retry-target") {
                assert.equal(elements.get("#scanner-status").textContent, "Bereit");
                assert.equal(
                  elements.get("#last-error").textContent,
                  "Letzter Fehler: Netzwerk nicht erreichbar",
                );
                assert.equal(elements.get("#retry-button").disabled, false);
                elements.get("#retry-button").listeners.get("click")();
                await settle();
                assert.equal(JSON.parse(postCalls[0].options.body).sha256, SHA);
                return;
              }

              if (name === "retry-ack") {
                const retryButton = elements.get("#retry-button");
                assert.equal(retryButton.disabled, false);
                retryButton.click();
                await settle();
                assert.equal(postCalls.length, 1);
                assert.equal(retryButton.disabled, true, "accepted retry must await status change");
                retryButton.click();
                await settle();
                assert.equal(postCalls.length, 1, "unchanged retry generation must not duplicate");

                retryAt = "2026-08-11T09:10:00Z";
                documentListeners.get("visibilitychange")();
                await settle();
                assert.equal(retryButton.disabled, false, "new retry generation must be actionable");
                retryButton.click();
                await settle();
                assert.equal(postCalls.length, 2);
                assert.notEqual(
                  postCalls[0].options.headers["Idempotency-Key"],
                  postCalls[1].options.headers["Idempotency-Key"],
                );
                return;
              }

              if (name === "retry-race") {
                const retryButton = elements.get("#retry-button");
                documentListeners.get("visibilitychange")();
                await settle();
                assert.equal(typeof releaseStatus, "function");
                retryButton.click();
                releaseStatus();
                await settle();
                assert.equal(postCalls.length, 0, "changed retry generation must cancel old intent");
                assert.equal(retryButton.disabled, false);

                retryButton.click();
                await settle();
                assert.equal(postCalls.length, 1);
                assert.equal(JSON.parse(postCalls[0].options.body).sha256, NEXT_SHA);
                return;
              }

              if ([
                "retry-malformed-accepted", "retry-empty-accepted",
                "retry-missing-accepted", "retry-false-accepted",
              ].includes(name)) {
                const retryButton = elements.get("#retry-button");
                assert.equal(retryButton.disabled, false);
                retryButton.click();
                await settle();
                assert.equal(postCalls.length, 1);
                assert.deepEqual(
                  JSON.parse(postCalls[0].options.body),
                  { sha256: SHA, retry_revision: 1 },
                );
                assert.equal(
                  retryButton.disabled,
                  true,
                  "server-pending generation must survive malformed accepted response",
                );
                assert.equal(
                  elements.get("#notice").textContent.startsWith("Aktion nicht bestätigt:"),
                  true,
                  "2xx without accepted=true must not be reported as success",
                );
                return;
              }

              elements.get("#connect-button").listeners.get("click")();
              await settle();

              if (name === "fetch-reject" || name === "body-reject") {
                assert.equal(postCalls.length, 2, `${name} must retry exactly once`);
                assert.equal(
                  postCalls[0].options.headers["Idempotency-Key"],
                  postCalls[1].options.headers["Idempotency-Key"],
                );
                assert.equal(postCalls[0].options.headers["X-CSRF-Token"], "token-one");
                assert.equal(postCalls[1].options.headers["X-CSRF-Token"], "token-one");
                return;
              }
              if (name === "malformed" || name === "http-error") {
                assert.equal(postCalls.length, 1, `${name} must not retry`);
                return;
              }
              if (name === "stale") {
                for (const selector of [
                  "#connect-button", "#renew-button", "#disconnect-button",
                  "#scan-button", "#restart-button", "#cancel-button", "#retry-button",
                ]) {
                  assert.equal(elements.get(selector).disabled, true, `${selector} must fail closed`);
                }
                return;
              }
              if (name === "rotation") {
                elements.get("#restart-button").listeners.get("click")();
                await settle();
                assert.equal(postCalls.length, 2);
                assert.notEqual(
                  postCalls[0].options.headers["Idempotency-Key"],
                  postCalls[1].options.headers["Idempotency-Key"],
                );
                assert.equal(postCalls[1].options.headers["X-CSRF-Token"], "token-two");
                return;
              }
              if (name === "login-pagehide") {
                const link = elements.get("#login-link");
                assert.equal(
                  link.attributes.has("href"),
                  false,
                  "status without login URL must clear the mutation handoff",
                );
                windowListeners.get("pagehide")();
                assert.equal(link.attributes.has("href"), false);
              }
            }

            (async () => {
              for (const scenario of [
                "native-status",
                "legacy-last-success",
                "fetch-reject", "body-reject", "malformed", "http-error",
                "stale", "not-ready", "readiness-race", "rotation", "retry-target",
                "retry-ack", "retry-race", "retry-malformed-accepted",
                "retry-empty-accepted", "retry-missing-accepted",
                "retry-false-accepted", "login-pagehide", "login-status",
                "login-expired",
                "login-not-ready",
                "status-poll-window",
                "status-poll-iframe",
                "auth-after-poll-window",
              ]) {
                await runScenario(scenario);
              }
            })().catch((error) => {
              console.error(error.stack || error);
              process.exitCode = 1;
            });
            """
        )
        with tempfile.TemporaryDirectory() as temporary:
            harness_path = Path(temporary) / "status-ui-runtime-test.cjs"
            harness_path.write_text(harness, encoding="utf-8")
            result = subprocess.run(
                [node, str(harness_path), str(app_js)],
                capture_output=True,
                text=True,
                # Nineteen scenarios deliberately use real timers. The old
                # 20s guard was at their normal ~19s runtime, causing flakes.
                timeout=60,
                check=False,
            )

        self.assertEqual(
            result.returncode,
            0,
            f"JavaScript runtime contract failed:\n{result.stdout}\n{result.stderr}",
        )

    def test_native_status_shows_only_confirmed_public_fields_and_limits_rows(self) -> None:
        files = tuple(
            SimpleNamespace(
                name=f"Test-Sicherung {index}", size=4096,
                date=datetime(2026, 8, 11, 8, 0, tzinfo=UTC),
                path="/private/hidden", uid="private-id",
            )
            for index in range(15)
        )
        object.__setattr__(self.snapshot, "native_mode", True)
        object.__setattr__(self.snapshot, "native_history_state", "ready")
        object.__setattr__(self.snapshot, "native_history", files)

        history = self.status().json().get("backup_history")

        self.assertIsNotNone(history)
        self.assertEqual(history["state"], "ready")
        self.assertEqual(len(history["files"]), 14)
        self.assertEqual(history["files"][0], {
            "name": "Test-Sicherung 0", "size": 4096, "date": "2026-08-11T08:00:00Z",
        })

    def test_native_status_hides_cached_history_when_disconnected(self) -> None:
        object.__setattr__(self.snapshot, "native_mode", True)
        object.__setattr__(self.snapshot, "connected", False)
        object.__setattr__(self.snapshot, "native_history_state", "ready")
        object.__setattr__(self.snapshot, "native_history", (
            SimpleNamespace(name="Hidden", size=4096, date=datetime(2026, 8, 11, tzinfo=UTC)),
        ))

        self.assertEqual(self.status().json().get("backup_history"), {
            "state": "unavailable", "files": [],
        })

    def test_status_schema_omits_remote_paths_and_login_secrets(self) -> None:
        payload = self.status().json()

        self.assertEqual(
            payload,
            {
                "csrf_token": "csrf-user-a",
                "service": {
                    "web_ready": True,
                    "connected": True,
                    "scanner_state": "idle",
                    "native_mode": False,
                },
                "upload": {
                    "sha256": "a" * 64,
                    "name": "Home Assistant.tar",
                    "started_at": "2026-08-11T09:00:00Z",
                    "native_operation": None,
                },
                "queue": {
                    "size": 2,
                    "next_retry_at": "2026-08-11T09:05:00Z",
                },
                "last_success_at": "2026-08-11T08:00:00Z",
                "last_error_code": None,
                "retry_sha256": None,
                "retry_revision": None,
                "remote_files": [
                    {
                        "uid": "remote-1",
                        "name": "ha-v1--safe.tar",
                        "size": 4096,
                        "modified_at": "2026-08-11T08:00:00Z",
                    }
                ],
            },
        )
        rendered = json.dumps(payload)
        self.assertNotIn("private-should-not-be-returned", rendered)
        self.assertNotIn("login_url", rendered)

    def test_status_exposes_only_a_valid_retry_target_hash(self) -> None:
        for value, expected in (("b" * 64, "b" * 64), ("unsafe", None)):
            with self.subTest(value=value):
                object.__setattr__(self.snapshot, "retry_sha256", value)
                object.__setattr__(self.snapshot, "retry_revision", 1)

                payload = self.status().json()

                self.assertEqual(payload["retry_sha256"], expected)
                self.assertEqual(payload["retry_revision"], 1 if expected else None)

    def test_post_without_csrf_is_rejected(self) -> None:
        response = self.client.post(
            "/api/worker/restart",
            peer=INGRESS_PEER,
            headers={"X-Remote-User-Id": USER_A, "Origin": ORIGIN},
            body={},
        )

        self.assertEqual(response.status, 403)
        self.assertEqual(response.json(), {"error": {"code": "csrf_rejected"}})
        self.assertTrue(self.commands.empty())

    def test_all_mutations_are_rejected_once_service_is_not_ready(self) -> None:
        token = self.csrf()
        object.__setattr__(self.snapshot, "web_ready", False)

        response = self.client.post(
            "/api/scan",
            headers={
                **self.mutation_headers(csrf=token),
                "Idempotency-Key": "stopping-service-scan",
            },
            body={},
        )

        self.assertEqual(response.status, 409)
        self.assertEqual(response.json(), {"error": {"code": "service_busy"}})
        self.assertTrue(self.commands.empty())

    def test_non_ingress_peer_and_missing_user_are_rejected(self) -> None:
        cases = (
            ("192.0.2.2", self.ingress_headers),
            (INGRESS_PEER, {}),
            (INGRESS_PEER, {"X-Remote-User-Id": "bad user\r\nX: injected"}),
        )
        for peer, headers in cases:
            with self.subTest(peer=peer, headers=headers):
                response = self.client.get("/api/status", peer=peer, headers=headers)
                self.assertEqual(response.status, 403)
                self.assertEqual(
                    response.json(), {"error": {"code": "access_denied"}}
                )

    def test_wrong_or_missing_origin_is_rejected_before_dispatch(self) -> None:
        token = self.csrf()
        for origin in (None, "null", "https://attacker.example", ORIGIN + "/path"):
            with self.subTest(origin=origin):
                headers = {
                    "X-Remote-User-Id": USER_A,
                    "X-CSRF-Token": token,
                }
                if origin is not None:
                    headers["Origin"] = origin
                response = self.client.post(
                    "/api/worker/restart", headers=headers, body={}
                )
                self.assertEqual(response.status, 403)
                self.assertEqual(
                    response.json(), {"error": {"code": "origin_rejected"}}
                )
        self.assertTrue(self.commands.empty())

    def test_csrf_token_cannot_be_reused_by_another_user(self) -> None:
        user_a_token = self.csrf(user=USER_A)
        self.csrf(user=USER_B)

        response = self.client.post(
            "/api/scan",
            headers=self.mutation_headers(user=USER_B, csrf=user_a_token),
            body={},
        )

        self.assertEqual(response.status, 403)
        self.assertEqual(response.json(), {"error": {"code": "csrf_rejected"}})
        self.assertTrue(self.commands.empty())

    def test_expired_csrf_token_is_rejected_and_status_rotates_it(self) -> None:
        old_token = self.csrf()
        self.monotonic += 1_800.0

        rejected = self.client.post(
            "/api/scan",
            headers=self.mutation_headers(csrf=old_token),
            body={},
        )
        replacement = self.csrf()

        self.assertEqual(rejected.status, 403)
        self.assertEqual(replacement, "csrf-user-b")
        self.assertTrue(self.commands.empty())

    def test_get_on_mutation_routes_and_unknown_verbs_have_no_side_effects(self) -> None:
        mutation_paths = (
            "/api/auth/connect",
            "/api/auth/disconnect",
            "/api/auth/renew",
            "/api/scan",
            "/api/upload/cancel",
            "/api/upload/retry",
            "/api/worker/restart",
        )
        for path in mutation_paths:
            with self.subTest(path=path):
                response = self.client.get(path, headers=self.ingress_headers)
                self.assertEqual(response.status, 405)
                self.assertEqual(response.headers["Allow"], "POST")
        trace = self.client.request(
            "TRACE", "/api/status", headers=self.ingress_headers
        )
        self.assertEqual(trace.status, 405)
        self.assertTrue(self.commands.empty())

    def test_oversized_malformed_duplicate_or_non_json_bodies_are_rejected(self) -> None:
        headers = self.mutation_headers()
        cases = (
            (
                b"{" + b" " * 16_384 + b"}",
                {**headers, "Content-Type": "application/json"},
                413,
                "body_too_large",
            ),
            (
                b"{not-json}",
                {**headers, "Content-Type": "application/json"},
                400,
                "invalid_json",
            ),
            (
                b'{"sha256":"' + b"a" * 64 + b'","sha256":"' + b"b" * 64 + b'"}',
                {**headers, "Content-Type": "application/json"},
                400,
                "invalid_json",
            ),
            (
                b"{}",
                {**headers, "Content-Type": "text/plain"},
                415,
                "unsupported_media_type",
            ),
        )
        for body, request_headers, status, code in cases:
            with self.subTest(code=code):
                response = self.client.post(
                    "/api/upload/retry", headers=request_headers, body=body
                )
                self.assertEqual(response.status, status)
                self.assertEqual(response.json(), {"error": {"code": code}})
        self.assertTrue(self.commands.empty())

    def test_excessively_nested_json_is_a_neutral_client_error(self) -> None:
        token = self.csrf()
        body = ("[" * 8_000 + "]" * 8_000).encode("ascii")

        response = self.client.post(
            "/api/scan",
            headers={
                **self.mutation_headers(csrf=token),
                "Content-Type": "application/json",
            },
            body=body,
        )

        self.assertEqual(response.status, 400)
        # Parser depth limits vary; a decoded array is still an invalid body.
        self.assertIn(
            response.json(),
            (
                {"error": {"code": "invalid_json"}},
                {"error": {"code": "invalid_body"}},
            ),
        )
        self.assertTrue(self.commands.empty())
        self.assertEqual(self.csrf(), token)

    def test_json_parser_recursion_error_is_a_neutral_client_error(self) -> None:
        token = self.csrf()

        with patch(
            "proton_backup.web.json.loads",
            side_effect=RecursionError("private parser detail"),
        ):
            response = self.client.post(
                "/api/scan",
                headers={
                    **self.mutation_headers(csrf=token),
                    "Content-Type": "application/json",
                },
                body=b"[]",
            )

        self.assertEqual(response.status, 400)
        self.assertEqual(response.json(), {"error": {"code": "invalid_json"}})
        self.assertTrue(self.commands.empty())
        self.assertEqual(self.csrf(), token)

    def test_post_rejects_unknown_fields_invalid_sha_and_ambiguous_lengths(self) -> None:
        token = self.csrf()
        base = self.mutation_headers(csrf=token)
        cases = (
            ("/api/scan", {"unexpected": True}, base, 400, "invalid_body"),
            ("/api/upload/retry", {"sha256": "A" * 64}, base, 400, "invalid_body"),
            ("/api/upload/retry", {"sha256": "a" * 63}, base, 400, "invalid_body"),
            (
                "/api/upload/retry",
                {"sha256": "a" * 64, "retry_revision": True},
                base,
                400,
                "invalid_body",
            ),
            (
                "/api/upload/retry",
                {"sha256": "a" * 64, "retry_revision": -1},
                base,
                400,
                "invalid_body",
            ),
            (
                "/api/upload/retry",
                {"sha256": "a" * 64, "retry_revision": 9_007_199_254_740_992},
                base,
                400,
                "invalid_body",
            ),
            (
                "/api/scan",
                {},
                {**base, "Content-Length": "2, 2"},
                400,
                "invalid_request",
            ),
            (
                "/api/scan",
                {},
                {**base, "Transfer-Encoding": "chunked"},
                400,
                "invalid_request",
            ),
        )
        for path, body, headers, status, code in cases:
            with self.subTest(path=path, code=code):
                response = self.client.post(path, headers=headers, body=body)
                self.assertEqual(response.status, status)
                self.assertEqual(response.json(), {"error": {"code": code}})
        self.assertTrue(self.commands.empty())

    def test_query_encoded_separator_and_traversal_tricks_are_rejected(self) -> None:
        targets = (
            "/api/status?user=other",
            "/api%2fstatus",
            "/static/%2e%2e/web.py",
            "/static/../web.py",
            "/static%5c..%5cweb.py",
            "//attacker.example/api/status",
        )
        for target in targets:
            with self.subTest(target=target):
                response = self.client.get(target, headers=self.ingress_headers)
                self.assertEqual(response.status, 400)
                self.assertEqual(
                    response.json(), {"error": {"code": "invalid_request"}}
                )

    def test_only_exact_proxy_stripped_routes_are_accepted(self) -> None:
        headers = {
            **self.ingress_headers,
            "X-Ingress-Path": "/api/hassio_ingress/opaque-token",
        }

        stripped = self.client.get("/api/status", headers=headers)
        prefixed = self.client.get(
            "/api/hassio_ingress/opaque-token/api/status", headers=headers
        )
        double = self.client.get(
            "/api/hassio_ingress/opaque-token/api/hassio_ingress/opaque-token/api/status",
            headers=headers,
        )
        encoded = self.client.get(
            "/api%2fhassio_ingress%2fopaque-token%2fapi%2fstatus",
            headers=headers,
        )

        self.assertEqual(stripped.status, 200)
        self.assertEqual(prefixed.status, 404)
        self.assertEqual(double.status, 404)
        self.assertEqual(encoded.status, 400)

    def test_forwarded_headers_never_authorize_an_unconfigured_origin(self) -> None:
        controller = WebController(
            snapshot_provider=lambda: self.snapshot,
            command_queue=Queue(maxsize=1),
            monotonic=lambda: self.monotonic,
            token_factory=lambda: "unconfigured-csrf",
        )
        client = ControllerClient(controller)
        token = client.get("/api/status", headers=self.ingress_headers).json()[
            "csrf_token"
        ]

        response = client.post(
            "/api/scan",
            headers={
                **self.ingress_headers,
                "Origin": "https://attacker.example",
                "X-Forwarded-Host": "attacker.example",
                "X-Forwarded-Proto": "https",
                "X-CSRF-Token": token,
            },
            body={},
        )

        self.assertEqual(response.status, 403)
        self.assertEqual(response.json(), {"error": {"code": "origin_rejected"}})

    def test_deceptive_or_ambiguous_origins_are_rejected(self) -> None:
        token = self.csrf()
        origins = (
            "https://homeassistant.example:443",
            "https://homeassistant.example.",
            "https://user@homeassistant.example",
            "ftp://homeassistant.example",
            "https://homeassіstant.example",
            ORIGIN + "," + ORIGIN,
        )
        for origin in origins:
            with self.subTest(origin=origin):
                response = self.client.post(
                    "/api/scan",
                    headers={
                        **self.ingress_headers,
                        "Origin": origin,
                        "X-CSRF-Token": token,
                    },
                    body={},
                )
                self.assertEqual(response.status, 403)
                self.assertEqual(
                    response.json(), {"error": {"code": "origin_rejected"}}
                )

    def test_all_malformed_origin_forms_fail_closed_as_origin_rejected(self) -> None:
        origins = (
            "https://[::1",
            "https://homeassistant.example:bad",
            "https://homeassistant.example:%34%34%33",
            "https://homeassistant%2eexample",
            " https://homeassistant.example",
            "https://HOMEASSISTANT.example",
            "https://homeassistant.example\t",
            "https://homeassistant.example\r\n",
            "https://homeassistant.example/%zz",
            "https://homeassistant.example\x00",
            ORIGIN + ", " + ORIGIN,
        )
        for origin in origins:
            with self.subTest(origin=repr(origin)):
                controller = WebController(
                    snapshot_provider=lambda: self.snapshot,
                    command_queue=Queue(maxsize=1),
                    token_factory=iter(
                        ("malformed-origin-one", "malformed-origin-two")
                    ).__next__,
                    allowed_origins={ORIGIN},
                )
                client = ControllerClient(controller)
                token = client.get(
                    "/api/status", headers=self.ingress_headers
                ).json()["csrf_token"]
                response = client.post(
                    "/api/scan",
                    headers={
                        **self.ingress_headers,
                        "Origin": origin,
                        "X-CSRF-Token": token,
                    },
                    body={},
                )
                self.assertEqual(response.status, 403)
                self.assertEqual(
                    response.json(), {"error": {"code": "origin_rejected"}}
                )

    def test_percent_and_ipv6_zone_origins_are_never_trusted(self) -> None:
        origins = (
            "https://[::1%zz]",
            "https://[::1%25eth0]",
            "https://[fe80::1%eth0]:8443",
            "https://home%41assistant.example",
            "https://%68omeassistant.example",
        )
        token = self.csrf()
        for origin in origins:
            with self.subTest(origin=origin, boundary="configuration"):
                with self.assertRaises(ValueError):
                    WebController(
                        snapshot_provider=lambda: self.snapshot,
                        command_queue=Queue(maxsize=1),
                        allowed_origins={origin},
                    )
            with self.subTest(origin=origin, boundary="request"):
                response = self.client.post(
                    "/api/scan",
                    headers={
                        **self.ingress_headers,
                        "Origin": origin,
                        "X-CSRF-Token": token,
                    },
                    body={},
                )
                self.assertEqual(response.status, 403)
                self.assertEqual(
                    response.json(), {"error": {"code": "origin_rejected"}}
                )

    def test_deceptive_origins_cannot_be_configured_as_trusted(self) -> None:
        origins = (
            "https://homeassistant.example:443",
            "https://homeassistant.example.",
            "https://user@homeassistant.example",
            "https://xn--80ak6aa92e.example",
        )
        for origin in origins:
            with self.subTest(origin=origin):
                with self.assertRaises(ValueError):
                    WebController(
                        snapshot_provider=lambda: self.snapshot,
                        command_queue=Queue(maxsize=1),
                        allowed_origins={origin},
                    )

    def test_full_live_user_capacity_refuses_new_users_without_evicting_existing(self) -> None:
        commands = Queue(maxsize=200)
        controller = WebController(
            snapshot_provider=lambda: self.snapshot,
            command_queue=commands,
            monotonic=lambda: self.monotonic,
            token_factory=SequentialValues("csrf-bound"),
            allowed_origins={ORIGIN},
        )
        client = ControllerClient(controller)
        user_a = "capacity-user-0000"
        token_a = client.get(
            "/api/status", headers={"X-Remote-User-Id": user_a}
        ).json()["csrf_token"]
        headers_a = {
            "X-Remote-User-Id": user_a,
            "Origin": ORIGIN,
            "X-CSRF-Token": token_a,
            "Idempotency-Key": "capacity-user-a-key",
        }
        accepted_a = client.post("/api/scan", headers=headers_a, body={})
        for index in range(1, 128):
            user = f"capacity-user-{index:04d}"
            token = client.get(
                "/api/status", headers={"X-Remote-User-Id": user}
            ).json()["csrf_token"]
            accepted = client.post(
                "/api/scan",
                headers={
                    "X-Remote-User-Id": user,
                    "Origin": ORIGIN,
                    "X-CSRF-Token": token,
                    "Idempotency-Key": "capacity-stable-key",
                },
                body={},
            )
            self.assertEqual(accepted.status, 202)

        for _attempt in range(10):
            refused = client.get(
                "/api/status", headers={"X-Remote-User-Id": USER_B}
            )
            self.assertEqual(refused.status, 503)
            self.assertEqual(
                refused.json(), {"error": {"code": "service_busy"}}
            )
            self.assertNotIn("csrf_token", refused.json())
        replay_a = client.post("/api/scan", headers=headers_a, body={})
        self.assertEqual(replay_a.json(), accepted_a.json())
        self.assertEqual(commands.qsize(), 128)

        self.monotonic += 1_800.0
        admitted = client.get(
            "/api/status", headers={"X-Remote-User-Id": USER_B}
        )
        self.assertEqual(admitted.status, 200)
        self.assertIn("csrf_token", admitted.json())

    def test_concurrent_new_user_admission_never_exceeds_live_capacity(self) -> None:
        gated = GatedSnapshot(self.snapshot)
        controller = WebController(
            snapshot_provider=gated,
            command_queue=Queue(maxsize=1),
            token_factory=SequentialValues("concurrent-capacity"),
            allowed_origins={ORIGIN},
        )
        client = ControllerClient(controller)
        first_user = "concurrent-user-0000"
        for index in range(127):
            response = client.get(
                "/api/status",
                headers={"X-Remote-User-Id": f"concurrent-user-{index:04d}"},
            )
            self.assertEqual(response.status, 200)
        gated.enabled = True
        responses = []

        def admit(user: str) -> None:
            responses.append(
                client.get("/api/status", headers={"X-Remote-User-Id": user})
            )

        threads = (
            Thread(target=admit, args=("concurrent-new-a",)),
            Thread(target=admit, args=("concurrent-new-b",)),
        )
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(3)
        gated.enabled = False

        self.assertEqual(sorted(response.status for response in responses), [200, 503])
        existing = client.get(
            "/api/status", headers={"X-Remote-User-Id": first_user}
        )
        self.assertEqual(existing.status, 200)

    def test_all_control_routes_enqueue_typed_commands(self) -> None:
        routes = (
            ("/api/auth/connect", ControlAction.CONNECT, {}),
            ("/api/auth/disconnect", ControlAction.DISCONNECT, {}),
            ("/api/auth/renew", ControlAction.RENEW, {}),
            ("/api/scan", ControlAction.SCAN, {}),
            ("/api/upload/cancel", ControlAction.CANCEL_UPLOAD, {}),
            (
                "/api/upload/retry",
                ControlAction.RETRY_UPLOAD,
                {"sha256": "b" * 64, "retry_revision": 1},
            ),
            ("/api/worker/restart", ControlAction.RESTART_WORKER, {}),
        )
        for path, action, body in routes:
            with self.subTest(path=path):
                if action is ControlAction.RETRY_UPLOAD:
                    object.__setattr__(self.snapshot, "retry_sha256", "b" * 64)
                    object.__setattr__(self.snapshot, "retry_revision", 1)
                command_queue = Queue(maxsize=1)
                controller = WebController(
                    snapshot_provider=lambda: self.snapshot,
                    command_queue=command_queue,
                    monotonic=lambda: self.monotonic,
                    token_factory=iter(("route-csrf-one", "route-csrf-two")).__next__,
                    allowed_origins={ORIGIN},
                )
                client = ControllerClient(controller)
                client.get("/api/status", headers=self.ingress_headers)
                response = client.post(
                    path,
                    headers={
                        **self.ingress_headers,
                        "Origin": ORIGIN,
                        "X-CSRF-Token": "route-csrf-one",
                        "Idempotency-Key": "request-123",
                    },
                    body=body,
                )
                command = command_queue.get_nowait()
                self.assertEqual(response.status, 202)
                self.assertEqual(response.json()["accepted"], True)
                self.assertEqual(response.json()["csrf_token"], "route-csrf-two")
                self.assertEqual(command.action, action)
                self.assertEqual(command.user_id, USER_A)
                self.assertEqual(command.sha256, body.get("sha256"))
                self.assertEqual(
                    command.retry_revision, body.get("retry_revision")
                )

    def test_retry_generation_is_server_deduplicated_across_tabs_and_stale_status(self) -> None:
        retry_sha256 = "b" * 64
        object.__setattr__(self.snapshot, "active_sha256", None)
        object.__setattr__(self.snapshot, "active_name", None)
        object.__setattr__(self.snapshot, "active_started_at", None)
        object.__setattr__(self.snapshot, "retry_sha256", retry_sha256)
        object.__setattr__(self.snapshot, "retry_revision", 1)
        commands = Queue(maxsize=3)
        tokens = SequentialValues("csrf-retry")
        command_ids = SequentialCommandIds()
        controller = WebController(
            snapshot_provider=lambda: self.snapshot,
            command_queue=commands,
            monotonic=lambda: self.monotonic,
            token_factory=tokens,
            command_id_factory=command_ids,
            allowed_origins={ORIGIN},
        )
        first_tab = ControllerClient(controller)
        second_tab = ControllerClient(controller)
        original_token = first_tab.get(
            "/api/status", headers=self.ingress_headers
        ).json()["csrf_token"]
        first_headers = {
            **self.mutation_headers(csrf=original_token),
            "Idempotency-Key": "retry-generation-one",
        }

        accepted = first_tab.post(
            "/api/upload/retry",
            headers=first_headers,
            body={"sha256": retry_sha256, "retry_revision": 1},
        )

        self.assertEqual(accepted.status, 202)
        self.assertEqual(commands.qsize(), 1)
        self.assertEqual(tokens.value, 2)
        self.assertEqual(command_ids.value, 1)
        snapshot_provider = controller._snapshot_provider
        controller._snapshot_provider = lambda: (_ for _ in ()).throw(
            RuntimeError("cached replay must not sample status")
        )
        replay = first_tab.post(
            "/api/upload/retry",
            headers=first_headers,
            body={"sha256": retry_sha256, "retry_revision": 1},
        )
        self.assertEqual(replay.json(), accepted.json())
        controller._snapshot_provider = snapshot_provider

        pending_status = second_tab.get(
            "/api/status", headers=self.ingress_headers
        ).json()
        self.assertIsNone(pending_status["retry_sha256"])
        self.assertIsNone(pending_status["retry_revision"])
        duplicate = second_tab.post(
            "/api/upload/retry",
            headers={
                **self.mutation_headers(csrf=accepted.json()["csrf_token"]),
                "Idempotency-Key": "retry-generation-duplicate",
            },
            body={"sha256": retry_sha256, "retry_revision": 1},
        )
        self.assertEqual(duplicate.status, 409)
        self.assertEqual(duplicate.json(), {"error": {"code": "service_busy"}})
        self.assertEqual(commands.qsize(), 1)
        self.assertEqual(tokens.value, 2)
        self.assertEqual(command_ids.value, 1)

        object.__setattr__(
            self.snapshot,
            "next_retry_at",
            datetime(2026, 8, 11, 9, 10, tzinfo=UTC),
        )
        object.__setattr__(self.snapshot, "retry_revision", 2)
        next_status = second_tab.get(
            "/api/status", headers=self.ingress_headers
        ).json()
        self.assertEqual(next_status["retry_sha256"], retry_sha256)
        self.assertEqual(next_status["retry_revision"], 2)
        next_retry = second_tab.post(
            "/api/upload/retry",
            headers={
                **self.mutation_headers(csrf=accepted.json()["csrf_token"]),
                "Idempotency-Key": "retry-generation-two",
            },
            body={"sha256": retry_sha256, "retry_revision": 2},
        )
        self.assertEqual(next_retry.status, 202)
        self.assertEqual(commands.qsize(), 2)
        self.assertEqual(tokens.value, 3)
        self.assertEqual(command_ids.value, 2)

        object.__setattr__(self.snapshot, "retry_revision", 1)
        stale_status = second_tab.get(
            "/api/status", headers=self.ingress_headers
        ).json()
        self.assertIsNone(stale_status["retry_sha256"])
        self.assertIsNone(stale_status["retry_revision"])

    def test_concurrent_retry_generation_admission_does_not_hold_snapshot_lock(self) -> None:
        retry_sha256 = "b" * 64
        snapshot = ServiceSnapshot(
            web_ready=True,
            connected=True,
            scanner_state="idle",
            active_sha256=None,
            active_name=None,
            active_started_at=None,
            queue_size=1,
            next_retry_at=datetime(2026, 8, 11, 9, 5, tzinfo=UTC),
            last_success_at=None,
            last_error_code="network_unavailable",
            remote_files=(),
            retry_sha256=retry_sha256,
            retry_revision=1,
        )
        gated = GatedSnapshot(snapshot)
        commands = Queue(maxsize=2)
        tokens = SequentialValues("csrf-concurrent-retry")
        command_ids = SequentialCommandIds()
        controller = WebController(
            snapshot_provider=gated,
            command_queue=commands,
            token_factory=tokens,
            command_id_factory=command_ids,
            allowed_origins={ORIGIN},
        )
        client = ControllerClient(controller)
        token_a = client.get(
            "/api/status", headers={"X-Remote-User-Id": USER_A}
        ).json()["csrf_token"]
        token_b = client.get(
            "/api/status", headers={"X-Remote-User-Id": USER_B}
        ).json()["csrf_token"]
        responses = []

        def submit(user: str, token: str, key: str) -> None:
            responses.append(
                client.post(
                    "/api/upload/retry",
                    headers={
                        "X-Remote-User-Id": user,
                        "Origin": ORIGIN,
                        "X-CSRF-Token": token,
                        "Idempotency-Key": key,
                    },
                    body={"sha256": retry_sha256, "retry_revision": 1},
                )
            )

        gated.enabled = True
        threads = (
            Thread(target=submit, args=(USER_A, token_a, "concurrent-retry-a")),
            Thread(target=submit, args=(USER_B, token_b, "concurrent-retry-b")),
        )
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(3)

        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(sorted(response.status for response in responses), [202, 409])
        self.assertEqual(commands.qsize(), 1)
        self.assertEqual(command_ids.value, 1)
        self.assertEqual(tokens.value, 3)

    def test_invalid_higher_retry_snapshot_cannot_poison_revision_order(self) -> None:
        retry_sha256 = "b" * 64
        object.__setattr__(self.snapshot, "active_sha256", None)
        object.__setattr__(self.snapshot, "retry_sha256", "NOT-A-SHA")
        object.__setattr__(self.snapshot, "retry_revision", 2)
        controller = WebController(
            snapshot_provider=lambda: self.snapshot,
            command_queue=Queue(maxsize=2),
            token_factory=SequentialValues("csrf-invalid-snapshot"),
            allowed_origins={ORIGIN},
        )
        client = ControllerClient(controller)
        invalid = client.get("/api/status", headers=self.ingress_headers).json()
        self.assertIsNone(invalid["retry_sha256"])
        self.assertIsNone(invalid["retry_revision"])

        object.__setattr__(self.snapshot, "retry_sha256", retry_sha256)
        object.__setattr__(self.snapshot, "retry_revision", 1)
        authoritative = client.get(
            "/api/status", headers=self.ingress_headers
        ).json()
        self.assertEqual(authoritative["retry_sha256"], retry_sha256)
        self.assertEqual(authoritative["retry_revision"], 1)

    def test_controller_restart_can_readmit_unmutated_retry_generation(self) -> None:
        retry_sha256 = "b" * 64
        object.__setattr__(self.snapshot, "active_sha256", None)
        object.__setattr__(self.snapshot, "retry_sha256", retry_sha256)
        object.__setattr__(self.snapshot, "retry_revision", 1)

        for suffix in ("before-restart", "after-restart"):
            commands = Queue(maxsize=1)
            controller = WebController(
                snapshot_provider=lambda: self.snapshot,
                command_queue=commands,
                token_factory=SequentialValues(f"csrf-{suffix}"),
                allowed_origins={ORIGIN},
            )
            client = ControllerClient(controller)
            token = client.get(
                "/api/status", headers=self.ingress_headers
            ).json()["csrf_token"]
            accepted = client.post(
                "/api/upload/retry",
                headers={
                    **self.mutation_headers(csrf=token),
                    "Idempotency-Key": f"retry-{suffix}",
                },
                body={"sha256": retry_sha256, "retry_revision": 1},
            )

            self.assertEqual(accepted.status, 202)
            self.assertEqual(commands.qsize(), 1)

    def test_queue_backpressure_and_idempotent_replay_are_bounded(self) -> None:
        token = self.csrf()
        headers = {
            **self.mutation_headers(csrf=token),
            "Idempotency-Key": "same-request",
        }
        first = self.client.post("/api/scan", headers=headers, body={})
        replay = self.client.post("/api/scan", headers=headers, body={})
        conflict = self.client.post("/api/worker/restart", headers=headers, body={})
        fills = self.client.post(
            "/api/worker/restart",
            headers={
                **headers,
                "X-CSRF-Token": first.json()["csrf_token"],
                "Idempotency-Key": "fills-queue",
            },
            body={},
        )
        busy = self.client.post(
            "/api/upload/cancel",
            headers={
                **headers,
                "X-CSRF-Token": fills.json()["csrf_token"],
                "Idempotency-Key": "over-capacity",
            },
            body={},
        )

        self.assertEqual(first.status, 202)
        self.assertEqual(replay.json(), first.json())
        self.assertEqual(self.commands.qsize(), 2)
        self.assertEqual(conflict.status, 409)
        self.assertEqual(
            conflict.json(), {"error": {"code": "idempotency_conflict"}}
        )
        self.assertEqual(busy.status, 503)
        self.assertEqual(busy.json(), {"error": {"code": "service_busy"}})

    def test_older_idempotency_key_rejects_the_current_token_from_a_later_action(
        self,
    ) -> None:
        token = self.csrf()
        first = self.client.post(
            "/api/scan",
            headers={
                **self.mutation_headers(csrf=token),
                "Idempotency-Key": "first-request-key",
            },
            body={},
        )
        second = self.client.post(
            "/api/worker/restart",
            headers={
                **self.mutation_headers(csrf=first.json()["csrf_token"]),
                "Idempotency-Key": "second-request-key",
            },
            body={},
        )

        replay = self.client.post(
            "/api/scan",
            headers={
                **self.mutation_headers(csrf=second.json()["csrf_token"]),
                "Idempotency-Key": "first-request-key",
            },
            body={},
        )

        self.assertEqual(replay.status, 403)
        self.assertEqual(replay.json(), {"error": {"code": "csrf_rejected"}})
        self.assertEqual(self.commands.qsize(), 2)

    def test_live_cached_replay_just_before_ttl_skips_factories(self) -> None:
        factories = FailAfterAcceptedFactories()
        commands = Queue(maxsize=2)
        controller = WebController(
            snapshot_provider=lambda: self.snapshot,
            command_queue=commands,
            monotonic=lambda: self.monotonic,
            token_factory=factories.token,
            command_id_factory=factories.command_id,
            allowed_origins={ORIGIN},
        )
        client = ControllerClient(controller)
        token = client.get("/api/status", headers=self.ingress_headers).json()[
            "csrf_token"
        ]
        headers = {
            **self.ingress_headers,
            "Origin": ORIGIN,
            "X-CSRF-Token": token,
            "Idempotency-Key": "factory-free-replay",
        }
        accepted = client.post("/api/scan", headers=headers, body={})
        self.monotonic += 1_799.999

        replay = client.post("/api/scan", headers=headers, body={})

        self.assertEqual(replay.status, 202)
        self.assertEqual(replay.json(), accepted.json())
        self.assertNotIn(token, repr(controller._idempotency))
        self.assertEqual(factories.command_id_calls, 1)
        self.assertEqual(factories.token_calls, 2)
        self.assertEqual(commands.qsize(), 1)

    def test_cached_replay_at_or_after_ttl_is_swept_without_factory_or_queue(
        self,
    ) -> None:
        for elapsed in (1_800.0, 1_800.001):
            with self.subTest(elapsed=elapsed):
                now = [1_000.0]
                factories = FailAfterAcceptedFactories()
                commands = Queue(maxsize=2)
                controller = WebController(
                    snapshot_provider=lambda: self.snapshot,
                    command_queue=commands,
                    monotonic=lambda: now[0],
                    token_factory=factories.token,
                    command_id_factory=factories.command_id,
                    allowed_origins={ORIGIN},
                )
                client = ControllerClient(controller)
                token = client.get(
                    "/api/status", headers=self.ingress_headers
                ).json()["csrf_token"]
                headers = {
                    **self.ingress_headers,
                    "Origin": ORIGIN,
                    "X-CSRF-Token": token,
                    "Idempotency-Key": "expired-cached-replay",
                }
                self.assertEqual(
                    client.post("/api/scan", headers=headers, body={}).status,
                    202,
                )
                now[0] += elapsed

                replay = client.post("/api/scan", headers=headers, body={})

                self.assertEqual(replay.status, 403)
                self.assertEqual(
                    replay.json(), {"error": {"code": "csrf_rejected"}}
                )
                self.assertEqual(factories.command_id_calls, 1)
                self.assertEqual(factories.token_calls, 2)
                self.assertEqual(commands.qsize(), 1)

    def test_cached_replay_with_wrong_csrf_is_rejected_without_factory_or_queue(
        self,
    ) -> None:
        factories = FailAfterAcceptedFactories()
        commands = Queue(maxsize=2)
        controller = WebController(
            snapshot_provider=lambda: self.snapshot,
            command_queue=commands,
            monotonic=lambda: self.monotonic,
            token_factory=factories.token,
            command_id_factory=factories.command_id,
            allowed_origins={ORIGIN},
        )
        client = ControllerClient(controller)
        token = client.get("/api/status", headers=self.ingress_headers).json()[
            "csrf_token"
        ]
        headers = {
            **self.ingress_headers,
            "Origin": ORIGIN,
            "X-CSRF-Token": token,
            "Idempotency-Key": "wrong-token-replay",
        }
        self.assertEqual(client.post("/api/scan", headers=headers, body={}).status, 202)

        replay = client.post(
            "/api/scan",
            headers={**headers, "X-CSRF-Token": "not-the-original-token"},
            body={},
        )

        self.assertEqual(replay.status, 403)
        self.assertEqual(replay.json(), {"error": {"code": "csrf_rejected"}})
        self.assertEqual(factories.command_id_calls, 1)
        self.assertEqual(factories.token_calls, 2)
        self.assertEqual(commands.qsize(), 1)

    def test_idempotency_conflict_returns_before_factories_are_called(self) -> None:
        factories = FailAfterAcceptedFactories()
        controller = WebController(
            snapshot_provider=lambda: self.snapshot,
            command_queue=Queue(maxsize=2),
            monotonic=lambda: self.monotonic,
            token_factory=factories.token,
            command_id_factory=factories.command_id,
            allowed_origins={ORIGIN},
        )
        client = ControllerClient(controller)
        token = client.get("/api/status", headers=self.ingress_headers).json()[
            "csrf_token"
        ]
        headers = {
            **self.ingress_headers,
            "Origin": ORIGIN,
            "X-CSRF-Token": token,
            "Idempotency-Key": "factory-free-conflict",
        }
        accepted = client.post("/api/scan", headers=headers, body={})
        self.assertEqual(accepted.status, 202)

        for supplied_token in (token, accepted.json()["csrf_token"]):
            with self.subTest(supplied_token=supplied_token):
                conflict = client.post(
                    "/api/worker/restart",
                    headers={**headers, "X-CSRF-Token": supplied_token},
                    body={},
                )
                self.assertEqual(conflict.status, 409)
                self.assertEqual(
                    conflict.json(), {"error": {"code": "idempotency_conflict"}}
                )
        self.assertEqual(factories.command_id_calls, 1)
        self.assertEqual(factories.token_calls, 2)

    def test_expired_original_token_cannot_authorize_idempotency_conflict(
        self,
    ) -> None:
        factories = FailAfterAcceptedFactories()
        commands = Queue(maxsize=2)
        controller = WebController(
            snapshot_provider=lambda: self.snapshot,
            command_queue=commands,
            monotonic=lambda: self.monotonic,
            token_factory=factories.token,
            command_id_factory=factories.command_id,
            allowed_origins={ORIGIN},
        )
        client = ControllerClient(controller)
        token = client.get("/api/status", headers=self.ingress_headers).json()[
            "csrf_token"
        ]
        headers = {
            **self.ingress_headers,
            "Origin": ORIGIN,
            "X-CSRF-Token": token,
            "Idempotency-Key": "expired-conflict",
        }
        self.assertEqual(client.post("/api/scan", headers=headers, body={}).status, 202)
        self.monotonic += 1_800.0

        conflict = client.post("/api/worker/restart", headers=headers, body={})

        self.assertEqual(conflict.status, 403)
        self.assertEqual(conflict.json(), {"error": {"code": "csrf_rejected"}})
        self.assertEqual(factories.command_id_calls, 1)
        self.assertEqual(factories.token_calls, 2)
        self.assertEqual(commands.qsize(), 1)

    def test_new_intent_generates_factories_after_csrf_validation(self) -> None:
        factories = FailAfterAcceptedFactories()
        commands = Queue(maxsize=1)
        controller = WebController(
            snapshot_provider=lambda: self.snapshot,
            command_queue=commands,
            monotonic=lambda: self.monotonic,
            token_factory=factories.token,
            command_id_factory=factories.command_id,
            allowed_origins={ORIGIN},
        )
        client = ControllerClient(controller)
        token = client.get("/api/status", headers=self.ingress_headers).json()[
            "csrf_token"
        ]

        accepted = client.post(
            "/api/scan",
            headers={
                **self.ingress_headers,
                "Origin": ORIGIN,
                "X-CSRF-Token": token,
                "Idempotency-Key": "new-intent-normal",
            },
            body={},
        )

        self.assertEqual(accepted.status, 202)
        self.assertEqual(accepted.json()["command_id"], "1" * 32)
        self.assertEqual(accepted.json()["csrf_token"], "csrf-after-accept")
        self.assertEqual(factories.command_id_calls, 1)
        self.assertEqual(factories.token_calls, 2)
        self.assertEqual(commands.qsize(), 1)

    def test_csrf_expiry_is_sampled_after_waiting_for_state_lock(self) -> None:
        clock = BlockingClock(1_000.0)
        commands = Queue(maxsize=1)
        controller = WebController(
            snapshot_provider=lambda: self.snapshot,
            command_queue=commands,
            monotonic=clock,
            token_factory=SequentialValues("locking-csrf"),
            allowed_origins={ORIGIN},
        )
        client = ControllerClient(controller)
        token = client.get("/api/status", headers=self.ingress_headers).json()[
            "csrf_token"
        ]
        responses = []

        controller._state_lock.acquire()
        clock.block = True
        thread = Thread(
            target=lambda: responses.append(
                client.post(
                    "/api/scan",
                    headers={
                        **self.ingress_headers,
                        "Origin": ORIGIN,
                        "X-CSRF-Token": token,
                        "Idempotency-Key": "expires-behind-lock",
                    },
                    body={},
                )
            )
        )
        try:
            thread.start()
            clock.called.wait(timeout=1)
            clock.value = 2_800.0
            clock.release.set()
        finally:
            controller._state_lock.release()
        thread.join(3)

        self.assertFalse(thread.is_alive())
        self.assertEqual(len(responses), 1)
        self.assertEqual(responses[0].status, 403)
        self.assertEqual(
            responses[0].json(), {"error": {"code": "csrf_rejected"}}
        )
        self.assertTrue(commands.empty())

    def test_simultaneous_idempotent_replay_enqueues_only_one_command(self) -> None:
        commands = Queue(maxsize=2)
        controller = WebController(
            snapshot_provider=lambda: self.snapshot,
            command_queue=commands,
            monotonic=lambda: self.monotonic,
            token_factory=iter(
                ("concurrent-csrf-one", "concurrent-csrf-two")
            ).__next__,
            command_id_factory=SequentialCommandIds(),
            allowed_origins={ORIGIN},
        )
        client = ControllerClient(controller)
        client.get("/api/status", headers=self.ingress_headers)
        headers = {
            **self.ingress_headers,
            "Origin": ORIGIN,
            "X-CSRF-Token": "concurrent-csrf-one",
            "Idempotency-Key": "concurrent-request",
        }
        responses = []
        start = Barrier(2)

        def submit() -> None:
            start.wait(timeout=2)
            responses.append(client.post("/api/scan", headers=headers, body={}))

        threads = (Thread(target=submit), Thread(target=submit))
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(3)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual([response.status for response in responses], [202, 202])
        self.assertEqual(responses[0].json(), responses[1].json())
        self.assertEqual(commands.qsize(), 1)

    def test_one_user_flood_cannot_evict_another_users_idempotency_key(self) -> None:
        commands = Queue(maxsize=300)
        tokens = SequentialValues("csrf")
        controller = WebController(
            snapshot_provider=lambda: self.snapshot,
            command_queue=commands,
            monotonic=lambda: self.monotonic,
            token_factory=tokens,
            allowed_origins={ORIGIN},
        )
        client = ControllerClient(controller)
        token_a = client.get(
            "/api/status", headers={"X-Remote-User-Id": USER_A}
        ).json()["csrf_token"]
        headers_a = {
            "X-Remote-User-Id": USER_A,
            "Origin": ORIGIN,
            "X-CSRF-Token": token_a,
            "Idempotency-Key": "user-a-stable",
        }
        first = client.post("/api/scan", headers=headers_a, body={})
        token_b = client.get(
            "/api/status", headers={"X-Remote-User-Id": USER_B}
        ).json()["csrf_token"]
        for index in range(256):
            response = client.post(
                "/api/scan",
                headers={
                    "X-Remote-User-Id": USER_B,
                    "Origin": ORIGIN,
                    "X-CSRF-Token": token_b,
                    "Idempotency-Key": f"user-b-{index:08d}",
                },
                body={},
            )
            self.assertEqual(response.status, 202)
            self.assertIn("csrf_token", response.json())
            token_b = response.json()["csrf_token"]

        replay = client.post("/api/scan", headers=headers_a, body={})

        self.assertEqual(replay.json(), first.json())
        self.assertEqual(commands.qsize(), 257)

    def test_idempotency_per_user_lru_and_ttl_are_observable(self) -> None:
        commands = Queue(maxsize=900)
        tokens = SequentialValues("bounded-csrf")
        controller = WebController(
            snapshot_provider=lambda: self.snapshot,
            command_queue=commands,
            monotonic=lambda: self.monotonic,
            token_factory=tokens,
            allowed_origins={ORIGIN},
        )
        client = ControllerClient(controller)
        current = client.get("/api/status", headers=self.ingress_headers).json()[
            "csrf_token"
        ]
        first_headers = {
            **self.ingress_headers,
            "Origin": ORIGIN,
            "X-CSRF-Token": current,
            "Idempotency-Key": "evicted-key-0000",
        }
        first = client.post("/api/scan", headers=first_headers, body={})
        self.assertIn("csrf_token", first.json())
        current = first.json()["csrf_token"]
        for index in range(1, 257):
            response = client.post(
                "/api/scan",
                headers={
                    **self.ingress_headers,
                    "Origin": ORIGIN,
                    "X-CSRF-Token": current,
                    "Idempotency-Key": f"evicted-key-{index:04d}",
                },
                body={},
            )
            current = response.json()["csrf_token"]
        evicted_replay = client.post("/api/scan", headers=first_headers, body={})
        self.assertEqual(evicted_replay.status, 403)

        self.monotonic += 1_800.0
        refreshed = client.get("/api/status", headers=self.ingress_headers).json()[
            "csrf_token"
        ]
        after_ttl = client.post(
            "/api/scan",
            headers={
                **first_headers,
                "X-CSRF-Token": refreshed,
            },
            body={},
        )
        self.assertEqual(after_ttl.status, 202)

    def test_csrf_is_consumed_once_but_failures_do_not_consume_it(self) -> None:
        commands = Queue(maxsize=1)
        tokens = SequentialValues("one-time-csrf")
        controller = WebController(
            snapshot_provider=lambda: self.snapshot,
            command_queue=commands,
            monotonic=lambda: self.monotonic,
            token_factory=tokens,
            command_id_factory=SequentialCommandIds(),
            allowed_origins={ORIGIN},
        )
        client = ControllerClient(controller)
        token = client.get("/api/status", headers=self.ingress_headers).json()[
            "csrf_token"
        ]
        responses = []
        start = Barrier(2)

        def submit(key: str) -> None:
            start.wait(timeout=2)
            responses.append(
                client.post(
                    "/api/scan",
                    headers={
                        **self.ingress_headers,
                        "Origin": ORIGIN,
                        "X-CSRF-Token": token,
                        "Idempotency-Key": key,
                    },
                    body={},
                )
            )

        threads = (
            Thread(target=submit, args=("csrf-race-one",)),
            Thread(target=submit, args=("csrf-race-two",)),
        )
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(3)
        self.assertEqual(sorted(response.status for response in responses), [202, 403])
        accepted = next(response for response in responses if response.status == 202)
        next_token = accepted.json()["csrf_token"]
        self.assertNotEqual(next_token, token)
        self.assertEqual(commands.qsize(), 1)

        commands.get_nowait()
        invalid = client.post(
            "/api/upload/retry",
            headers={
                **self.ingress_headers,
                "Origin": ORIGIN,
                "X-CSRF-Token": next_token,
                "Idempotency-Key": "failure-policy-key",
            },
            body={"sha256": "invalid"},
        )
        self.assertEqual(invalid.status, 400)
        commands.put_nowait(ControlCommand("f" * 32, ControlAction.SCAN, USER_A))
        full = client.post(
            "/api/scan",
            headers={
                **self.ingress_headers,
                "Origin": ORIGIN,
                "X-CSRF-Token": next_token,
                "Idempotency-Key": "failure-policy-key",
            },
            body={},
        )
        self.assertEqual(full.status, 503)
        commands.get_nowait()
        accepted_after_failures = client.post(
            "/api/scan",
            headers={
                **self.ingress_headers,
                "Origin": ORIGIN,
                "X-CSRF-Token": next_token,
                "Idempotency-Key": "failure-policy-key",
            },
            body={},
        )
        self.assertEqual(accepted_after_failures.status, 202)

    def test_token_factory_failure_occurs_before_enqueue_and_preserves_old_token(self) -> None:
        commands = Queue(maxsize=1)
        controller = WebController(
            snapshot_provider=lambda: self.snapshot,
            command_queue=commands,
            token_factory=FailingRotationTokens(),
            allowed_origins={ORIGIN},
        )
        client = ControllerClient(controller)
        token = client.get("/api/status", headers=self.ingress_headers).json()[
            "csrf_token"
        ]
        headers = {
            **self.ingress_headers,
            "Origin": ORIGIN,
            "X-CSRF-Token": token,
            "Idempotency-Key": "token-failure-key",
        }

        failed = client.post("/api/scan", headers=headers, body={})
        retry = client.post("/api/scan", headers=headers, body={})

        self.assertEqual(failed.status, 500)
        self.assertEqual(failed.json(), {"error": {"code": "internal_error"}})
        self.assertEqual(retry.status, 202)
        self.assertEqual(commands.qsize(), 1)

    def test_diagnostics_are_last_100_bounded_and_redacted(self) -> None:
        for index in range(105):
            self.diagnostics.append(
                timestamp=datetime(2026, 8, 11, 9, 0, tzinfo=UTC),
                code="network_unavailable",
                message=f"event-{index} password=super-secret https://proton.me/auth?token=x",
                attempt=index,
                backup_name="Home Assistant.tar",
            )

        response = self.client.get(
            "/api/diagnostics", headers=self.ingress_headers
        )
        payload = response.json()

        self.assertEqual(response.status, 200)
        self.assertEqual(len(payload["events"]), 100)
        self.assertIn("event-5", payload["events"][0]["message"])
        rendered = json.dumps(payload)
        self.assertNotIn("super-secret", rendered)
        self.assertNotIn("token=x", rendered)

    def test_snapshot_exception_returns_neutral_error_with_security_headers(self) -> None:
        def explode():
            raise RuntimeError("password=private-secret https://proton.me/auth?token=x")

        controller = WebController(
            snapshot_provider=explode,
            command_queue=Queue(maxsize=1),
            token_factory=lambda: "unused",
        )
        response = ControllerClient(controller).get(
            "/api/status", headers=self.ingress_headers
        )

        self.assertEqual(response.status, 500)
        self.assertEqual(response.json(), {"error": {"code": "internal_error"}})
        self.assertNotIn("private-secret", response.text)
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_http_parser_errors_use_neutral_json_and_security_headers(self) -> None:
        handler = object.__new__(IngressRequestHandler)
        handler.requestline = "malformed password=private-secret"
        handler.request_version = "HTTP/1.1"
        handler.command = "BROKEN"
        handler.close_connection = False
        handler.wfile = BytesIO()

        handler.send_error(400, "password=private-secret")

        wire = handler.wfile.getvalue()
        headers, body = wire.split(b"\r\n\r\n", 1)
        self.assertIn(b"Cache-Control: no-store", headers)
        self.assertIn(b"Content-Type: application/json; charset=utf-8", headers)
        self.assertEqual(
            json.loads(body), {"error": {"code": "invalid_request"}}
        )
        self.assertNotIn(b"private-secret", wire)
        self.assertTrue(handler.close_connection)


class IngressHttpBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.commands = Queue(maxsize=10)
        self.tokens = SequentialValues("live-csrf")
        self.snapshot = ServiceSnapshot(
            web_ready=True,
            connected=False,
            scanner_state="idle",
            active_sha256=None,
            active_name=None,
            active_started_at=None,
            queue_size=0,
            next_retry_at=None,
            last_success_at=None,
            last_error_code=None,
            remote_files=(),
        )
        controller = WebController(
            snapshot_provider=lambda: self.snapshot,
            command_queue=self.commands,
            token_factory=self.tokens,
            allowed_ingress_peers=frozenset({"127.0.0.1"}),
            allowed_origins={ORIGIN},
        )
        self.live = LoopbackIngress(controller)
        self.addCleanup(self.live.close)
        status = self.live.request(
            self.raw_request("GET", "/api/status", (("X-Remote-User-Id", USER_A),))
        )
        self.assertEqual(status.status, 200)
        self.csrf = status.json()["csrf_token"]

    @staticmethod
    def raw_request(
        method: str,
        target: str,
        headers: tuple[tuple[str, str], ...] = (),
        body: bytes = b"",
    ) -> bytes:
        lines = [f"{method} {target} HTTP/1.1", "Host: ingress.local"]
        lines.extend(f"{name}: {value}" for name, value in headers)
        return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body

    def mutation_headers(self) -> tuple[tuple[str, str], ...]:
        return (
            ("X-Remote-User-Id", USER_A),
            ("Origin", ORIGIN),
            ("X-CSRF-Token", self.csrf),
            ("Content-Type", "application/json"),
        )

    def assert_neutral_error(
        self, response: RawHttpResponse, status: int, code: str
    ) -> None:
        self.assertEqual(response.status, status)
        self.assertEqual(response.json(), {"error": {"code": code}})
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])
        self.assertEqual(
            response.headers["Content-Type"], "application/json; charset=utf-8"
        )

    def test_real_parser_rejects_duplicate_length_and_length_with_transfer_encoding(self) -> None:
        duplicate_length = self.live.request(
            self.raw_request(
                "POST",
                "/api/scan",
                self.mutation_headers()
                + (("Content-Length", "2"), ("Content-Length", "2")),
                b"{}",
            )
        )
        length_and_transfer = self.live.request(
            self.raw_request(
                "POST",
                "/api/scan",
                self.mutation_headers()
                + (("Content-Length", "2"), ("Transfer-Encoding", "chunked")),
                b"{}",
            )
        )

        self.assert_neutral_error(duplicate_length, 400, "invalid_request")
        self.assert_neutral_error(length_and_transfer, 400, "invalid_request")
        self.assertTrue(self.commands.empty())

    def test_real_parser_rejects_duplicate_security_headers(self) -> None:
        cases = (
            (("Origin", ORIGIN), 403, "origin_rejected"),
            (("X-CSRF-Token", self.csrf), 403, "csrf_rejected"),
            (("Idempotency-Key", "duplicate-key"), 400, "invalid_request"),
        )
        for duplicate, status, code in cases:
            with self.subTest(header=duplicate[0]):
                base = self.mutation_headers() + (
                    ("Idempotency-Key", "duplicate-key"),
                    ("Content-Length", "2"),
                )
                response = self.live.request(
                    self.raw_request(
                        "POST", "/api/scan", base + (duplicate,), b"{}"
                    )
                )
                self.assert_neutral_error(response, status, code)
        self.assertTrue(self.commands.empty())

    def test_real_parser_rejects_malformed_target_and_short_body(self) -> None:
        malformed = self.live.request(
            self.raw_request(
                "GET",
                "/api/%zz/status",
                (("X-Remote-User-Id", USER_A),),
            )
        )
        short = self.live.request(
            self.raw_request(
                "POST",
                "/api/scan",
                self.mutation_headers() + (("Content-Length", "4"),),
                b"{}",
            )
        )

        self.assert_neutral_error(malformed, 400, "invalid_request")
        self.assert_neutral_error(short, 400, "invalid_request")

    def test_real_server_uses_socket_peer_not_forwarded_identity(self) -> None:
        controller = WebController(
            snapshot_provider=lambda: self.snapshot,
            command_queue=Queue(maxsize=1),
            token_factory=SequentialValues("peer-csrf"),
        )
        disallowed = LoopbackIngress(controller)
        self.addCleanup(disallowed.close)

        response = disallowed.request(
            self.raw_request(
                "GET",
                "/api/status",
                (
                    ("X-Remote-User-Id", USER_A),
                    ("X-Forwarded-For", "172.30.32.2"),
                ),
            )
        )

        self.assert_neutral_error(response, 403, "access_denied")

    def test_real_parser_send_error_is_neutral_and_secret_free(self) -> None:
        response = self.live.request(
            b"GET /"
            + b"password=private-secret" * 4_000
            + b" HTTP/1.1\r\nHost: ingress.local\r\n\r\n"
        )

        self.assert_neutral_error(response, 400, "invalid_request")
        self.assertNotIn(b"private-secret", response.body)


if __name__ == "__main__":
    unittest.main()
