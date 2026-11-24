"use strict";

const routes = Object.freeze({
  status: "api/status",
  diagnostics: "api/diagnostics",
  connect: "api/auth/connect",
  disconnect: "api/auth/disconnect",
  renew: "api/auth/renew",
  scan: "api/scan",
  cancel: "api/upload/cancel",
  retry: "api/upload/retry",
  restart: "api/worker/restart",
});

const elements = Object.freeze({
  overallStatus: document.querySelector("#overall-status"),
  notice: document.querySelector("#notice"),
  connectionState: document.querySelector("#connection-state"),
  connectionStatus: document.querySelector("#connection-status"),
  scannerStatus: document.querySelector("#scanner-status"),
  uploadName: document.querySelector("#upload-name"),
  uploadStarted: document.querySelector("#upload-started"),
  uploadSha: document.querySelector("#upload-sha"),
  queueSize: document.querySelector("#queue-size"),
  nextRetry: document.querySelector("#next-retry"),
  lastSuccessHeading: document.querySelector("#last-success-heading"),
  lastSuccess: document.querySelector("#last-success"),
  lastError: document.querySelector("#last-error"),
  remoteFiles: document.querySelector("#remote-files"),
  backupHistoryNote: document.querySelector("#backup-history-note"),
  remoteDateHeading: document.querySelector("#remote-date-heading"),
  diagnosticsList: document.querySelector("#diagnostics-list"),
  loginArea: document.querySelector("#login-area"),
  loginLink: document.querySelector("#login-link"),
  connectButton: document.querySelector("#connect-button"),
  renewButton: document.querySelector("#renew-button"),
  disconnectButton: document.querySelector("#disconnect-button"),
  scanButton: document.querySelector("#scan-button"),
  restartButton: document.querySelector("#restart-button"),
  cancelButton: document.querySelector("#cancel-button"),
  retryButton: document.querySelector("#retry-button"),
  diagnosticsButton: document.querySelector("#diagnostics-button"),
  confirmDialog: document.querySelector("#confirm-dialog"),
  confirmMessage: document.querySelector("#confirm-message"),
  confirmCancel: document.querySelector("#confirm-cancel"),
  confirmAccept: document.querySelector("#confirm-accept"),
});

const state = {
  csrfToken: null,
  snapshot: null,
  statusFresh: false,
  mutationPending: false,
  statusRequest: null,
  acceptedRetryFingerprint: null,
  confirmation: null,
  loginTimer: null,
  loginExpiresAt: 0,
  loginGeneration: null,
};

const statusIntervalMs = 30_000;
const statusWindowMs = 10 * 60_000;
let statusTimer = null;
let statusWindowOpen = false;
let pageActive = true;
let panelVisible = true;
let handoffTimer = null;
let handoffGeneration = 0;

const dateFormatter = new Intl.DateTimeFormat("de-DE", {
  dateStyle: "medium",
  timeStyle: "short",
});

const numberFormatter = new Intl.NumberFormat("de-DE", {
  maximumFractionDigits: 1,
});

function setText(element, value) {
  element.textContent = value;
}

function formatDate(value) {
  if (typeof value !== "string") {
    return "–";
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "–" : dateFormatter.format(date);
}

function formatSize(value) {
  if (!Number.isSafeInteger(value) || value < 0) {
    return "–";
  }
  if (value < 1024) {
    return `${value} B`;
  }
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let amount = value / 1024;
  let unit = units[0];
  for (let index = 1; index < units.length && amount >= 1024; index += 1) {
    amount /= 1024;
    unit = units[index];
  }
  return `${numberFormatter.format(amount)} ${unit}`;
}

function errorLabel(code) {
  const labels = {
    access_denied: "Zugriff verweigert",
    ambiguous_remote_listing: "Remote-Liste ist nicht eindeutig",
    ambiguous_remote_metadata: "Remote-Metadaten sind nicht eindeutig",
    authentication_required: "Anmeldung erforderlich",
    cancelled: "Upload wurde abgebrochen",
    csrf_rejected: "Sitzung abgelaufen",
    idempotency_conflict: "Anfragekonflikt",
    internal_error: "Interner Fehler",
    invalid_body: "Ungültige Anfrage",
    invalid_retention_scope: "Aufbewahrungsbereich ist ungültig",
    invalid_request: "Ungültige Anfrage",
    network_unavailable: "Netzwerk nicht erreichbar",
    not_found: "Nicht gefunden",
    origin_rejected: "Ursprung nicht freigegeben",
    process_timeout: "Upload hat zu lange gedauert",
    remote_ambiguous: "Remote-Status unklar",
    upload_failed: "Upload fehlgeschlagen – neuer Versuch geplant",
    remote_delete_failed: "Remote-Löschung fehlgeschlagen",
    remote_listing_failed: "Remote-Liste konnte nicht geladen werden",
    remote_listing_incomplete: "Remote-Liste ist unvollständig",
    retention_failed: "Aufbewahrung konnte nicht abgeschlossen werden",
    service_busy: "Dienst ausgelastet",
    state_read_failed: "Lokaler Status konnte nicht gelesen werden",
    storage_failed: "Backup-Anfrage fehlgeschlagen – in Home Assistant erneut versuchen",
    backup_not_found: "Sicherung nicht gefunden",
    delete_not_supported: "Remote-Löschen ist derzeit gesperrt",
  };
  return labels[code] || "Unbekannter Fehler";
}

function scannerLabel(value) {
  const labels = {
    error: "Fehler",
    idle: "Bereit",
    scanning: "Prüfung läuft",
    starting: "Wird gestartet",
    stopped: "Angehalten",
  };
  return labels[value] || "Unbekannter Zustand";
}

function showNotice(message, isError = false) {
  setText(elements.notice, message);
  elements.notice.hidden = false;
  elements.notice.classList.toggle("notice-error", isError);
}

function clearNotice() {
  elements.notice.hidden = true;
  elements.notice.classList.remove("notice-error");
  setText(elements.notice, "");
}

function retryFingerprint(snapshot) {
  if (
    snapshot === null
    || typeof snapshot.retry_sha256 !== "string"
    || !Number.isSafeInteger(snapshot.retry_revision)
    || snapshot.retry_revision <= 0
    || snapshot.queue === null
    || typeof snapshot.queue !== "object"
  ) {
    return null;
  }
  return Object.freeze({
    sha256: snapshot.retry_sha256,
    revision: snapshot.retry_revision,
    nextRetryAt: typeof snapshot.queue.next_retry_at === "string"
      ? snapshot.queue.next_retry_at
      : null,
  });
}

function sameRetryFingerprint(first, second) {
  return first !== null
    && second !== null
    && first.sha256 === second.sha256
    && first.revision === second.revision
    && first.nextRetryAt === second.nextRetryAt;
}

function updateControls() {
  const snapshot = state.snapshot;
  const loaded = state.statusFresh && snapshot !== null;
  const ready = loaded && snapshot.service.web_ready === true;
  const connected = ready && snapshot.service.connected === true;
  const scannerIdle = ready && snapshot.service.scanner_state === "idle";
  const activeSha = ready && typeof snapshot.upload.sha256 === "string"
    ? snapshot.upload.sha256
    : null;
  const retrySha256 = ready && typeof snapshot.retry_sha256 === "string"
    ? snapshot.retry_sha256
    : null;
  const retryAcknowledged = sameRetryFingerprint(
    state.acceptedRetryFingerprint,
    retryFingerprint(snapshot),
  );
  const pending = state.mutationPending;
  const nativeMode = ready && snapshot.service.native_mode === true;
  const nativeActive = ready && typeof snapshot.upload.native_operation === "string";

  elements.connectButton.disabled = pending || !ready || connected;
  elements.renewButton.disabled = pending || !connected;
  elements.disconnectButton.disabled = pending || !connected;
  elements.scanButton.disabled = pending || !connected || !scannerIdle || nativeMode;
  elements.restartButton.disabled = pending || !ready;
  elements.cancelButton.disabled = pending || (activeSha === null && !nativeActive);
  elements.retryButton.disabled = pending
    || activeSha !== null
    || retrySha256 === null
    || retryAcknowledged;
  if (nativeMode) elements.retryButton.disabled = true;
  elements.diagnosticsButton.disabled = pending || !loaded;
}

function renderNativeBackupSummary(historyState, newest) {
  setText(elements.lastSuccessHeading, "Letzte bestätigte Sicherung");
  const date = formatDate(newest?.date);
  let summary = "Derzeit nicht verfügbar";
  if (historyState === "loading") summary = "Wird geprüft …";
  else if (historyState === "ready") {
    summary = newest ? (date === "–" ? summary : date) : "Noch keine";
  } else if (historyState === "stale") {
    if (!newest) summary = "Zuletzt keine bestätigt (Stand nicht aktuell)";
    else if (date !== "–") summary = `${date} (Stand nicht aktuell)`;
  }
  setText(elements.lastSuccess, summary);
}

function renderRemoteFiles(files, nativeMode, history = null) {
  const historyState = history?.state;
  const hasHistory = historyState === "ready" || historyState === "stale";
  setText(elements.remoteDateHeading, nativeMode ? "Sicherungsdatum" : "Remote-Änderung");
  elements.remoteFiles.replaceChildren();
  const source = nativeMode ? (hasHistory ? history.files : null) : files;
  const safeFiles = Array.isArray(source) ? source.slice(0, 14) : [];
  if (nativeMode) renderNativeBackupSummary(historyState, safeFiles[0]);
  elements.backupHistoryNote.hidden = !nativeMode || historyState !== "stale" || safeFiles.length === 0;
  setText(elements.backupHistoryNote, elements.backupHistoryNote.hidden ? "" :
    "Liste nicht aktuell: Es wird der zuletzt bestätigte Stand angezeigt.");
  if (safeFiles.length === 0) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 3;
    let message = "Noch keine Remote-Sicherung vorhanden.";
    if (nativeMode) {
      if (historyState === "ready") message = "Noch keine bestätigte Proton-Sicherung vorhanden.";
      else if (historyState === "loading") message = "Sicherungsliste wird geladen.";
      else if (historyState === "stale") message = "Liste nicht aktuell: Zuletzt wurden keine Proton-Sicherungen bestätigt.";
      else message = "Proton-Sicherungsliste derzeit nicht verfügbar.";
    }
    setText(cell, message);
    row.append(cell);
    elements.remoteFiles.append(row);
    return;
  }

  for (const file of safeFiles) {
    const row = document.createElement("tr");
    const name = document.createElement("td");
    const size = document.createElement("td");
    const modified = document.createElement("td");
    setText(name, typeof file.name === "string" ? file.name : "–");
    setText(size, formatSize(file.size));
    setText(modified, formatDate(nativeMode ? file.date : file.modified_at));
    row.append(name, size, modified);
    elements.remoteFiles.append(row);
  }
}

function hideNativeBackupHistory() {
  if (state.snapshot?.service.native_mode === true) {
    state.snapshot = {
      ...state.snapshot,
      backup_history: { state: "unavailable", files: [] },
    };
    renderRemoteFiles(null, true);
  } else if (state.snapshot === null) {
    renderRemoteFiles(null, true);
  }
}

function renderStatus(snapshot) {
  const connected = snapshot.service.connected === true;
  const ready = snapshot.service.web_ready === true;
  const nativeMode = snapshot.service.native_mode === true;
  const nativeOperation = snapshot.upload.native_operation;
  const uploadActive = typeof snapshot.upload.sha256 === "string" || typeof nativeOperation === "string";
  const operationLabels = { list: "Inventar", get: "Metadaten", upload: "Upload", download: "Download", delete: "Löschen" };
  const currentRetryFingerprint = retryFingerprint(snapshot);
  if (!sameRetryFingerprint(state.acceptedRetryFingerprint, currentRetryFingerprint)) {
    state.acceptedRetryFingerprint = null;
  }
  state.snapshot = snapshot;

  setText(elements.connectionStatus, connected ? "Verbunden" : "Nicht verbunden");
  elements.connectionState.classList.toggle("connected", connected);
  setText(elements.scannerStatus, nativeMode ? "Über Home-Assistant-Backups gesteuert" : scannerLabel(snapshot.service.scanner_state));
  const activeLabel = snapshot.upload.name || "Backup-Anfrage";
  setText(elements.uploadName, uploadActive ? (nativeMode ? `${operationLabels[nativeOperation] || "Backup"}: ${activeLabel}` : activeLabel) : "Keine Übertragung aktiv");
  setText(elements.uploadStarted, formatDate(snapshot.upload.started_at));
  setText(elements.uploadSha, typeof snapshot.upload.sha256 === "string" ? snapshot.upload.sha256 : "–");
  setText(elements.cancelButton, nativeMode ? "Backup-Anfrage abbrechen" : "Upload abbrechen");
  setText(elements.restartButton, nativeMode ? "Aktuelle Anfrage zurücksetzen" : "Uploader neu starten");
  setText(elements.queueSize, String(snapshot.queue.size));
  setText(elements.nextRetry, formatDate(snapshot.queue.next_retry_at));
  if (!nativeMode) {
    setText(elements.lastSuccessHeading, "Letzter Erfolg");
    setText(elements.lastSuccess, snapshot.last_success_at ? formatDate(snapshot.last_success_at) : "Noch keiner");
  }
  setText(elements.lastError, snapshot.last_error_code ? `Letzter Fehler: ${errorLabel(snapshot.last_error_code)}` : "Kein Fehler gemeldet");

  elements.overallStatus.classList.remove("status-neutral", "status-ok", "status-warning", "status-error");
  if (!ready) {
    setText(elements.overallStatus, "Dienst nicht bereit");
    elements.overallStatus.classList.add("status-error");
  } else if (!connected) {
    setText(elements.overallStatus, "Verbindung erforderlich");
    elements.overallStatus.classList.add("status-warning");
  } else {
    setText(elements.overallStatus, "Betriebsbereit");
    elements.overallStatus.classList.add("status-ok");
  }

  renderRemoteFiles(snapshot.remote_files, nativeMode, connected ? snapshot.backup_history : null);
  updateControls();
}

async function readJson(response) {
  try {
    return await response.json();
  } catch (_error) {
    return null;
  }
}

async function refreshStatus(options = {}) {
  const force = options.force === true;
  if (state.mutationPending && !force) {
    return;
  }
  if (state.statusRequest !== null) {
    return state.statusRequest;
  }

  state.statusRequest = (async () => {
    const requestStartedAt = Date.now();
    try {
      const response = await fetch(routes.status, {
        method: "GET",
        headers: { Accept: "application/json" },
        cache: "no-store",
      });
      const payload = await readJson(response);
      if (!response.ok || payload === null) {
        const code = payload && payload.error ? payload.error.code : null;
        throw new Error(errorLabel(code));
      }
      if (typeof payload.csrf_token !== "string") {
        throw new Error("Ungültige Statusantwort");
      }
      state.csrfToken = payload.csrf_token;
      state.statusFresh = true;
      renderStatus(payload);
      updateLoginLink(payload, requestStartedAt);
    } catch (error) {
      hideLoginLink();
      state.csrfToken = null;
      state.statusFresh = false;
      showNotice(`Status konnte nicht geladen werden: ${error.message}`, true);
      setText(elements.overallStatus, "Status nicht verfügbar");
      elements.overallStatus.classList.remove("status-ok", "status-warning");
      elements.overallStatus.classList.add("status-error");
      hideNativeBackupHistory();
      updateControls();
    }
  })();

  try {
    await state.statusRequest;
  } finally {
    state.statusRequest = null;
  }
}

function newIdempotencyKey() {
  if (typeof crypto.randomUUID === "function") {
    return `ui-${crypto.randomUUID()}`;
  }
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  const encoded = Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
  return `ui-${encoded}`;
}

function sleep(milliseconds) {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}

async function sendMutation(intent) {
  let lastNetworkError = null;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      const response = await fetch(intent.route, {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
          "Idempotency-Key": intent.idempotencyKey,
          "X-CSRF-Token": intent.csrfToken,
        },
        body: JSON.stringify(intent.body),
        cache: "no-store",
      });
      if (!response.ok) {
        const payload = await readJson(response);
        return { response, payload };
      }
      const bodyText = await response.text();
      let payload;
      try {
        payload = JSON.parse(bodyText);
      } catch (_error) {
        return { response, payload: null };
      }
      return { response, payload };
    } catch (error) {
      lastNetworkError = error;
      if (attempt === 0) {
        await sleep(400);
      }
    }
  }
  throw lastNetworkError || new Error("Netzwerkfehler");
}

function hideLoginLink() {
  if (state.loginTimer !== null) {
    window.clearTimeout(state.loginTimer);
    state.loginTimer = null;
  }
  state.loginExpiresAt = 0;
  state.loginGeneration = null;
  elements.loginLink.removeAttribute("href");
  elements.loginArea.hidden = true;
}

function expireLoginLinkIfNeeded() {
  if (state.loginExpiresAt !== 0 && Date.now() >= state.loginExpiresAt) {
    hideLoginLink();
  }
}

function scheduleLoginExpiry(expiresAtMs) {
  if (state.loginTimer !== null) {
    window.clearTimeout(state.loginTimer);
  }
  state.loginExpiresAt = expiresAtMs;
  state.loginTimer = window.setTimeout(
    hideLoginLink,
    Math.max(0, expiresAtMs - Date.now()),
  );
}

function showLoginLink(value, generation, expiresAtMs) {
  hideLoginLink();
  if (
    typeof value !== "string"
    || typeof generation !== "string"
    || !/^[0-9a-f]{32}$/.test(generation)
    || !Number.isSafeInteger(expiresAtMs)
  ) {
    return;
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch (_error) {
    return;
  }
  const protonHost = parsed.hostname === "proton.me" || parsed.hostname.endsWith(".proton.me");
  if (parsed.protocol !== "https:" || parsed.port || !protonHost || parsed.username || parsed.password) {
    return;
  }
  const remainingMs = Math.min(expiresAtMs - Date.now(), 120000);
  if (remainingMs <= 0) {
    return;
  }
  elements.loginLink.setAttribute("href", parsed.href);
  elements.loginArea.hidden = false;
  state.loginGeneration = generation;
  scheduleLoginExpiry(expiresAtMs);
}

function updateLoginLink(payload, requestStartedAt) {
  if (
    payload === null
    || typeof payload !== "object"
    || payload.login_active !== true
    || payload.service === null
    || typeof payload.service !== "object"
    || payload.service.web_ready !== true
    || payload.service.connected === true
    || typeof payload.login_generation !== "string"
    || !/^[0-9a-f]{32}$/.test(payload.login_generation)
    || !Number.isSafeInteger(payload.login_remaining_ms)
    || payload.login_remaining_ms <= 0
    || payload.login_remaining_ms > 120000
    || !Number.isSafeInteger(requestStartedAt)
  ) {
    hideLoginLink();
    return;
  }
  const expiresAtMs = requestStartedAt + payload.login_remaining_ms;
  if (!Number.isSafeInteger(expiresAtMs) || expiresAtMs <= Date.now()) {
    hideLoginLink();
    return;
  }
  if (typeof payload.login_url === "string") {
    showLoginLink(
      payload.login_url,
      payload.login_generation,
      expiresAtMs,
    );
    return;
  }
  if (
    state.loginGeneration !== payload.login_generation
    || !elements.loginLink.hasAttribute("href")
  ) {
    hideLoginLink();
    return;
  }
  scheduleLoginExpiry(Math.min(state.loginExpiresAt, expiresAtMs));
}

function stopLoginHandoffChecks() {
  handoffGeneration += 1;
  if (handoffTimer !== null) {
    window.clearTimeout(handoffTimer);
    handoffTimer = null;
  }
}

function watchLoginHandoff() {
  stopLoginHandoffChecks();
  const generation = handoffGeneration;
  const until = performance.now() + 120_000;
  function schedule() {
    if (generation !== handoffGeneration || !statusPanelIsVisible()
        || performance.now() + 2_000 >= until || elements.loginLink.hasAttribute("href")) {
      return;
    }
    handoffTimer = window.setTimeout(async () => {
      handoffTimer = null;
      if (generation !== handoffGeneration || !statusPanelIsVisible() || performance.now() >= until
          || elements.loginLink.hasAttribute("href")) return;
      await refreshStatus();
      if (state.statusFresh && state.snapshot?.service.connected === true) return;
      schedule();
    }, 2_000);
  }
  schedule();
}

async function mutate(route, body, successMessage, expectedRetryFingerprint = null) {
  if (state.mutationPending) {
    return;
  }
  state.mutationPending = true;
  updateControls();
  clearNotice();

  try {
    if (state.statusRequest !== null) {
      await state.statusRequest;
    }
    if (
      !state.statusFresh
      || state.snapshot === null
      || state.snapshot.service.web_ready !== true
    ) {
      throw new Error("Dienst nicht bereit");
    }
    if (typeof state.csrfToken !== "string") {
      throw new Error("Kein gültiges Sitzungstoken");
    }
    const currentRetryFingerprint = route === routes.retry
      ? retryFingerprint(state.snapshot)
      : null;
    if (
      route === routes.retry
      && !sameRetryFingerprint(expectedRetryFingerprint, currentRetryFingerprint)
    ) {
      throw new Error("Retry-Ziel wurde zwischenzeitlich aktualisiert");
    }
    const intentBody = route === routes.retry
      ? Object.freeze({
        sha256: currentRetryFingerprint.sha256,
        retry_revision: currentRetryFingerprint.revision,
      })
      : body;
    const intent = Object.freeze({
      route,
      body: intentBody,
      idempotencyKey: newIdempotencyKey(),
      csrfToken: state.csrfToken,
      retryFingerprint: currentRetryFingerprint,
    });
    const { response, payload } = await sendMutation(intent);
    if (!response.ok || payload === null) {
      const code = payload && payload.error ? payload.error.code : null;
      throw new Error(errorLabel(code));
    }
    if (payload.accepted !== true || typeof payload.csrf_token !== "string") {
      throw new Error("Ungültige Steuerungsantwort");
    }
    state.csrfToken = payload.csrf_token;
    if (intent.retryFingerprint !== null) {
      state.acceptedRetryFingerprint = intent.retryFingerprint;
    }
    if ([routes.connect, routes.renew, routes.disconnect].includes(route)) {
      hideLoginLink();
      hideNativeBackupHistory();
    }
    if (route === routes.connect || route === routes.renew) watchLoginHandoff();
    if (route === routes.disconnect) stopLoginHandoffChecks();
    showNotice(successMessage);
  } catch (error) {
    showNotice(`Aktion nicht bestätigt: ${error.message}`, true);
  } finally {
    await refreshStatus({ force: true });
    state.mutationPending = false;
    updateControls();
  }
}

function requestConfirmation(message, action) {
  if (state.mutationPending || state.confirmation !== null) {
    return;
  }
  state.confirmation = action;
  setText(elements.confirmMessage, message);
  elements.confirmDialog.showModal();
  elements.confirmAccept.focus();
}

function closeConfirmation() {
  state.confirmation = null;
  if (elements.confirmDialog.open) {
    elements.confirmDialog.close();
  }
}

async function refreshDiagnostics() {
  elements.diagnosticsButton.disabled = true;
  try {
    const response = await fetch(routes.diagnostics, {
      method: "GET",
      headers: { Accept: "application/json" },
      cache: "no-store",
    });
    const payload = await readJson(response);
    if (!response.ok || payload === null || !Array.isArray(payload.events)) {
      const code = payload && payload.error ? payload.error.code : null;
      throw new Error(errorLabel(code));
    }
    elements.diagnosticsList.replaceChildren();
    if (payload.events.length === 0) {
      const empty = document.createElement("li");
      setText(empty, "Keine Diagnoseereignisse vorhanden.");
      elements.diagnosticsList.append(empty);
      return;
    }
    for (const event of payload.events) {
      const item = document.createElement("li");
      const timestamp = formatDate(event.timestamp);
      const message = typeof event.message === "string" ? event.message : "Unbekanntes Ereignis";
      setText(item, `${timestamp}: ${message}`);
      elements.diagnosticsList.append(item);
    }
  } catch (error) {
    showNotice(`Diagnose konnte nicht geladen werden: ${error.message}`, true);
  } finally {
    updateControls();
  }
}

elements.connectButton.addEventListener("click", () => {
  mutate(routes.connect, {}, "Verbindungsaufbau wurde gestartet.");
});

elements.renewButton.addEventListener("click", () => {
  requestConfirmation(
    "Die bestehende Proton-Anmeldung wirklich erneuern?",
    () => mutate(routes.renew, {}, "Erneuerung der Anmeldung wurde gestartet."),
  );
});

elements.disconnectButton.addEventListener("click", () => {
  requestConfirmation(
    "Die Verbindung zu Proton wirklich trennen? Laufende Übertragungen können dadurch unterbrochen werden.",
    () => mutate(routes.disconnect, {}, "Trennung der Verbindung wurde angefordert."),
  );
});

elements.scanButton.addEventListener("click", () => {
  mutate(routes.scan, {}, "Lokale Prüfung wurde angefordert.");
});

elements.cancelButton.addEventListener("click", () => {
  mutate(routes.cancel, {}, "Abbruch des Uploads wurde angefordert.");
});

elements.retryButton.addEventListener("click", () => {
  const expectedRetryFingerprint = retryFingerprint(state.snapshot);
  if (expectedRetryFingerprint !== null) {
    mutate(
      routes.retry,
      {},
      "Erneuter Upload wurde angefordert.",
      expectedRetryFingerprint,
    );
  }
});

elements.restartButton.addEventListener("click", () => {
  mutate(routes.restart, {}, "Neustart des Uploaders wurde angefordert.");
});

elements.diagnosticsButton.addEventListener("click", refreshDiagnostics);

elements.confirmCancel.addEventListener("click", closeConfirmation);

elements.confirmAccept.addEventListener("click", () => {
  const action = state.confirmation;
  closeConfirmation();
  if (typeof action === "function") {
    action();
  }
});

elements.confirmDialog.addEventListener("cancel", () => {
  state.confirmation = null;
});

function clearStatusTimer() {
  if (statusTimer !== null) {
    window.clearInterval(statusTimer);
    statusTimer = null;
  }
}

function statusPanelIsVisible() {
  return pageActive && panelVisible && document.visibilityState === "visible";
}

function syncStatusPolling(refreshIfOpen = false) {
  if (!statusPanelIsVisible()) {
    clearStatusTimer();
    stopLoginHandoffChecks();
    statusWindowOpen = false;
    return;
  }
  expireLoginLinkIfNeeded();
  if (statusWindowOpen) {
    if (refreshIfOpen && statusTimer !== null) refreshStatus();
    return;
  }
  statusWindowOpen = true;
  const until = performance.now() + statusWindowMs;
  refreshStatus();
  statusTimer = window.setInterval(() => {
    if (!statusPanelIsVisible()) {
      syncStatusPolling();
    } else if (performance.now() >= until) {
      clearStatusTimer();
    } else {
      refreshStatus();
    }
  }, statusIntervalMs);
}

document.addEventListener("visibilitychange", () => syncStatusPolling(true));

window.addEventListener("pagehide", () => {
  pageActive = false;
  hideLoginLink();
  syncStatusPolling();
});

window.addEventListener("pageshow", () => {
  pageActive = true;
  syncStatusPolling();
});

// Home Assistant may keep a hidden iframe alive without hiding the tab.
if (typeof window.IntersectionObserver === "function") {
  panelVisible = false;
  const observer = new window.IntersectionObserver(([entry]) => {
    panelVisible = entry.isIntersecting && entry.intersectionRatio > 0;
    syncStatusPolling();
  });
  observer.observe(document.documentElement);
}

updateControls();
syncStatusPolling();
