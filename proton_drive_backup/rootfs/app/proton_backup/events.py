"""Bounded operational reporting; never accepts exception or CLI text."""
import logging
from contextlib import contextmanager
from datetime import UTC, datetime
from .redaction import SafeLogger

_MESSAGES = {
    "startup_failed": "Start fehlgeschlagen; lokale Konfiguration und Berechtigungen prüfen",
    "service_started": "Dienst gestartet", "service_stopped": "Dienst beendet",
    "service_failed": "Dienst wegen eines internen Fehlers angehalten",
    "backup_ready": "Backup erkannt und eingereiht",
    "upload_started": "Upload gestartet", "upload_succeeded": "Upload bestätigt",
    "proton_connected": "Mit Proton verbunden",
    "proton_disconnected": "Proton-Verbindung nicht verfügbar",
    "authentication_required": "Anmeldung bei Proton erforderlich",
    "auth_login_started": "Fordere Proton-Anmeldelink an",
    "auth_login_link_ready": "Proton-Anmeldelink bereit; in der Statusseite öffnen",
    "auth_login_finished": "Proton-Anmeldeaufruf abgeschlossen; Verbindung wird geprüft",
    "auth_login_failed": "Proton-Anmeldeaufruf fehlgeschlagen oder abgebrochen; Statusseite und App-Protokoll prüfen, keinen Anmeldelink weitergeben",
    "network_unavailable": "Netzwerk nicht erreichbar; neuer Versuch geplant",
    "process_timeout": "Zeitlimit erreicht; neuer Versuch geplant",
    "cancelled": "Abgebrochen; Backup bleibt in der Warteschlange",
    "upload_failed": "Upload fehlgeschlagen; neuer Versuch geplant",
    "remote_ambiguous": "Vorhandenes Remote-Archiv nicht sicher zuordenbar; Prüfung erforderlich",
    "retention_failed": "Aufbewahrung konnte nicht abgeschlossen werden",
    "command_rejected": "Befehl passt nicht mehr zum aktuellen Zustand",
    "stop_failed": "Beenden konnte nicht vollständig abgeschlossen werden",
    "native_transfer_failed": "Native Backup-Anfrage fehlgeschlagen; in Home Assistant prüfen und erneut versuchen",
    "native_cancelled": "Native Backup-Anfrage abgebrochen; erneuten Versuch in Home Assistant starten",
    "startup_started": "Starte Proton Drive Backup; prüfe zuerst die lokalen Einstellungen",
    "startup_options_invalid": "App-Konfiguration fehlt, ist nicht lesbar oder enthält kein gültiges JSON-Objekt",
    "startup_origin_missing": "Home-Assistant-Adresse fehlt; in der App-Konfiguration eintragen",
    "startup_origin_invalid": "Home-Assistant-Adresse ungültig: nur http(s)://Host mit optionalem Port, ohne Pfad, abschließenden Schrägstrich oder Zugangsdaten",
    "startup_additional_origins_invalid": "Weitere Home-Assistant-Adressen ungültig: höchstens 16 vollständige Ursprünge ohne Pfad oder abschließenden Schrägstrich",
    "startup_native_mode_invalid": "Native Backup-Anbindung muss ein Ein/Aus-Schalter sein",
    "startup_token_invalid": "Verbindungsschlüssel muss als Text eingetragen sein; kein Proton-Passwort verwenden",
    "startup_token_length_invalid": "Verbindungsschlüssel muss 32 bis 128 Zeichen lang sein; selbst erzeugten zufälligen Schlüssel eintragen",
    "startup_token_characters_invalid": "Verbindungsschlüssel enthält nicht erlaubte Zeichen; erlaubt sind ausschließlich A-Z, a-z, 0-9 und ._~- ohne Leerzeichen",
    "startup_native_enabled": "Nativer Backup-Modus gewählt; zusätzlicher Ordner-Uploader bleibt deaktiviert",
    "startup_legacy_enabled": "Alter Ordner-Upload-Modus gewählt; für das HA-Backup-Menü Native Backup-Anbindung einschalten",
    "startup_configuration_ready": "Lokale Startvorbereitung abgeschlossen; starte jetzt die Hintergrunddienste",
}

# All stage labels are fixed source strings. Never derive them from an exception,
# a URL, subprocess output, or configuration supplied by a caller.
_STARTUP_STAGES = {
    "startup_options": ("Prüfe lokale App-Konfiguration", "App-Konfiguration gültig", "App-Konfiguration konnte nicht geprüft werden; vorherigen Fehlercode beachten"),
    "startup_private_storage": ("Bereite private Datenverzeichnisse vor", "Private Datenverzeichnisse bereit", "Private Datenverzeichnisse nicht verfügbar; App-Datenspeicher und AppArmor-Protokoll prüfen, nichts löschen"),
    "startup_credentials": ("Prüfe privaten GPG/pass-Anmeldespeicher", "Privater Anmeldespeicher bereit", "GPG/pass-Anmeldespeicher konnte nicht vorbereitet werden; AppArmor-/Systemprotokoll prüfen, private Daten nicht löschen"),
    "startup_credential_paths": ("Prüfe Verzeichnisse des Anmeldespeichers", "Verzeichnisse des Anmeldespeichers geprüft", "Anmeldeverzeichnisse nicht verfügbar; Datenspeicher und AppArmor-Protokoll prüfen, nichts löschen"),
    "startup_credential_existing": ("Prüfe vorhandenen lokalen Anmeldeschlüssel", "Vorhandener lokaler Anmeldeschlüssel geprüft", "Vorhandener lokaler Anmeldeschlüssel konnte nicht geprüft werden; private Daten unverändert lassen"),
    "startup_gpg_generate": ("Erzeuge lokalen GPG-Schlüssel ohne Proton-Zugangsdaten", "Lokaler GPG-Schlüssel erzeugt", "Lokaler GPG-Schlüssel konnte nicht erzeugt werden; GPG und AppArmor-Protokoll prüfen"),
    "startup_gpg_fingerprint": ("Prüfe Kennung des lokalen GPG-Schlüssels", "Kennung des lokalen GPG-Schlüssels geprüft", "Lokaler GPG-Schlüssel konnte nicht eindeutig gelesen werden; private Daten unverändert lassen"),
    "startup_pass_init": ("Initialisiere lokalen pass-Anmeldespeicher", "Lokaler pass-Anmeldespeicher initialisiert", "Lokaler pass-Anmeldespeicher konnte nicht initialisiert werden; pass und AppArmor-Protokoll prüfen"),
    "startup_credential_permissions": ("Prüfe Schutz der lokalen Anmeldedaten", "Schutz der lokalen Anmeldedaten geprüft", "Schutzprüfung der lokalen Anmeldedaten fehlgeschlagen; private Daten nicht löschen und Schutzmodus eingeschaltet lassen"),
    "startup_state": ("Öffne lokale Statusdatenbank", "Statusdatenbank bereit", "Statusdatenbank konnte nicht geöffnet werden; App-Datenspeicher prüfen, Datenbank nicht löschen"),
    "startup_components": ("Bereite Backup-Komponenten vor", "Backup-Komponenten bereit", "Backup-Komponenten konnten nicht vorbereitet werden; App-Version und Installation prüfen"),
    "startup_dependencies": ("Lade interne HTTP-Schnittstelle", "Bibliotheken für interne HTTP-Schnittstelle bereit", "Interne HTTP-Schnittstelle konnte nicht geladen werden; App aktualisieren und neu bauen"),
    "startup_runtime": ("Starte Hintergrunddienst", "Hintergrunddienst bereit", "Hintergrunddienst konnte nicht starten; vorherigen Schritt und Fehlercode beachten"),
    "startup_recovery": ("Prüfe gespeicherten Arbeitszustand", "Gespeicherter Arbeitszustand geprüft", "Gespeicherter Arbeitszustand konnte nicht wiederhergestellt werden; Daten unverändert lassen und Diagnose prüfen"),
    "startup_web": ("Starte Status-Weboberfläche", "Status-Weboberfläche bereit", "Status-Weboberfläche konnte nicht starten; App-/Supervisor-Protokoll und Port 8099 prüfen"),
    "startup_native_api": ("Starte interne Backup-Schnittstelle", "Interne Backup-Schnittstelle bereit", "Interne Backup-Schnittstelle konnte nicht starten; App-/Supervisor-Protokoll und internen Port 8100 prüfen, keinen Host-Port freigeben"),
}
for _stage, _texts in _STARTUP_STAGES.items():
    _MESSAGES.update({f"{_stage}_{suffix}": message
                      for suffix, message in zip(("started", "ready", "failed"), _texts)})
_STARTUP_ERRORS = frozenset(code for code in _MESSAGES
                          if code.startswith("startup_") and (code.endswith("_failed")
                              or code.endswith("_invalid") or code == "startup_origin_missing"))

_AUTH_FAILURES = {
    "unknown": "Grund des Anmeldefehlers noch nicht zugeordnet",
    "spawn_failed": "Proton-Programm konnte nicht gestartet werden; Installation und AppArmor-Protokoll prüfen",
    "cleanup_failed": "Proton-Anmeldeprozess konnte nicht vollständig beendet werden",
    "secret_rejected": "Ausgabe des Anmeldeprozesses wurde von der sicheren Link-Prüfung abgewiesen",
    "reader_failed": "Ausgabe oder private Link-Übergabe des Anmeldeprozesses konnte nicht verarbeitet werden",
    "no_url": "Proton-Programm wurde beendet, ohne einen Anmeldelink bereitzustellen",
}
_AUTH_HINTS = {
    "certificate": "Fehlerausgabe enthält einen Hinweis auf Zertifikate/TLS; noch keine bestätigte Ursache",
    "network": "Fehlerausgabe enthält einen Hinweis auf Netzwerk/DNS; noch keine bestätigte Ursache",
    "permissions": "Fehlerausgabe enthält einen Hinweis auf Dateirechte; noch keine bestätigte Ursache",
    "runtime": "Fehlerausgabe enthält einen Hinweis auf Programmbibliotheken/Laufzeit; noch keine bestätigte Ursache",
    "usage": "Fehlerausgabe enthält einen Hinweis auf Befehlsparameter; noch keine bestätigte Ursache",
    "credentials": "Fehlerausgabe enthält einen Hinweis auf den lokalen Anmeldespeicher; Daten unverändert lassen",
}
_MESSAGES.update({"auth_process_" + kind: message for kind, message in _AUTH_FAILURES.items()})
_MESSAGES.update({"auth_hint_" + kind: message for kind, message in _AUTH_HINTS.items()})


@contextmanager
def startup_step(events, stage):
    """Report a fixed phase while preserving failures and never formatting them."""
    if type(stage) is not str or stage not in _STARTUP_STAGES:
        raise ValueError("invalid startup stage")
    events.record(f"{stage}_started")
    try:
        yield
    except Exception:
        events.record(f"{stage}_failed")
        raise
    else:
        events.record(f"{stage}_ready")


class EventLog:
    def __init__(self, *, diagnostics=None, logger=None, clock=lambda: datetime.now(UTC)):
        self._diagnostics = diagnostics
        self._logger = logger or SafeLogger(logging.getLogger("proton_backup"))
        self._clock = clock

    def auth_process_failure(self, *, failure_kind, exit_code=None,
                             stdout_seen=False, stderr_seen=False, stderr_hint="unknown"):
        # Reject arbitrary strings/objects before formatting: subprocess and
        # exception content is never diagnostic text, even when redacted.
        kind = failure_kind if type(failure_kind) is str and failure_kind in _AUTH_FAILURES else "unknown"
        self.record("auth_process_" + kind)
        code = exit_code if type(exit_code) is int and -255 <= exit_code <= 255 else "unavailable"
        stdout = "present" if stdout_seen is True else "absent"
        stderr = "present" if stderr_seen is True else "absent"
        try:
            self._logger.log(logging.ERROR, "auth_process_result: exit_code=%s stdout=%s stderr=%s", code, stdout, stderr)
        except Exception:
            pass
        if type(stderr_hint) is str and stderr_hint in _AUTH_HINTS:
            self.record("auth_hint_" + stderr_hint)

    def record(self, code, *, backup_name=None):
        # Drop arbitrary strings: a CLI response must never become a log code.
        if code not in _MESSAGES:
            code = "service_failed"
        message = _MESSAGES[code]
        level = (logging.ERROR if code in _STARTUP_ERRORS or code.startswith(("auth_process_", "auth_hint_")) or code in {"service_failed", "stop_failed", "auth_login_failed"}
                 else logging.WARNING if code in {"remote_ambiguous", "retention_failed"} else logging.INFO)
        try:
            self._logger.log(level, "%s: %s", code, message)
            if self._diagnostics is not None:
                self._diagnostics.append(timestamp=self._clock(), code=code,
                                         message=message, backup_name=backup_name)
        except Exception:
            return


def configure_logging():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
