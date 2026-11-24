# Handbuch: Proton Drive Backup für Home Assistant

Proton Drive Backup ergänzt das normale Backup-Menü von Home Assistant um **Proton Drive** als zusätzlichen Sicherungsort. Home Assistant erstellt die Archive und steuert Zeitplan, Inhalte und Verschlüsselung. Die Integration verbindet das Backup-Menü mit der App. Die App meldet sich bei Proton an, überträgt die Archive und zeigt den Status. Für geplante Backups muss die App laufen; ihre Web-Oberfläche darf geschlossen bleiben.

## Voraussetzungen

- Home Assistant OS auf amd64 (x86-64), Home Assistant Core ab 2026.11.2 und Administratorzugriff auf Home Assistant.
- Die beiden getrennten GitHub-Repositories: [App für Home Assistant OS](https://github.com/Fighterbomber001/Proton-drive-4-Homeassistant-App) und [Integration für den Marketplace](https://github.com/Fighterbomber001/Proton-drive-4-Homeassistant).
- Ein Proton-Konto mit ausreichend freiem Speicher. Ein separates Konto für Sicherungen erleichtert die Trennung von anderen Daten.
- Freier Platz im App-Datenbereich mindestens in Größe des jeweils übertragenen Archivs, zusätzlich zum übrigen Systembedarf. Die Anbindung begrenzt ein Archiv auf 100 GiB; der tatsächlich verfügbare Speicher kann deutlich darunter liegen.
- Ein unabhängiger Sicherungsort und ein getrennt aufbewahrtes [Home-Assistant-Notfallpaket mit Verschlüsselungsschlüssel](https://www.home-assistant.io/more-info/backup-emergency-kit).

## Installation und Kopplung

1. Öffne [Einstellungen → Apps → App installieren → ⋮ → Repositories](https://contributors.home-assistant.io/apps/guides/repository/#add-a-repository-to-home-assistant). Füge die GitHub-Adresse des [App-Repositorys](https://github.com/Fighterbomber001/Proton-drive-4-Homeassistant-App) hinzu und installiere **Proton Drive Backup**.
2. Öffne **Konfiguration** auf der App-Seite. Fülle die folgenden Felder aus, speichere und starte die App. Ist sie bereits gestartet, starte sie nach dem Speichern neu.

   | Feld | Einstellung |
   | --- | --- |
   | Home-Assistant-Adresse (`home_assistant_origin`) | Die Adresse, über die dein Browser Home Assistant tatsächlich öffnet, z. B. `https://ha.example.org`. Mit Protokoll und, falls erforderlich, Port. Ohne Zugangsdaten, Pfad, Abfrage, Fragment oder abschließenden Schrägstrich. |
   | Weitere Home-Assistant-Adressen (`additional_origins`) | Nur wenn nötig: bis zu 16 weitere tatsächlich verwendete Browser-Adressen im selben Format. Keine Platzhalter und keine Zugangsdaten. |
   | Native Backup-Anbindung (`native_mode`) | Einschalten (`true`). |
   | Verbindungsschlüssel der Integration (`integration_token`) | Eigener, zufälliger Schlüssel, z. B. 64 Hex-Zeichen aus einem Passwortmanager. Erlaubt sind 32–128 Zeichen aus `A–Z`, `a–z`, `0–9`, `.`, `_`, `~` und `-`. Kein Proton-Passwort und kein Home-Assistant-Token. |

3. Öffne die **Web-Oberfläche** der App, wähle **Mit Proton verbinden** und dann **Proton-Anmeldung öffnen**. Der Link ist nur kurz gültig. Gib dein Proton-Passwort und ggf. den Zwei-Faktor-Code ausschließlich auf der Proton-Seite ein. Kehre zur App zurück und warte auf **Verbunden**.
4. Öffne [Einstellungen → Marketplace → Aus Link hinzufügen](https://www.home-assistant.io/integrations/marketplace/#custom-repositories). Verbinde GitHub, wenn der Marketplace dich dazu auffordert. Gib die GitHub-Adresse des [Integrations-Repositorys](https://github.com/Fighterbomber001/Proton-drive-4-Homeassistant) ein, installiere **Proton Drive Backup** und starte Home Assistant Core neu, wenn der Marketplace dies verlangt.
5. Füge unter **Einstellungen → Geräte & Dienste → Integration hinzufügen** den Eintrag **Proton Drive** hinzu. Für das oben verlinkte App-Repository ist **Interne App-Adresse** bereits mit `http://adc40830-proton-drive-backup:8100` vorbelegt. Bei einer anderen Installationsquelle verwende den tatsächlichen [Repository-Präfix des Supervisors](https://contributors.home-assistant.io/apps/guides/repository/#the-repository-id) anstelle von `adc40830`. Bei einer vorhandenen Kopplung bleibt die gespeicherte Adresse maßgeblich. Das ist **nicht** die Browser-Adresse `home_assistant_origin`. Richte keine Portfreigabe ein. Gib unter **Lokaler Kopplungsschlüssel** denselben Schlüssel ein wie in `integration_token`.
6. Wähle unter **Einstellungen → System → Backups** **Proton Drive** als zusätzlichen Sicherungsort. Lass die Verschlüsselung für dieses Ziel aktiv, behalte ein unabhängiges Ziel und lege ein kleines manuelles Backup an. Kontrolliere beide Kopien und lade die Proton-Kopie zur Probe herunter.

## Sicherungen im Alltag

Plane und starte Sicherungen im Backup-Menü von Home Assistant. In der App siehst du unter **Verbindung** die Proton-Anmeldung, unter **Letzte bestätigte Sicherung** den jüngsten bestätigten Stand und unter **Diagnose** Hinweise bei Fehlern. **Letzte Sicherungen** zeigt bis zu 14 bestätigte Proton-Kopien mit Name, Sicherungsdatum und Größe, nach Sicherungsdatum absteigend. Das ist eine Vorschau ohne Download- oder Wiederherstellungsfunktion. Verwende dafür das Backup-Menü von Home Assistant.

Die sichtbare App-Seite fragt den Status beim Öffnen sofort ab, danach alle 30 Sekunden, höchstens zehn Minuten lang. Wird die Seite ausgeblendet, stoppt die Abfrage. Beim erneuten Anzeigen beginnt ein neues Zeitfenster. Eine Statusabfrage lädt keine Backup-Archive herunter. Sie kann eine Inventarprüfung anstoßen; die App holt die Metadaten nicht bei jeder Browser-Abfrage neu, und laufende Sicherungsanfragen haben Vorrang.

Steht dort **Liste nicht aktuell**, zeigt die App den zuletzt bestätigten Stand, sofern er vorliegt. Eine nicht aktuelle, nicht verfügbare oder gerade ladende Liste ist kein Nachweis für gelöschte oder fehlende Sicherungen.

## Ablage und Aufbewahrung in Proton Drive

```text
HomeAssistant-Backups/
└── <Installations-ID>/
    └── native/
        ├── archives/
        │   └── <Ablage-ID>/
        │       └── <Sicherungsarchiv>.tar
        └── manifests/
            └── <Inventardatei>.json
```

Ein Manifest ordnet dem Backup das Archiv mit seinem Dateinamen, seiner Größe und seiner SHA-256-Prüfsumme zu. Die TAR-Datei ist das eigentliche Backup. Ordner- und Dateinamen werden intern vergeben und können vom Anzeigenamen der Sicherung abweichen. Verschiebe oder ändere diese Dateien nicht. Ein abgebrochener Upload kann Archivdateien ohne bestätigtes Manifest hinterlassen.

Die **14 Zeilen** begrenzen nur die App-Anzeige. Diese Anbindung unterstützt **kein Löschen von Proton-Kopien** aus Home Assistant und keine automatische Aufbewahrungsregel in Proton Drive. Prüfe daher regelmäßig den verfügbaren Speicher. Bei sehr großen Beständen gelten außerdem technische Inventargrenzen: Werden mehr als 128 passende Installationsordner oder mehr als 1.024 passende Manifeste in einer vollständigen Inventarabfrage gefunden, kann die Abfrage fehlschlagen. Das ist weder eine Aufbewahrungsregel noch ein Löschvorgang.

## Download und Wiederherstellung erproben

1. Wähle unter **Einstellungen → System → Backups** eine bestätigte Sicherung. Lade das Archiv ausdrücklich vom Speicherort **Proton Drive** herunter. So prüfst du die Proton-Kopie und nicht eine zweite, etwa lokal gespeicherte Kopie.
2. Halte den für dieses Backup gültigen Notfallschlüssel bereit. Stelle das heruntergeladene Archiv auf einem getrennten Testsystem wieder her. Prüfe dort, ob Home Assistant startet und ob die für dich wichtigen Daten, Einstellungen und Funktionen vorhanden sind. Nutze für den ersten Versuch nicht dein einziges laufendes System.

Bei einem neuen Upload prüft die App unter anderem Dateigröße und Kennung des abgelegten Archivs und liest das gespeicherte Manifest zur Kontrolle zurück. Sie lädt das Archiv dabei nicht noch einmal vollständig herunter. Beim Download über die Integration prüft die App die Archivgröße und vergleicht die SHA-256-Prüfsumme mit dem Manifest. Weder ein erfolgreicher Upload noch diese Download-Prüfung weist eine funktionierende Wiederherstellung des ganzen Systems nach.

**Falls das bisherige Home Assistant nicht mehr startet:** Halte den Zugang zu Proton Drive unabhängig von der App bereit. Melde dich direkt bei Proton Drive an und lade die passende TAR-Datei herunter. Im Zweifel identifiziert das zugehörige Manifest das Archiv: Backup-Name und Sicherungsdatum stehen unter `metadata.name` und `metadata.date`. Die Ablage-ID ist der letzte Teil des Manifest-Dateinamens vor `.json`; der eigentliche Archivname steht unter `archive.name`. Wähle anschließend in Home Assistant die Wiederherstellung aus einer lokalen Datei, etwa im Einrichtungsdialog eines frischen Systems. Bei verschlüsselten Archiven brauchst du den zur Sicherung passenden Notfallschlüssel. Die gespeicherte Proton-Anmeldung der App wird vom App-Backup ausgeschlossen; verlasse dich im Notfall nicht darauf. Bewahre die unabhängige Sicherung und den Schlüssel so auf, dass sie ohne das ausgefallene System erreichbar sind.

Siehe auch [Backups und Wiederherstellung in Home Assistant](https://www.home-assistant.io/common-tasks/general/backups/#restoring-a-backup).

## Aktualisieren und Fehler eingrenzen

- **Updates:** Warte laufende Übertragungen ab und prüfe eine aktuelle, unabhängige Sicherung. Aktualisiere die App über **Einstellungen → Apps** und die Integration getrennt über den **Marketplace**. **Neu aufbauen** ist kein Ersatz für **Aktualisieren**. Teste nach Änderungen einen manuellen Backup-Lauf und den Download der Proton-Kopie.
- **Proton Drive fehlt oder ist nicht erreichbar:** Prüfe, ob die App läuft, `native_mode` aktiv ist und **Verbunden** angezeigt wird. Prüfe die interne App-Adresse und den Kopplungsschlüssel. Richte für die Fehlersuche keine Portfreigabe ein.
- **Proton-Anmeldung ungültig:** Nutze je nach Anzeige **Mit Proton verbinden** oder **Anmeldung erneuern**. Das ist unabhängig vom lokalen Kopplungsschlüssel. Starte bei Bedarf anschließend eine neue Sicherung aus dem Backup-Menü.
- **App-Adresse oder Kopplungsschlüssel ändern:** Ändere die App-Konfiguration bzw. den zugehörigen Eintrag der Integration. Starte die App nach Änderungen an ihrer Konfiguration neu. Verwende in der Integration die neue interne Adresse bzw. den neuen Schlüssel derselben App-Installation. Eine andere Installations-ID wird bei der Neukonfiguration nicht stillschweigend übernommen.
- **Anzeige oder Übertragung gestört:** Öffne die App-Seite erneut und nutze ggf. **Diagnose aktualisieren**. Prüfe die Speicherkapazität in Proton Drive, den freien App-Speicher und den Zustand des Ziels im Home-Assistant-Backup-Menü.
- **Problem melden:** Nenne die Versionen von Home Assistant, App und Integration, den betroffenen Schritt und ggf. einen bereinigten Fehlercode. Veröffentliche keine unbereinigten Logs, privaten Host- oder Kontodaten, Backup-Namen, Archive, Anmeldelinks, Kopplungs- oder Notfallschlüssel. Siehe [Sicherheitsmeldungen](SECURITY.md).

Siehe auch den [Disclaimer](DISCLAIMER.md).
