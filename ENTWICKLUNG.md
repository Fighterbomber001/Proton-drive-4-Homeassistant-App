# Wie eine Sicherung bestätigt wird

Home Assistant entscheidet, **was** gesichert wird. Das Integrations-Repository verbindet das Backup-Menü mit dieser App. Hier liegen die interne HTTP-Schnittstelle, die Proton-Anmeldung, die Übertragung und das Dashboard.

| Frage | Einstieg im App-Code | Wichtige Grenze |
| --- | --- | --- |
| Wer darf eine Übertragung anfordern? | `proton_drive_backup/rootfs/app/proton_backup/native_api.py` | Interne Kopplung mit eigenem Schlüssel; nicht die Browser-Anmeldung. |
| Wann ist eine Proton-Kopie im Inventar sichtbar? | `native_storage.py` im selben Ordner | Archiv zuerst speichern, Identität und Größe prüfen, dann Manifest veröffentlichen und zurücklesen. Ein abgebrochener Transfer ist kein bestätigter Inventareintrag. |
| Was wird beim Download geprüft? | `NativeStorage.download_backup` und die Download-Route in `native_api.py` | Größe und SHA-256 gegen das Manifest prüfen; nur die zu genau dieser Prüfung gehörende temporäre Datei streamen und anschließend entfernen. |
| Was zeigt „Letzte bestätigte Sicherung“? | `native_history.py` und `static/app.js` | Dasselbe Sicherungsdatum wie in der ersten bestätigten Tabellenzeile. „Keine“, „veraltet“ und „nicht verfügbar“ sind verschiedene Zustände. |
| Was halten Fehlerprotokolle fest? | `events.py` und `redaction.py` | Bekannte Fehlerkategorien sind für Diagnosezwecke geeignet; keine Zugangsdaten oder vollständigen Dienstantworten veröffentlichen. |

## Lokal testen

Im Stamm dieses Repositorys Python 3.12+, `aiohttp` und Node.js bereitstellen. Dann `python -B -m unittest discover -s tests -t .` ausführen. Die Tests arbeiten mit synthetischen Daten, temporären Dateien und lokalen Gegenstellen, nicht mit einem Proton-Konto. Die CI prüft zusätzlich den Linux-Imagebau und den Einstiegspunkt. Dafür muss die im Dockerfile festgelegte Proton-CLI von Proton bezogen werden können.

Der Testbetrieb bestätigt keine Wiederherstellung einer konkreten Home-Assistant-Installation.
