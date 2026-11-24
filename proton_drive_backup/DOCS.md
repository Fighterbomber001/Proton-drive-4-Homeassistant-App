# Proton Drive Backup einrichten

Die [App](https://github.com/Fighterbomber001/Proton-drive-4-Homeassistant-App) wird im Home-Assistant-App-Store installiert. Für Backups über das Home-Assistant-Menü benötigst du zusätzlich die separate [Proton Drive Backup-Integration](https://github.com/Fighterbomber001/Proton-drive-4-Homeassistant) aus dem Marketplace.

1. Öffne die App-Konfiguration. Setze `native_mode` auf `true`. Trage unter `home_assistant_origin` die Adresse ein, mit der dein Browser Home Assistant aufruft: mit Protokoll und, falls nötig, Port, aber ohne Pfad oder abschließenden Schrägstrich. Weitere tatsächlich genutzte Browser-Adressen gehören in `additional_origins`.
2. Erzeuge einen zufälligen Kopplungsschlüssel, z. B. 64 Hex-Zeichen, und setze ihn als `integration_token`. Verwende weder dein Proton-Passwort noch einen Home-Assistant-Token. Speichere die Konfiguration und starte die App neu, falls sie bereits läuft.
3. Öffne die **Web-Oberfläche**. Wähle **Mit Proton verbinden** und danach **Proton-Anmeldung öffnen**. Gib Passwort und Zwei-Faktor-Code ausschließlich auf der Proton-Seite ein. Kehre zurück und prüfe, ob **Verbunden** angezeigt wird.
4. Installiere die separate Integration und füge unter **Einstellungen → Geräte & Dienste → Integration hinzufügen** den Eintrag **Proton Drive** hinzu. Trage als **Interne App-Adresse** `http://<Repository-ID>-proton-drive-backup:8100` ein. Die [Repository-ID](https://contributors.home-assistant.io/apps/guides/repository/#the-repository-id) steht am Anfang des vom Supervisor vergebenen App-Slugs. Trage denselben **Lokalen Kopplungsschlüssel** ein. Verwende nicht die Web-Oberflächen-Adresse und richte keine Portfreigabe ein.
5. Wähle **Proton Drive** als zusätzlichen Sicherungsort unter **Einstellungen → System → Backups**. Lass die Archivverschlüsselung aktiv und behalte einen unabhängigen Sicherungsort. Prüfe einen kleinen manuellen Backup-Lauf und den Download vom Ziel **Proton Drive**.

## Status und Speicher

Die sichtbare App-Seite fragt den Status beim Öffnen sofort und dann alle 30 Sekunden für bis zu zehn Minuten ab. Beim Ausblenden stoppt die Abfrage; beim erneuten Anzeigen startet ein neues Zeitfenster. Der Statusabruf ist unabhängig vom Backup-Zeitplan. Geschlossene App-Seiten verhindern keine geplanten Backups.

**Letzte Sicherungen** zeigt bis zu 14 bestätigte Proton-Kopien, neueste zuerst. Eine nicht aktuelle oder nicht verfügbare Liste beweist keinen Verlust. Das Backup-Menü von Home Assistant ist der Ort für Sicherungen, Downloads und Wiederherstellung.

Archive liegen in Proton Drive unter `HomeAssistant-Backups/<Installations-ID>/native/archives/<Ablage-ID>/`; die dazugehörigen Inventardateien liegen unter `native/manifests/`. Die 14 Zeilen sind kein Aufbewahrungslimit. Die Anbindung löscht keine Proton-Kopien und übernimmt dort keine automatische Aufbewahrung. Kontrolliere den freien Platz regelmäßig. Je Archiv sind maximal 100 GiB möglich; Upload und Download brauchen vorübergehend ausreichend freien Speicher in der App.

Bei mehr als 128 passenden Installationsordnern oder mehr als 1.024 passenden Manifesten kann die vollständige Inventarabfrage fehlschlagen. Diese technischen Grenzen löschen keine Dateien.

## Wiederherstellung und Updates

Bewahre das Home-Assistant-Notfallpaket und eine unabhängige Kopie getrennt auf. Die App prüft beim Download Größe und SHA-256-Prüfsumme des Archivs. Ein bestätigter Upload oder erfolgreicher Download ersetzt keinen Restore-Test. Lade die Sicherung von **Proton Drive** herunter und erprobe ihre Wiederherstellung auf einem getrennten Testsystem. Ist das bisherige Home Assistant ausgefallen, kannst du über dein Konto in Proton Drive das Archiv herunterladen und in Home Assistant als Datei zur Wiederherstellung auswählen; dazu nötig ist der zur Sicherung passende Notfallschlüssel, sofern das Archiv verschlüsselt ist.

Warte vor einem Update auf das Ende laufender Übertragungen und prüfe eine aktuelle unabhängige Sicherung. Nutze **Aktualisieren** für die App und den **Marketplace** für die Integration. **Neu aufbauen** installiert keine neue App-Version.

Weitere Hinweise: [Backups und Wiederherstellung in Home Assistant](https://www.home-assistant.io/common-tasks/general/backups/).
