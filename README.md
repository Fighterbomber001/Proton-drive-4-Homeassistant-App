# Proton Drive Backup – App für Home Assistant OS

Die App überträgt Home-Assistant-Backups zu Proton Drive und stellt sie zum Download bereit. In der App meldest du dich bei Proton an und siehst die letzten bestätigten Sicherungen mit Name, Datum und Größe.

Die App und die [Proton Drive Backup-Integration](https://github.com/Fighterbomber001/Proton-drive-4-Homeassistant) werden getrennt installiert. Dieses Repository gehört in den **App-Store** von Home Assistant. Die Integration kommt aus dem **Marketplace** und ergänzt **Proton Drive** als Ziel im normalen Backup-Menü. Home Assistant erstellt die Sicherungen und steuert Zeitplan, Inhalt und Verschlüsselung.

**Voraussetzungen:** Home Assistant OS auf amd64 (x86-64), Home Assistant Core ab 2026.11.2, die passende Integration und ein Proton-Konto mit genügend Platz.

- [Handbuch](HANDBUCH.md) – Installation, Einrichtung, Betrieb und Wiederherstellung
- [Disclaimer](DISCLAIMER.md) – unabhängiges Community-Projekt, Daten und Grenzen
- [Sicherheitsmeldungen](SECURITY.md)

Die App zeigt bis zu 14 bestätigte Sicherungen. Das ist nur eine Anzeigegrenze: Sicherungen in Proton Drive werden nicht automatisch gelöscht. Behalte einen unabhängigen Sicherungsort und erprobe die Wiederherstellung auf einem getrennten System.

Dies ist ein unabhängiges Community-Projekt, kein offizielles Produkt von Proton oder Home Assistant. „Proton“ und „Proton Drive“ sind Marken der Proton AG; siehe [Protons Nutzungsbedingungen](https://proton.me/legal/terms), Abschnitt 8. Die App lädt die Proton-CLI von Proton beim Erstellen des App-Images herunter. Die CLI ist nicht Teil des Repository-Quellcodes.
