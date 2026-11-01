# Änderungen

Alle nennenswerten Änderungen an ubusec. Versionen folgen dem Schema MAJOR.MINOR.PATCH.

## 1.4.1 – 2026-11-01

- **Speicherschutz beim Virenscan:** Scans dürfen höchstens 40 % des Arbeitsspeichers belegen. Wird es eng,
  beendet das System bevorzugt den Scanner statt Webserver oder Datenbank.
- Wird ein paralleler clamscan-Prozess vom System beendet, läuft der Scan weiter; die noch nicht geprüften
  Dateien werden anschließend mit einem einzelnen Prozess nachgeholt (bisher brach der ganze Scan ab).
- Vorsichtigere automatische Prozesszahl (freier Speicher und Speichergrenze werden berücksichtigt).
- Abbruchgrund in der Weboberfläche: Zeitpunkt, Bereich, Fortschritt und Ursache (Benutzer, systemctl stop,
  Strg+C, Zeitlimit, Neustart, Speichermangel, Programmfehler).

## 1.4.0 – 2026-11-01

- Neuer Prüfbereich **Prüfwerkzeuge**: Versionen und verfügbare Updates von ClamAV, rkhunter, chkrootkit,
  Lynis, OpenSCAP, unhide, needrestart, dig, testssl.sh und AIDE; Alter der Virensignaturen und CVE-Daten;
  Hinweis, wenn Lynis deutlich hinter der Herstellerversion liegt.
- Neue Seite **Werkzeuge** in der Weboberfläche mit „Jetzt prüfen“, „Werkzeuge aktualisieren“ (nur ubusecs
  eigene Werkzeuge und Signaturen) und „Lynis-Paketquelle des Herstellers einrichten“.
- **Versionshinweis**: ubusec fragt höchstens alle sechs Stunden bei GitHub nach einer neuen Version und zeigt
  sie samt Änderungen an (abschaltbar).
- Neue Befehle: `--check-tools`, `--update-tools`, `--lynis-upstream` und `--update` (lädt die neueste Version
  von GitHub, prüft die SHA256-Prüfsumme und installiert sie – nur auf ausdrücklichen Befehl).
- Erstes öffentliches Release auf GitHub.

## 1.3.0 – 2026-11-01

- Virenscan auf mehreren Kernen: Die Dateiliste wird auf parallele clamscan-Prozesse verteilt (Anzahl
  einstellbar, „Automatisch“ nach Kernen und Arbeitsspeicher).
- Einstellbare Ausnahmen: Datenbankdateien, Backup-Ordner, Protokolle, Postfächer, Nextcloud-Datenordner
  (automatisch erkannt) und eigene Ordner. Netzlaufwerke werden nie durchsucht.
- Fortschrittsanzeige beim Virenscan: Datei X von Y, geschätzte Restzeit, aktueller Ordner.
- Abbruch nach Neustart oder Stromausfall wird erkannt; hängende Scan-Aufträge werden angezeigt und können
  verworfen werden.
- Updates überschreiben die bestehende Baseline nicht mehr.
- Versionsnummer in Seitenleiste, Anmeldeseite und Berichten.

## 1.2.1 – 2026-11-01

- Abbruch eines Scans (systemctl stop, Strg+C) setzt den Status korrekt zurück und beendet laufende Werkzeuge.
- Schaltfläche „Scan abbrechen“ in der Weboberfläche.
- Ein abgebrochener Virenscan wird als „unvollständig“ gemeldet statt als „keine Funde“.

## 1.2.0 – 2026-11-01

- Neuer Prüfbereich **Websites & Domains** (Domains aus Virtualmin): HTTPS, Zertifikate, TLS-Versionen,
  Sicherheits-Header, offen abrufbare Dateien, Verzeichnislisten, SPF, DMARC, CAA, Apache-Einstellungen.
- Neuer Prüfbereich **Webanwendungen**: WordPress, Nextcloud, Mautic, Roundcube, eigene PHP-Anwendungen,
  PHP-Versionen und php.ini, MySQL/MariaDB-Konten.
- Einstellungen in der Weboberfläche: Konto, Zwei-Faktor, Benutzer, Zeitpläne, Benachrichtigungen,
  Scan-Einstellungen, Fehlalarme, Protokoll.
- HSTS für die Weboberfläche bei HTTPS-Betrieb.

## 1.1.0 – 2026-11-01

- Weboberfläche mit Anmeldung (scrypt, optional Zwei-Faktor), Scan-Start, Berichten und Verbesserungshinweisen.
- Scan-Aufträge über eine geprüfte Warteschlange; die Oberfläche läuft ohne root-Rechte.
- Umbenennung von secscan in ubusec.

## 1.0.0 – 2026-11-01

- Erste Version: Kommandozeilen-Scanner mit Lynis, OpenSCAP, rkhunter, chkrootkit, ClamAV, unhide,
  dpkg --verify, needrestart und eigenen Prüfungen; Text- und HTML-Bericht; systemd-Zeitpläne.
