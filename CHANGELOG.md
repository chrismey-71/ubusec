# Änderungen

Alle nennenswerten Änderungen an ubusec. Versionen folgen dem Schema MAJOR.MINOR.PATCH.

## Unveröffentlicht

- Fortschrittsanzeige zeigt während des Lynis-Audits den gerade laufenden Test (z. B. „Lynis-Test FILE-6310: …“),
  damit sichtbar ist, dass der Scan arbeitet.
- Behoben: Auf neueren Ubuntu-Versionen (z. B. 26.04) legte die Installation /usr/local/lib/ubusec nur für root
  lesbar an; die Weboberfläche startete dann nicht („Permission denied“).
- Installation der Weboberfläche: ubusec prüft, ob der Dienstbenutzer die Programmdateien lesen kann, und zeigt
  sonst die Berechtigungen aller Ordner auf dem Weg an (statt dass der Dienst später mit „Permission denied“ scheitert).
- Behoben: „sudo lynis show details TEST-ID“ fand kein Protokoll. ubusec legt Lynis-Protokoll und -Bericht jetzt
  zusätzlich an den Standardort (/var/log/lynis.log, /var/log/lynis-report.dat).

## 1.4.2 – 2026-11-01

- Behoben: „Als Fehlalarm ausblenden“ und „Baseline übernehmen“ in der Weboberfläche wurden abgelehnt
  („Aktion … in der Scan-Warteschlange“). Ausgeblendete Meldungen verschwinden jetzt sofort aus Übersicht
  und Empfehlungen, nicht erst nach dem nächsten Scan.
- Behoben: Die Seite „Werkzeuge“ zeigte nach einem Update eine ältere Version als „Neueste Version“ (veralteter
  Zwischenspeicher). „Jetzt prüfen“ fragt GitHub jetzt immer sofort.
- Behoben: Die Lynis-Paketquelle des Herstellers scheiterte mit „NO_PUBKEY“, weil die Schlüsseldatei nur für root
  lesbar war – apt prüft Signaturen aber als Benutzer _apt.
- Lynis-Paketquelle: Fehlt der Signaturschlüssel trotzdem (z. B. nach einem Schlüsselwechsel bei CISOfy), holt ubusec den fehlenden Signaturschlüssel vom Ubuntu-Keyserver – aber nur, wenn er zum selben
  Hauptschlüssel gehört wie die Schlüsseldatei von cisofy.com. Klappt das nicht, wird die Quelle wieder entfernt,
  damit „apt update“ und die automatischen Sicherheitsupdates fehlerfrei bleiben.

## 1.4.1 – 2026-11-01

- **Virenscan über den ClamAV-Dienst:** Läuft `clamav-daemon` ohnehin (Virtualmin-Mailfilter, Nextcloud
  „Antivirus for files“), prüft ubusec über ihn – die Virensignaturen liegen dann nur einmal im Speicher,
  der Scan braucht kaum zusätzlichen Arbeitsspeicher. Fällt der Dienst aus oder darf er eine Datei nicht
  lesen, übernimmt clamscan. Neue Einstellung „Virenscanner“ (Automatisch / immer eigene clamscan-Prozesse).
- **Speicherschutz beim Virenscan:** Scans dürfen höchstens 40 % des Arbeitsspeichers belegen, mindestens
  2,5 GB und höchstens 75 %. Wird es eng, beendet das System bevorzugt den Scanner statt Webserver oder
  Datenbank. Die Einstellungen zeigen die Grenze und warnen, wenn mehr clamscan-Prozesse gewählt sind, als
  hineinpassen.
- Wird ein paralleler clamscan-Prozess vom System beendet, läuft der Scan weiter; die noch nicht geprüften
  Dateien werden anschließend mit einem einzelnen Prozess nachgeholt (bisher brach der ganze Scan ab).
- Der Virenscan weicht nie in den Swap aus (der bleibt Webserver und Datenbank vorbehalten); erreicht er seine
  Grenze, wird er beendet und nachgeholt statt den Server auszubremsen.
- Vorsichtigere automatische Prozesszahl (freier Speicher und Speichergrenze werden berücksichtigt).
- Neue Prüfung „Arbeitsspeicher knapp“, wenn der Swap zu mehr als der Hälfte belegt ist; Hinweis auf
  vm.swappiness; Arbeitsspeicher und Swap werden in den Scan-Einstellungen angezeigt.
- chkrootkit-Warnung „Potential bindshell“ wird überprüft: Lauscht auf dem Port ein bekannter Dienst (z. B. Postfix
  auf 465/SMTPS), erscheint sie als erkannter Fehlalarm statt als kritischer Befund; sonst mit Programmname.
- Collabora Online aus der Nextcloud-App „Built-in CODE Server“ (läuft aus /tmp/appimage_extracted_…) wird
  erkannt und nicht mehr als kritischer Befund gemeldet – nur wenn die MD5-Prüfsumme des AppImage aus dem
  Nextcloud-App-Ordner zum Ordnernamen passt und die Prozesse nicht als root laufen.
- Treffer in den Testdateien des Pakets clamav-testfiles (/usr/share/clamav-testfiles, Signatur
  „Clamav.Test.File“) werden als harmlos erkannt, sofern die Paketdateien unverändert sind.
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
