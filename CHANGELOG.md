# Änderungen

Alle nennenswerten Änderungen an ubusec. Versionen folgen dem Schema MAJOR.MINOR.PATCH.

## 1.4.4 – 2026-11-02

- **KI-Fassung der Empfehlungen:** Neuer Download auf der Seite „Empfehlungen“ zum Einfügen in eine KI – mit
  Arbeitsauftrag; eigene Domains, Systembenutzer, öffentliche IP-Adressen, E-Mail-Adressen, Prüfsummen und Dateinamen
  aus Nextcloud-Ablagen werden durch Platzhalter ersetzt. Dazu eine Zuordnungsliste nur für dich.
- Weniger Doppelungen und Fehlalarme (nach Auswertung eines echten Virtualmin-Servers):
  - rkhunter: Meldungen werden nicht mehr mit der folgenden Prüfzeile vermischt; versteckte Dateien erscheinen als
    ein Befund statt einzeln; etckeeper (/etc/.git …) und /etc/.updated gelten als harmlos; die SSH-Abweichung
    PermitRootLogin ist nur noch ein Hinweis (der SSH-Befund selbst bleibt); übliche Warnungen sind MITTEL statt HOCH.
  - chkrootkit: „RTNETLINK answers“ und Dokumentationsdateien von Paketen (z. B. Ruby-.document) werden ignoriert.
  - Lynis: Vorschläge mit Detail (welche SSH-Option), ohne Doppelte, ohne SSH-Optionen, die ubusec selbst prüft,
    ohne Tests, die schon als Warnung erscheinen; auf virtuellen Servern ohne GRUB-Passwort, Partitionen und USB.
  - Collabora: Systemvorlage in /tmp/coolwsd.*/systemplate wird byte-genau mit den Systemdateien verglichen;
    /tmp/.webmin und das Symbol des geprüften AppImage gelten nicht mehr als verdächtig.
  - Autostart-Prüfung ignoriert Kommentarzeilen (z. B. LD_PRELOAD-Beispiel in mariadb.service).
  - PHP in Upload-Ordnern: Nextcloud-Datenordner werden nicht mehr durchsucht, leere Platzhalter
    („Silence is golden“) zählen nicht.
  - Archive in Plugin-/App-Ordnern (z. B. Nextcloud recognize) nur noch NIEDRIG; Roundcube-SQL-Schemas ignoriert.
  - Apache-Statusseite: „Require local“ wird erkannt – ubusec prüft vom Server selbst aus, deshalb war sie
    fälschlich als öffentlich gemeldet.
  - DNS: Hostnamen-Domains von Server-Anbietern (z. B. netcup ultrasrv.de) werden nicht geprüft; fehlendes CAA
    wird je Domain einmal gemeldet statt für jede Subdomain.
  - CVE: Die OVAL-Bestandsprüfung („Check that Ubuntu … is installed“) ist keine Sicherheitsmeldung mehr; veraltete
    CVE-Daten werden nicht gemeldet, wenn der CVE-Bereich sie im selben Scan ohnehin neu lädt.
  - Datei-Integrität: Datendateien von rkhunter (rkhunter --update) zählen nicht als Veränderung.
  - Neue bzw. passendere Hinweise: rpcbind/FTP bei öffentlichen Ports, BIND-Version, SMTP-Banner, Content-Security-Policy.

## 1.4.3 – 2026-11-02

- **Empfehlungen herunterladen:** Auf der Seite „Empfehlungen“ lassen sich alle offenen Punkte samt Begründung und
  Behebung als HTML (zum Lesen und Drucken), als CSV-Tabelle (mit Spalte „Erledigt“ zum Abhaken in Excel/LibreOffice)
  oder als Markdown-Text herunterladen; inklusive der Härtungsvorschläge von Lynis.
- rkhunter-Warnung „Suspicious file types found in /dev“ wird überprüft: Dateien in /dev/shm, die nur bekannte Dienste
  als gemeinsamen Speicher nutzen (z. B. Apache: ShM.<Prüfsumme>, PostgreSQL, PHP-FPM, Collabora), erscheinen als
  erkannter Fehlalarm; Programmdateien oder unbekannte Nutzer bleiben ein Befund.
- Lynis-Test CRYP-7902 (Ablauf von Zertifikatsdateien) wird übersprungen (Eintrag in /etc/lynis/custom.prf): Er folgt
  symbolischen Links und durchsuchte auf Virtualmin-Servern stundenlang Web- und Datenordner. Die Zertifikate der
  Domains prüft ubusec im Bereich „Websites & Domains“.
- Lynis-Audit mit Zeitlimit (Standard 45 Minuten, LYNIS_TIMEOUT in ubusec.conf); bei Überschreitung wird der
  hängende Test gemeldet und der Scan läuft weiter.
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
