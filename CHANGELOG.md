# Änderungen

Alle nennenswerten Änderungen an ubusec. Versionen folgen dem Schema MAJOR.MINOR.PATCH.

## 1.5.14 – 2026-11-10

- **Linux Malware Detect durchsuchte die Websites gar nicht:** Bis 1.5.12 übergab ubusec die Ordner als
  Komma-Liste („/var/www,/home“), die maldet nicht versteht – es durchsuchte dadurch nur seine Zusatzordner /tmp,
  /var/tmp und /dev/shm, darunter die Zehntausenden Dateien, die Collabora Online in /tmp entpackt (Laufzeit über
  2 Stunden). Seit 1.5.13 wird jeder Ordner einzeln übergeben; jetzt lässt maldet außerdem /tmp aus (prüft ClamAV)
  und übernimmt die Ausnahmen des Virenscans (Nextcloud-Daten, Backups, Datenbanken …).
- **Linux Malware Detect übernimmt die Einstellung „Parallele Prüfungen“** (dort höchstens 8 gleichzeitige Prüfungen;
  „Automatisch“ überlässt die Wahl maldet: 2 je Prozessorkern, höchstens 8). Läuft der ClamAV-Dienst, nutzt maldet ihn
  für seinen ClamAV-Teil ohnehin selbst.

## 1.5.13 – 2026-11-10

- **Schritt „Webshells & Web-Malware“ zeigt Fortschritt und ist im Schnellscan deutlich schneller:** Die Weboberfläche
  zeigt jetzt, was gerade passiert („Suche Webshell-Muster in PHP-Dateien – 12 000 von 48 000 Dateien“ mit
  geschätzter Restzeit; „Linux Malware Detect … – läuft seit 4 Min.“). Linux Malware Detect prüft im Schnellscan nur
  noch Dateien, die in den letzten 2 Tagen geändert wurden (maldet -r); alles durchsucht es im Vollscan.

## 1.5.12 – 2026-11-10

- **Fehlalarm behoben:** ClamAV meldete die Signaturdatei von Linux Malware Detect
  (`/usr/local/maldetect/sigs/rfxn.yara`) als „Html.Downloader.Satan…“ – Signaturdateien enthalten absichtlich
  Schadcode-Muster. Signatur-, Quarantäne- und Arbeitsordner von Linux Malware Detect, rkhunter und chkrootkit
  werden beim Virenscan jetzt ausgelassen.

## 1.5.11 – 2026-11-10

- **„Soll ich das für dich prüfen?“ bei verdächtigen PHP-Dateien vergleicht jetzt mit dem Original.** Findet ubusec
  Webshell-Muster (z. B. `system($_GET`), holt es dieselbe Datei in derselben Version aus der Quelle der Anwendung –
  Mautic von GitHub, WordPress-Kern und -Plugins von wordpress.org – und vergleicht Byte für Byte. Identisch heißt:
  Teil der Anwendung (meist Testdaten), „Alles in Ordnung“ mit Ausblenden-Knopf. Bisher meldete die Prüfung solche
  Testdateien als „Abweichung gefunden“ und bot kein Ausblenden an. In Test-Ordnern ohne abrufbares Original lautet
  das Ergebnis „nicht eindeutig“ statt Alarm.

## 1.5.10 – 2026-11-10

- **Lynis „Multiple accounts found with same UID“ [AUTH-9208] verständlich:** ubusec sieht selbst nach, welche Konten
  sich eine UID teilen. Virtualmin-Webzugänge einer Domain (Heimatordner im Ordner des Domain-Besitzers, keine echte
  Shell, z. B. `frenzel@domain` mit /bin/false) gelten als in Ordnung und erscheinen nur noch als Info. Andere Fälle
  meldet ubusec als „Mehrere Benutzerkonten mit derselben UID“ mit den Kontonamen und einer Anleitung – UID 0 immer.
- **KI-Fassung und Downloads genauer:** Bei langen Listen, die ubusec schon beim Scan kürzt (z. B. offene
  Sicherheitsmeldungen), fehlte in den Exporten der Hinweis „… und N weitere“. Benutzernamen werden nicht mehr in
  Webadressen ersetzt – ein Systembenutzer „ubuntu“ machte aus ubuntu.com/pro „benutzer-1.com/pro“.
- **sudo ohne Passwort:** Die Meldung nennt jetzt die Datei (z. B. `/etc/sudoers.d/90-cloud-init-users`); der
  Hinweis erklärt den Cloud-Standardbenutzer und wie man ihn gefahrlos sperrt.
- **WPScan: weniger Fehlalarme bei Lücken „noch ohne Fix“.** WPScan nennt den betroffenen Bereich dann oft nur im Titel
  („Add From Server <= 3.3.3 – …“). ubusec wertet diese Angabe jetzt aus: Ist die installierte Version neuer, wird die
  Lücke nicht mehr gemeldet.
- Lynis-Vorschläge ohne umsetzbaren Zielwert („Port (set 22 to )“) und „debsums installieren“ (ubusec prüft Pakete
  selbst) werden nicht mehr aufgeführt.

## 1.5.9 – 2026-11-09

- **Update/Installation bricht nicht mehr ab, wenn gerade ein anderes apt läuft** (z. B. die automatischen
  Sicherheitsupdates): ubusec wartet bis zu 5 Minuten auf die Paketverwaltung statt mit „Could not get lock
  /var/lib/dpkg/lock-frontend“ abzubrechen. Bereits installierte Pakete der Weboberfläche werden nicht erneut
  angefordert.
- **WPScan schont das Tageskontingent** (kostenlos 25 Abfragen am Tag): Jedes Plugin wird höchstens einmal am Tag
  abgefragt, über alle Scans eines Tages hinweg höchstens 22-mal (Reserve für eigene Abfragen). Weitere Scans am
  selben Tag nutzen das gespeicherte Ergebnis (bis 14 Tage alt). Bei vielen Plugins kommen nie geprüfte zuerst und
  dann die ältesten an die Reihe. Meldet WPScan das Limit oder lehnt das Token ab, fragt ubusec an diesem Tag nicht
  mehr. Die Einstellungen zeigen „Heute genutzt: x von 22“; neuer Knopf „WordPress-Plugins jetzt bei WPScan prüfen“.

## 1.5.8 – 2026-11-09

- **Fehler behoben:** Bei „Archive in Plugin-/App-Ordnern öffentlich abrufbar“ bot ubusec „Jetzt ändern“ an, lehnte
  dann aber ab („verschiebt ubusec nicht automatisch“). Verschieben wäre auch falsch: Themes wie Impreza installieren
  ihre Zusatz-Plugins aus diesen ZIP-Dateien. Neu ist stattdessen „Archive in diesem Ordner für das Web sperren“ – eine
  `.htaccess` im Ordner verhindert den Abruf über die Website, die Datei bleibt liegen. Mit Prüfung der Website
  danach und „Rückgängig machen“.
- **PHP-Einstellungen nur für installierte Versionen prüfen:** `php.ini`-Dateien entfernter PHP-Versionen (z. B.
  Virtualmins `etc/php7.4` je Domain oder `/etc/php/7.4` nach `apt remove`) lösen keine Meldungen wie „Session-Cookies
  ohne HttpOnly“ mehr aus und werden nicht mehr zum Ändern angeboten. Stattdessen nennt ubusec sie als
  „Überbleibsel“ mit den installierten Versionen und einer Anleitung zum Aufräumen.
- **„HTTPS nicht erreichbar“ nur noch, wenn es stimmt:** Klappt die verschlüsselte Verbindung, aber die Startseite
  antwortet nicht innerhalb von 8 Sekunden, fragt ubusec ein zweites Mal mit 45 Sekunden nach. Antwortet sie dann,
  heißt es „Startseite antwortet sehr langsam“ (NIEDRIG, mit Sekunden); sonst „Startseite antwortet über HTTPS
  nicht“ (MITTEL) mit dem Grund (z. B. Zeitüberschreitung) und Hinweisen zu Cache und zu Wordfence/fail2ban, die die
  Prüfanfragen des Servers sperren können.

## 1.5.7 – 2026-11-09

- **Klarere Knöpfe nach „Soll ich das für dich prüfen?“:** Unter dem Ergebnis steht jetzt „Was jetzt?“ mit genau einer
  Empfehlung. Ist alles in Ordnung (Fehlalarm), wird „Als Fehlalarm ausblenden“ hervorgehoben (bei Baseline-Befunden:
  „Baseline übernehmen“), „Bereich neu scannen“ und der Notfallkasten entfallen. Bei einer echten Abweichung gibt es
  keinen Ausblenden-Knopf. „Erneut prüfen“ heißt jetzt „Prüfung wiederholen“, „Nach dem Beheben erneut prüfen“ heißt
  „Bereich neu scannen (nach dem Beheben)“ – mit kurzer Erklärung, wann man welchen Knopf braucht.
- Copyright-Vermerk mit Link zur Lizenz unten in der Navigationsleiste.

## 1.5.6 – 2026-11-09

- **Fehler behoben:** Ein Scan brach mit „msg: unbound variable“ ab, wenn rkhunter zuvor eine Warnung gemeldet hatte.
  Die chkrootkit-Auswertung übernahm dann die Schwere aus dem rkhunter-Teil (bash behält beim zweiten `local` in
  derselben Funktion den alten Wert). Die Variablen werden jetzt ausdrücklich geleert.
- **Updates sicherer:** ubusec und seine Prüfskripte werden jetzt atomar ersetzt (neue Datei, dann umbenennen). Ein
  Scan, der während `ubusec --update` läuft, arbeitet so in jedem Fall mit der alten Fassung zu Ende.

## 1.5.5 – 2026-11-09

- **Fehler behoben:** „Linux Malware Detect installieren“ nutzte eine falsche Download-Adresse. Richtig ist
  `https://www.rfxn.com/downloads/maldetect-current.tar.gz` (laut rfxn.com). Zusätzlich wird die von rfxn.com
  veröffentlichte MD5-Prüfsumme abgeglichen; stimmt sie nicht, wird nicht installiert.

## 1.5.4 – 2026-11-08

- **Fehler behoben:** Während AIDE seine Datenbank anlegt, meldete die Seite „Werkzeuge“ fälschlich „abgebrochen“.
  Ursache: systemd ersetzt `$$` in der Befehlszeile durch `$`, dadurch stand statt der Prozessnummer nur „$“ in
  `aide-init.running`. Die Nummer wird jetzt von ubusec selbst eingetragen. Damit greift auch der Schutz vor einem
  zweiten gleichzeitigen Start, und Scans erkennen die laufende Einrichtung wieder.

## 1.5.3 – 2026-11-08

- **Werkzeuge: sichtbare Rückmeldung.** Nach „AIDE installieren“, „Linux Malware Detect installieren“, „Werkzeuge
  aktualisieren“ und „Lynis-Paketquelle einrichten“ zeigt die Seite einen Tag lang, ob es geklappt hat (bei Fehlern
  mit geöffnetem Protokoll).
- **AIDE einrichten: Fortschritt live.** Während die Datenbank angelegt wird, steht dort „läuft seit … Min.“ (die Seite
  aktualisiert sich alle 30 Sekunden), danach „AIDE ist eingerichtet“ mit Dauer und Größe – oder der Fehler mit
  Protokoll, auch wenn der Vorgang z. B. durch einen Neustart abgebrochen wurde. Der Knopf „AIDE einrichten“
  verschwindet, solange es läuft; ein zweiter Start wird abgefangen. Am Ende wird die Werkzeugliste neu geprüft.

## 1.5.2 – 2026-11-08

- **Neutrale Beispiele:** Anleitung „SSH-Schlüssel“ (Weboberfläche und `ubusec --ssh-help`): Beispielnamen neutral (mein-laptop, mein-mac,
  mein-ipad); der Servername wird weiterhin automatisch vom jeweiligen Server eingesetzt. README: Beispiel-Benutzer „anna“.

## 1.5.1 – 2026-11-08

- **Fehler behoben:** „KI-Fassung herunterladen“ und „Zuordnung der Platzhalter“ brachen mit „Internal Server Error“
  ab. Die Weboberfläche läuft abgeschottet (ProtectHome) und darf /home nicht lesen; die Benutzernamen kommen jetzt
  nur aus /etc/passwd.
- **Empfehlungen als Excel-Datei (.xlsx)** statt CSV: Kopfzeile fixiert, Filter in jeder Spalte, Farben je Schwere,
  Zeilenumbrüche in den Zellen, Spalte „Status“ mit Auswahlliste (offen, in Arbeit, erledigt, ignoriert) – „erledigt“
  färbt die Zeile grün und streicht sie durch –, Spalte „Notiz“, Lynis-Vorschläge auf einem eigenen Blatt, druckfertig
  im Querformat. Ohne Zusatzpakete erzeugt; öffnet in Excel, LibreOffice und Numbers.
- **SSH-Passwort-Anmeldung genauer bewertet:** Ist root schon auf Schlüssel umgestellt, meldet ubusec nur noch
  NIEDRIG „Passwort-Anmeldung für andere Benutzer aktiv“ und nennt die Benutzer, die sich noch mit Passwort anmelden
  können (Passwort gesetzt und Login-Shell). Gibt es keine, entfällt die Meldung.

## 1.5.0 – 2026-11-08

- **SSH-Schlüssel einrichten, ohne sich auszusperren:** neue Seite „SSH-Schlüssel“ (Einstellungen bzw. Knopf am
  Befund „Root-Login mit Passwort“) mit Anleitung für Windows, Mac, Linux, WebSSH und PuTTY – ein Schlüssel pro Gerät,
  neue Geräte hinzufügen, verlorene entfernen, Notfallzugang über die Konsole des Anbieters oder Webmin. Öffentliche
  Schlüssel lassen sich dort eintragen und entfernen (private werden erkannt und abgewiesen, PuTTY-Format wird
  umgewandelt, vorher wird gesichert). ubusec zeigt die letzten Anmeldungen als root mit dem benutzten Schlüssel und
  stellt erst dann auf `PermitRootLogin prohibit-password` um, wenn eine Schlüssel-Anmeldung als root geklappt hat;
  der letzte Schlüssel kann danach nicht versehentlich entfernt werden. Im Terminal: `ubusec --ssh-help`.
- **chkrootkit-Meldungen einzeln bewertet** statt als Rohliste: versteckte Dateien aus unveränderten Ubuntu-Paketen →
  harmlos; „Linux.Xor.DDoS“ für Collabora in /tmp → per AppImage-Prüfsumme bzw. byte-genauem Vergleich der
  Systemvorlage bestätigt; „BPFDoor“ und „Packet Sniffer“ → Programm des Prozesses wird mit dem frisch geladenen
  Ubuntu-Paket verglichen (z. B. systemd-networkd). Nur Unerklärtes bleibt ein Befund – mit Prüfen-Knopf und Hinweis.
- Prüfung „Automatische Sicherheitsupdates“: erkennt auch Werte wie „1d“ oder „always“, prüft zusätzlich den
  systemd-Timer apt-daily-upgrade und nennt im Befund den genauen Grund (Paket fehlt, Schalter in 20auto-upgrades
  aus oder nicht gesetzt, Timer abgeschaltet).
- **AIDE und Linux Malware Detect per Knopfdruck:** Die Seite „Werkzeuge“ erklärt Nutzen und Aufwand und bietet
  „installieren“ bzw. „einrichten“ an. AIDE bekommt Ausnahmen für große Datenordner (Nextcloud-Daten, Postfächer,
  Datenbanken, Protokolle, Sicherungen) und legt seine Datenbank im Hintergrund mit niedriger Priorität an; geprüft
  wird beim Vollscan. Linux Malware Detect wird von rfxn.com installiert und so eingestellt, dass es keinen eigenen
  täglichen Scan startet, nichts automatisch in Quarantäne verschiebt und Nextcloud-Daten auslässt.
- Webshell-Muster in Testcode von Anwendungen (Ordner Tests/ bzw. tests/, z. B. bei Mautic) werden getrennt und als
  MITTEL gemeldet statt HOCH; „Jetzt prüfen“ zeigt die gefundenen Befehle.
- **PHP-Dateien in Upload-Ordnern** genauer: Programmcode-Ordner, die zufällig images/, media/ oder files/ heißen
  (Plugins, Themes, vendor, Nextcloud-Apps, Mautic), zählen nicht mehr; von Plugins erzeugte Dateien (MailPoet-
  Vorlagen-Cache, Matomo-Konfiguration) und Dateien mit Zugriffsschutz in der ersten Zeile werden als harmlos
  erkannt; ist die PHP-Ausführung per .htaccess gesperrt, ist der Befund nur MITTEL.
  Neu im Befund: „Auf Schadcode prüfen“ (Webshell-Muster und Virenscanner je Datei), „In die Sicherung verschieben“
  und „PHP-Ausführung im Upload-Ordner sperren“.
- Neue Korrektur auf Knopfdruck: Sticky-Bit für Verzeichnisse setzen, die für alle beschreibbar sind (z. B.
  /var/fcgiwrap von Virtualmin).
- **Baseline direkt im Befund übernehmen:** Bei Baseline-Meldungen (z. B. „Neue Benutzerkonten“) steht der Knopf
  „Baseline übernehmen“ jetzt im Befund selbst; danach prüft ubusec den Bereich „Baseline“ sofort neu, sodass die
  Meldungen gleich verschwinden.
- Fehlalarm behoben: .pem-Dateien gelten nur noch als Zugangsdaten, wenn sie einen privaten Schlüssel enthalten
  (z. B. ist cacert.pem von UpdraftPlus nur die öffentliche Liste der Zertifizierungsstellen).
- **Berichte löschen:** einzeln (samt Rohdaten) oder alle auf einmal unter „Berichte“.
- **Empfehlungen neu beginnen:** Übersicht und Empfehlungen berücksichtigen danach nur Scans ab diesem Zeitpunkt,
  alle Punkte gelten wieder als „neu“; die Berichte bleiben erhalten. Beides ist während eines laufenden Scans gesperrt
  und steht im Protokoll.
- **Schnellscan prüft nur geänderte Dateien:** Nach dem ersten vollständigen Virenscan prüft der tägliche Schnellscan
  alle seither neuen oder geänderten Dateien im ganzen System (maßgeblich ist die vom Dateisystem gesetzte ctime, die
  sich nicht zurückdatieren lässt) – statt nur einiger Ordner und meist in wenigen Minuten. Der Vollscan prüft
  weiterhin jede Datei mit den neuesten Signaturen. Bei einem Fund rückt der Ausgangspunkt nicht vor, die Datei wird
  also bei jedem Schnellscan erneut gemeldet. Hinweis, wenn der letzte Vollscan länger als 10 Tage zurückliegt.
  Abschaltbar unter Einstellungen → Scan-Einstellungen.

## 1.4.4 – 2026-11-02

- **„Soll ubusec das für dich ändern?“** – Korrekturen auf Knopfdruck für eindeutig umsetzbare Punkte:
  wp-config.php schützen (chmod 640), Datei-Editor abschalten (DISALLOW_FILE_EDIT), PHP im Upload-Ordner sperren,
  xmlrpc.php sperren (ganz oben in der .htaccess, außerhalb der Blöcke von WordPress und Wordfence), rpcbind
  abschalten (nur ohne NFS), Kernel-Parameter härten (/etc/sysctl.d/99-ubusec.conf, ohne IP-Weiterleitung),
  SSH X11Forwarding aus und MaxAuthTries 4 (Drop-in, mit sshd -t geprüft), Postfix-Banner und VRFY, BIND-Version
  verbergen, php.ini (session.cookie_httponly, expose_php), phpinfo-Dateien, .DS_Store, mitgelieferte Archive in
  WordPress-Plugins und den Roundcube-Installer in die Sicherung verschieben. Vor jeder Änderung wird gesichert; Besitzer und Rechte bleiben erhalten; wp-config.php
  wird mit php -l geprüft; nach Website-Änderungen ruft ubusec die Startseite auf und nimmt die Änderung bei einem
  Serverfehler sofort selbst zurück. Jede Änderung lässt sich mit „Rückgängig machen“ zurücknehmen und steht im
  Protokoll. SSH- und Firewall-Änderungen gibt es bewusst nicht per Knopfdruck (Gefahr, sich auszusperren).
- **„Soll ubusec das für dich prüfen?“** – Nachprüfung auf Knopfdruck direkt im Befund (nur lesend, läuft als root
  über die geprüfte Steuer-Warteschlange):
  - chkrootkit „INFECTED“ und veränderte Paketdateien: Vergleich mit dem frisch geladenen Ubuntu-Originalpaket,
  - Dateien in /tmp, /dev/shm und versteckte Dateien: Steckbrief mit Art, Besitzer, Datum, Prüfsumme, Paket und
    nutzenden Prozessen,
  - öffentliche Ports und Bindshell-Warnungen: welches Programm lauscht, aus welchem Paket, öffentlich oder lokal.
  Das Ergebnis erscheint im Befund (✓ / ! / ✗) und bleibt für spätere Berichte erhalten.
- **chkrootkit „INFECTED“ bei Systemprogrammen** (z. B. basename, date, ls – häufig mit den Rust-Coreutils von Ubuntu
  25.10/26.04): ubusec lädt das Paket in der installierten Version frisch von Ubuntu und vergleicht die Programme
  byte-genau. Identisch → als Fehlalarm erkannt (INFO); abweichend → KRITISCH; ohne Verbindung → Abgleich mit der
  lokalen Paketprüfsumme (MITTEL).
- **Empfehlungen nach Aufwand:** Jeder Punkt zeigt seinen Aufwand; die Liste lässt sich „schnell erledigt zuerst“
  ordnen und nach Aufwand filtern (bis 5 Min, bis 30 Min, länger, erst prüfen). Die Auswahl wird gemerkt.
- **Ohne Ubuntu Pro:** Neuer Befund listet die Pakete, die Sicherheitskorrekturen nur über Ubuntu Pro (ESM) erhalten,
  mit dem Grund, warum sie installiert sind; der Hinweis erklärt die Wege mit und ohne Pro.
- **WordPress:** Befunde enthalten jetzt die konkreten Befehle bzw. Dateien für jede Website (chmod für wp-config.php,
  DISALLOW_FILE_EDIT, .htaccess für Uploads und xmlrpc.php, mit WP-CLI auch Plugin-Updates) – mit Kopieren-Knopf.
- **Öffentliche Ports:** konkreter Vorschlag je Dienst (z. B. rpcbind abschalten, FTP durch SFTP ersetzen).
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
