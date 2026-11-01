# ubusec – Sicherheitsprüfung für Ubuntu-Server

[Releases](https://github.com/chrismey-71/ubusec/releases) · [Änderungen](CHANGELOG.md) · Lizenz: MIT

ubusec bündelt bewährte Open-Source-Werkzeuge und fasst ihre Ergebnisse zu **einem knappen
Bericht** mit Schweregraden zusammen – auf der Kommandozeile, als Text/HTML/JSON und in einer
**Weboberfläche** mit Login, Scan-Start, Berichten und Verbesserungshinweisen.

| Bereich | Was geprüft wird | Werkzeuge |
|---|---|---|
| Prüfwerkzeuge | Versionen und Updates der eingesetzten Werkzeuge, Alter von Virensignaturen und CVE-Daten, neue ubusec-Version | apt, GitHub |
| Updates | ausstehende (Sicherheits-)Updates, Neustart, veralteter Kernel, Dienste mit alten Bibliotheken, unattended-upgrades, End-of-Life | apt, needrestart, distro-info |
| CVE | bekannte Lücken installierter Pakete mit verfügbarem Fix | OpenSCAP + Ubuntu-OVAL (Canonical) |
| Konfiguration | Härtungsaudit, SSH, Kernel-Parameter, UID-0-Konten, leere Passwörter, sudo, AppArmor, fail2ban | Lynis + eigene Prüfungen |
| Berechtigungen | kritische Dateien, world-writable, verwaiste Dateien, SUID ohne Paket, Home-Ordner | eigene Prüfungen |
| Firewall | aktive Firewall, Default-Policy, IPv6, offene und riskante Ports | ss, ufw, nft, iptables |
| Integrität | veränderte Programmdateien, optional AIDE | dpkg --verify, AIDE |
| Baseline | neu seit Baseline: Benutzer, sudo-Regeln, SSH-Schlüssel, Ports, Cronjobs, Dienste, SUID | eigene Prüfungen |
| Rootkits | Rootkits, versteckte Prozesse, LD_PRELOAD, Prozesse aus /tmp, Cryptominer, verdächtige Autostarts | rkhunter, chkrootkit, unhide + Heuristiken |
| Malware | Viren, Trojaner – parallel auf mehreren Kernen, mit einstellbaren Ausnahmen | ClamAV |
| Web | Webshells, PHP in Upload-Ordnern | eigene Signaturen, optional Linux Malware Detect |
| **Websites & Domains** | alle Domains aus Virtualmin: HTTPS und Zertifikatsablauf, alte TLS-Versionen, Weiterleitung auf HTTPS, Sicherheits-Header (HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy), Versionsangaben, offene Dateien (`.git`, `.env`, Backups, Datenbank-Dumps, phpinfo, Source-Maps), Verzeichnislisten, SPF, DMARC, CAA, Apache-Einstellungen | eigene Prüfungen, dig, optional testssl.sh |
| **Webanwendungen** | WordPress (Version, Plugins, Themes, Debug, Datei-Editor, xmlrpc, Benutzer-Auslesen, Upload-Ordner), Nextcloud (Version/Support, Updates, Datenverzeichnis), Mautic, Roundcube (Sicherheitsupdates, Installer, Protokolle), eigene PHP-Apps (MySQL-root, SQL-Injection- und XSS-Muster, Backups im Webordner), PHP-Versionen und php.ini, MySQL/MariaDB-Konten | eigene Prüfungen, wordpress.org, endoflife.date, GitHub, optional WPScan |

## Installation

Neueste Version unter [Releases](https://github.com/chrismey-71/ubusec/releases) – Paket und Prüfsumme laden,
prüfen und installieren (Versionsnummer anpassen):

```bash
VER=1.4.2
curl -fLO https://github.com/chrismey-71/ubusec/releases/download/v$VER/ubusec-$VER.tar.gz
curl -fLO https://github.com/chrismey-71/ubusec/releases/download/v$VER/SHA256SUMS
sha256sum -c SHA256SUMS
tar xzf ubusec-$VER.tar.gz && cd ubusec
sudo ./ubusec --install --with-web      # optional zusätzlich: --with-aide
```

Das installiert die Werkzeuge, richtet die Zeitpläne ein (Schnellscan Mo–Sa, Vollscan sonntags,
jeweils 03:17), legt die Baseline an und fragt nach einem Benutzer für die Weboberfläche
(mit Zwei-Faktor-Anmeldung per Authenticator-App). Danach:

Danach in der Weboberfläche unter **Einstellungen** E-Mail oder ntfy eintragen und den ersten
**Vollscan** starten (oder `sudo ubusec --full`).

## Aktualisieren

Ab Version 1.4 genügt auf dem Server:

```bash
sudo ubusec --update
```

ubusec fragt GitHub nach der neuesten Version, zeigt die Änderungen, lädt das Paket, prüft die
SHA256-Prüfsumme und installiert es nach Rückfrage. Einstellungen, Benutzer, Berichte und Baseline bleiben
erhalten. Die Weboberfläche weist auf neue Versionen hin (Seitenleiste und Seite „Werkzeuge“), spielt sie
aber bewusst nie selbst ein. Von älteren Versionen: Paket wie oben laden und denselben
Installationsbefehl ausführen.

## Prüfwerkzeuge aktuell halten

Die Seite **Werkzeuge** zeigt für jedes Prüfwerkzeug Version, verfügbare Updates und das Alter der
Signaturen bzw. Prüfdaten. „Werkzeuge aktualisieren“ spielt Updates nur für ubusecs eigene Werkzeuge ein
und holt neue Virensignaturen (`sudo ubusec --update-tools`). Ubuntu liefert Lynis oft in einer alten
Version; „Lynis-Paketquelle des Herstellers einrichten“ (`sudo ubusec --lynis-upstream`) bindet die
offizielle Paketquelle von CISOfy ein – der Schlüssel gilt dabei nur für diese Quelle.

Virensignaturen aktualisiert der Dienst `clamav-freshclam` mehrmals täglich, die CVE-Daten lädt ubusec
selbst, sobald sie älter als 10 Stunden sind. Veraltete Daten meldet der Bereich „Prüfwerkzeuge“.

Ohne `--with-web` gibt es nur die Kommandozeile; die Weboberfläche lässt sich später mit
demselben Befehl nachrüsten.

## Weboberfläche aufrufen

Die Oberfläche lauscht aus Sicherheitsgründen **nur auf 127.0.0.1:8765** des Servers.
Zwei Wege, sie zu erreichen:

**A) SSH-Tunnel (am sichersten, ohne weitere Einrichtung)**

```bash
ssh -L 8765:127.0.0.1:8765 benutzer@dein-server
```
Dann im Browser auf deinem Rechner: http://127.0.0.1:8765

**B) Eigene Subdomain mit HTTPS über Apache (z. B. in Virtualmin)**

1. In Virtualmin eine Subdomain anlegen, etwa `ubusec.deinedomain.at`, und ein Let's-Encrypt-Zertifikat dafür ausstellen.
2. In der SSL-Konfiguration dieser Subdomain (Virtualmin: *Web Configuration → Edit Directives*) ergänzen:
   ```apache
   ProxyPreserveHost On
   ProxyPass        / http://127.0.0.1:8765/
   ProxyPassReverse / http://127.0.0.1:8765/
   RequestHeader set X-Forwarded-Proto "https"
   # dringend empfohlen: nur deine eigenen IP-Adressen zulassen
   <Location />
     Require ip 203.0.113.10
   </Location>
   ```
   (Module bei Bedarf aktivieren: `sudo a2enmod proxy proxy_http headers`)
3. In `/etc/ubusec/web.conf` setzen: `SECURE_COOKIES=1` und `TRUST_PROXY=1`, dann
   `sudo systemctl restart ubusec-web`.

Nginx entsprechend: `proxy_pass http://127.0.0.1:8765;` plus
`proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` und `X-Forwarded-Proto $scheme`.

## Was die Weboberfläche kann

- **Übersicht:** Gesamturteil in einem Satz, Befundleiste (ein Feld pro offenem Problem), Sicherheitswert, die fünf wichtigsten Punkte, Verlauf, geplante und letzte Scans.
- **Scan starten:** Schnellscan, Vollscan oder ausgewählte Bereiche – mit Live-Fortschritt. Der Scan läuft weiter, wenn du die Seite schließt, und lässt sich mit „Scan abbrechen“ jederzeit stoppen.
- **Berichte:** alle Scans mit Filter nach Schweregrad und „nur neue“, Download als Text/HTML/JSON, Einsicht in die Rohausgaben jedes Werkzeugs.
- **Empfehlungen:** alle offenen Punkte, nach Dringlichkeit gruppiert. Zu jedem Punkt: warum er wichtig ist, konkrete Schritte mit kopierbaren Befehlen, Aufwand, bei Einbruchsverdacht ein Notfallplan.
- Aktionen: Bereich nach einer Korrektur **erneut prüfen**, geprüfte Fehlalarme **ausblenden**, Änderungen als neue **Baseline übernehmen**.

## Einstellungen in der Weboberfläche

- **Mein Konto:** Passwort ändern (andere Sitzungen werden dabei abgemeldet), Zwei-Faktor einrichten, neu einrichten oder ausschalten.
- **Benutzer:** weitere Benutzer anlegen und löschen.
- **Geplante Scans:** Schnell- und Vollscan ein-/ausschalten, Wochentage und Uhrzeit wählen.
- **Benachrichtigungen:** E-Mail und/oder ntfy-Push, ab welcher Schwere, nur bei neuen Meldungen, Testnachricht.
- **Scan-Einstellungen:** Aufbewahrung der Berichte; beim Virenscan Ordner, maximale Dateigröße, Anzahl paralleler Prozesse und Ausnahmen (Datenbanken, Backups, Protokolle, Postfächer, Nextcloud-Datenordner, eigene Ordner); Webverzeichnisse, Domains ausschließen oder ergänzen, gründliche TLS-Prüfung, WPScan-Token.
- **Fehlalarme:** ausgeblendete Meldungen ansehen und wieder einblenden.
- **Protokoll:** letzte Anmeldungen (auch fehlgeschlagene) und alle Aktionen über die Weboberfläche.

Für E-Mails braucht der Server ein Mailprogramm (`sudo apt install bsd-mailx`; bei Virtualmin
mit Postfix ist das meist schon da). Für Push-Nachrichten die kostenlose App **ntfy** installieren
und einen schwer erratbaren Themennamen abonnieren.

## Benutzer verwalten

```bash
sudo ubusec --web-user christian --totp   # anlegen oder Passwort ändern, mit 2-Faktor
sudo ubusec --web-user-del christian
```

## Kommandozeile

```bash
sudo ubusec                     # Schnellscan
sudo ubusec --full              # Vollscan
sudo ubusec --only cve,rootkit  # gezielt
sudo ubusec --last              # letzten Bericht anzeigen
sudo ubusec --accept            # nach Prüfung: aktuellen Zustand als Baseline übernehmen
sudo ubusec --help
```

Exit-Code: 0 = ok/Info, 1 = Niedrig/Mittel, 2 = Hoch, 3 = Kritisch.

## Wie die Weboberfläche abgesichert ist

- Sie läuft als eigener **Systembenutzer `ubusec` ohne Root-Rechte**, in einer abgeschotteten systemd-Umgebung (nur Lesezugriff aufs System, Schreibzugriff einzig auf die Auftragswarteschlange).
- Ein Scan-Start oder eine Einstellungsänderung legt nur eine **Auftragsdatei** ab (Scans: `ubusec-queue.path`, Einstellungen: `ubusec-ctl.path`, sofort). root führt sie über `ubusec-queue.path` aus, nachdem er sie in einen eigenen Ordner verschoben und streng geprüft hat. Erlaubt sind nur bekannte Aktionen, Modi und Bereiche; alles andere wird abgewiesen und in `/var/log/ubusec/web-audit.log` protokolliert.
- Einstellungen werden von root gegen feste Regeln geprüft und sicher gequotet in `/etc/ubusec/settings.conf` geschrieben; unbekannte Schlüssel oder ungültige Werte werden abgewiesen.
- Passwörter werden mit **scrypt** gespeichert. Optionale **Zwei-Faktor-Anmeldung** (TOTP), Codes sind nicht wiederverwendbar.
- **Sperre nach 5 Fehlversuchen** für 15 Minuten pro IP-Adresse, automatische Abmeldung nach 30 Minuten Inaktivität.
- CSRF-Schutz für alle Aktionen, strikte Content-Security-Policy, Cookies HttpOnly und SameSite=Strict.
- Keine externen Ressourcen: Schriften und Skripte liegen lokal, die Oberfläche meldet nichts nach außen.

Hinter einem Reverse-Proxy unbedingt `TRUST_PROXY=1` setzen – sonst sieht die Fehlversuch-Sperre alle Besucher als 127.0.0.1 und sperrt im Zweifel alle gemeinsam.

## Virenscan: Geschwindigkeit und Ausnahmen

ubusec erstellt zuerst eine Liste aller zu prüfenden Dateien und prüft sie dann auf einem von zwei Wegen:

- **Über den ClamAV-Dienst (clamd)**, wenn er ohnehin läuft – etwa für den Virenfilter von Virtualmin oder
  für Nextcloud „Antivirus for files“. Die Virensignaturen liegen dann nur einmal im Speicher, der Scan
  braucht kaum zusätzlichen Arbeitsspeicher. „Automatisch“ nutzt höchstens die Hälfte der Kerne (maximal 4),
  damit der Dienst eingehende Mails und Uploads weiter zügig prüft. Antwortet der Dienst während des Scans
  nicht mehr, werden die restlichen Dateien mit clamscan geprüft; Dateien, die der Dienst nicht lesen darf,
  ebenso.
- **Mit eigenen clamscan-Prozessen**, wenn kein Dienst läuft (oder in den Einstellungen so gewählt). Jeder
  Prozess nutzt einen Prozessorkern und etwa 1,4 GB Arbeitsspeicher; „Automatisch“ wählt die Anzahl passend
  zu Kernen, freiem Speicher und Speichergrenze (höchstens 6).

Alle Prüfungen laufen mit niedrigster Priorität, Websites haben immer Vorrang.

Die Scan-Dienste dürfen höchstens 40 % des Arbeitsspeichers belegen – mindestens aber 2,5 GB, damit ein
clamscan-Prozess sicher hineinpasst, und höchstens 75 %. Sie weichen nie in den Swap aus. Wird der Speicher
knapp, trifft es den Scanner und nicht Webserver oder Datenbank; ein vom System beendeter Teilprozess bricht
den Scan nicht ab, seine Dateien werden danach einzeln nachgeholt. Die Einstellungen zeigen die Grenze und
wie viele clamscan-Prozesse hineinpassen. Die Grenze wird bei der Installation berechnet – nach einer
Änderung des Arbeitsspeichers `sudo ubusec --install` erneut ausführen.

Die Fortschrittsanzeige zeigt „Datei X von Y“, die geschätzte Restzeit und den Ordner, der gerade
geprüft wird.

Standardmäßig ausgenommen: Datenbankdateien, Backup-Ordner und Protokolle (abwählbar). Optional:
Postfächer, Nextcloud-Datenordner (automatisch erkannt) und eigene Ordner. Netzlaufwerke (NFS,
CIFS, SSHFS) werden nie durchsucht. Den Nextcloud-Datenordner nur ausnehmen, wenn in Nextcloud die
App „Antivirus for files“ aktiv ist – eine Anleitung dazu steht in den Einstellungen.

## Laufenden Scan abbrechen

Am einfachsten über „Scan abbrechen“ in der Weboberfläche. Auf der Kommandozeile:

```bash
sudo systemctl stop ubusec-queue.service   # über die Weboberfläche gestartet
sudo systemctl stop ubusec-full.service    # Vollscan aus dem Zeitplan (Schnellscan: ubusec-quick.service)
```

Ein abgebrochener Scan erzeugt keinen Bericht; die Weboberfläche zeigt „abgebrochen“ an. Das gilt
auch nach einem Neustart oder Stromausfall. Bleibt ein Scan-Auftrag liegen, weil der
Warteschlangendienst nicht reagiert, zeigt die Oberfläche das nach zwei Minuten mit dem passenden
Befehl an und bietet „Auftrag verwerfen“ an.

## Fehlalarme

Am einfachsten über „Als Fehlalarm ausblenden“ in der Weboberfläche. Von Hand: in
`/etc/ubusec/ignore.list` eine Regex pro Zeile, geprüft gegen `bereich|meldung|details`.

## Hinweise zu den Website-Prüfungen

- HTTP-Prüfungen gehen an die IP, an die der Apache-VirtualHost gebunden ist – also direkt an diesen Server, auch wenn eine Domain anderswo hin zeigt. Ein CDN davor (z. B. Cloudflare) wird damit nicht geprüft.
- Es wird **kein Code der Webseiten als root ausgeführt**. WordPress-, Mautic- und Roundcube-Versionen werden aus Dateien gelesen; die Nextcloud-Updateprüfung (`occ`) läuft unter dem Domain-Benutzer.
- Für Versionsvergleiche fragt ubusec wordpress.org, endoflife.date und GitHub ab (einmal täglich zwischengespeichert). Sind diese nicht erreichbar, steht ein Hinweis im Bericht.
- Die Code-Analyse eigener PHP-Anwendungen (SQL-Injection, XSS) sucht typische Muster – sie ersetzt keinen Code-Review und kann Fehlalarme liefern.
- DKIM wird nicht geprüft, weil sich der verwendete Schlüsselname (Selector) von außen nicht ermitteln lässt.

## Hinweise

- ubusec meldet nur, es **löscht oder verändert nichts** am System (Ausnahme: Einträge in der Ignore-Liste und die Baseline, beides nur auf deine Anweisung).
- CVE-Fixes aus `esm-apps`/`esm-infra` benötigen Ubuntu Pro (für bis zu 5 Rechner kostenlos).
- Für Webhosting empfiehlt sich zusätzlich Linux Malware Detect (https://www.rfxn.com/projects/linux-malware-detect/) – ubusec nutzt es automatisch.
- Ein Scanner auf einem kompromittierten System kann getäuscht werden (Kernel-Rootkits). Bei konkretem Verdacht von einem Rettungssystem aus prüfen.

## Lizenzen

ubusec selbst steht unter der [MIT-Lizenz](LICENSE).

**Mitgeliefert** werden nur die Schriften Instrument Sans und Red Hat Mono (SIL Open Font License 1.1,
Lizenztexte in `web/static/fonts/`).

**Nicht mitgeliefert** werden die Prüfwerkzeuge. ubusec installiert sie über die Paketquellen von Ubuntu
(bzw. auf Wunsch Lynis über die Quelle des Herstellers) und ruft sie als eigenständige Programme auf. Jedes
Werkzeug steht unter seiner eigenen Lizenz; den vollständigen Text liefert das jeweilige Paket unter
`/usr/share/doc/<paket>/copyright` mit.

| Werkzeug | Lizenz | Projekt |
|---|---|---|
| ClamAV | GPL-2.0 | https://www.clamav.net |
| Lynis | GPL-3.0 | https://cisofy.com/lynis/ |
| rkhunter | GPL-2.0 | https://rkhunter.sourceforge.net |
| chkrootkit | BSD-artige Lizenz | https://www.chkrootkit.org |
| OpenSCAP | LGPL-2.1 | https://www.open-scap.org |
| unhide | GPL-3.0 | https://github.com/YJesus/Unhide |
| needrestart | GPL-2.0 | https://github.com/liske/needrestart |
| testssl.sh (optional) | GPL-2.0 | https://testssl.sh |
| AIDE (optional) | GPL-2.0 | https://aide.github.io |
| Linux Malware Detect (optional) | GPL-2.0 | https://www.rfxn.com/projects/linux-malware-detect/ |
| dig (BIND 9) | MPL-2.0 | https://www.isc.org/bind/ |
| qrencode | LGPL-2.1 | https://fukuchi.org/works/qrencode/ |
| Flask | BSD-3-Clause | https://flask.palletsprojects.com |
| Waitress | ZPL-2.1 | https://docs.pylonsproject.org/projects/waitress/ |

Versions- und Supportdaten bezieht ubusec zur Laufzeit von Canonical (Ubuntu-OVAL), wordpress.org,
endoflife.date und GitHub; es werden dabei keine Daten über den Server übermittelt.
