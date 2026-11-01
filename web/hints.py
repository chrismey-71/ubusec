"""Verbesserungshinweise zu den Meldungen von ubusec.

Jeder Eintrag: (Regex auf "modul|meldung", Hinweis). Der erste Treffer gewinnt.
Ein Hinweis hat:
  why    – warum das wichtig ist (ein, zwei Sätze, verständlich ohne Fachwissen)
  steps  – konkrete Schritte; Einträge, die mit "$ " beginnen, sind Befehle
  effort – grobe Einschätzung: "5 Min", "15 Min", "1 Std", "prüfen"
  alarm  – True, wenn ein Einbruch möglich ist (zeigt die Notfall-Hinweise)
"""
import re

INCIDENT = [
    "Nicht nur das Symptom löschen: Ein Angreifer hinterlässt meist mehrere Hintertüren.",
    "Beweise sichern, bevor du etwas änderst (z. B. Provider-Snapshot des Servers anlegen).",
    "Bei bestätigtem Einbruch: Server aus sauberer Quelle neu aufsetzen, Daten aus Backups vor dem Einbruch zurückspielen.",
    "Alle Passwörter, SSH-Schlüssel, API-Tokens und Datenbank-Zugänge dieses Servers wechseln.",
]

_H = [
    # ------------------------------------------------------------- updates ---
    (r"^updates\|\d+ Sicherheitsupdates", dict(
        why="Für diese Pakete gibt es bereits Korrekturen bekannter Sicherheitslücken. Bis sie installiert sind, "
            "ist der Server über öffentlich dokumentierte Wege angreifbar.",
        steps=["$ sudo apt update && sudo apt upgrade",
               "Anschließend prüfen, ob ein Neustart nötig ist (erscheint sonst beim nächsten Scan)."],
        effort="5 Min")),
    (r"^updates\|\d+ weitere Paket-Updates", dict(
        why="Keine Sicherheitskorrekturen, aber Fehlerbehebungen. Regelmäßig mit einspielen hält den Abstand zu "
            "künftigen Sicherheitsupdates klein.",
        steps=["$ sudo apt update && sudo apt upgrade"], effort="5 Min")),
    (r"^updates\|Zurückgehaltene Pakete", dict(
        why="Pakete auf „hold“ bekommen auch keine Sicherheitsupdates mehr.",
        steps=["Prüfen, ob das Zurückhalten noch nötig ist.", "$ sudo apt-mark unhold <paket>"], effort="prüfen")),
    (r"^updates\|Neustart erforderlich", dict(
        why="Einige Updates (Kernel, Systembibliotheken) wirken erst nach einem Neustart. Bis dahin läuft der alte, "
            "verwundbare Code weiter.",
        steps=["Zu einer ruhigen Zeit neu starten:", "$ sudo reboot"], effort="5 Min")),
    (r"^updates\|Laufender Kernel ist veraltet", dict(
        why="Der Kernel mit den Sicherheitskorrekturen ist installiert, aber noch nicht aktiv.",
        steps=["$ sudo reboot", "Tipp: Ubuntu Pro bietet Livepatch, das Kernel-Korrekturen ohne Neustart einspielt."],
        effort="5 Min")),
    (r"^updates\|\d+ Dienste laufen noch mit alten", dict(
        why="Diese Dienste haben die alten Bibliotheken noch im Speicher. Eine geschlossene Lücke bleibt in ihnen offen, "
            "bis sie neu gestartet werden.",
        steps=["$ sudo needrestart -r a", "Oder gezielt: sudo systemctl restart <dienst>"], effort="5 Min")),
    (r"^updates\|Automatische Sicherheitsupdates", dict(
        why="Ohne automatische Updates hängt die Sicherheit davon ab, dass jemand täglich daran denkt. Kritische Lücken "
            "werden oft innerhalb von Stunden nach Bekanntwerden ausgenutzt.",
        steps=["$ sudo apt install unattended-upgrades",
               "$ sudo dpkg-reconfigure -plow unattended-upgrades",
               "Optional automatischer Neustart nachts: in /etc/apt/apt.conf.d/50unattended-upgrades "
               "Unattended-Upgrade::Automatic-Reboot \"true\"; und Automatic-Reboot-Time \"03:30\"; setzen."],
        effort="15 Min")),
    (r"^updates\|Ubuntu .* erhält keine Sicherheitsupdates", dict(
        why="Für diese Ubuntu-Version werden keine Lücken mehr geschlossen. Jede neu bekannte Schwachstelle bleibt offen.",
        steps=["Backup anlegen.", "$ sudo do-release-upgrade",
               "Oder Ubuntu Pro (ESM) aktivieren: sudo pro attach <token>"], effort="1 Std")),
    (r"^updates\|Ubuntu .* aus dem Standard-Support", dict(
        why="Sicherheitsupdates gibt es nur noch mit Ubuntu Pro (für bis zu 5 Rechner kostenlos).",
        steps=["Token holen: https://ubuntu.com/pro", "$ sudo pro attach <token>",
               "Langfristig auf die nächste LTS-Version wechseln: sudo do-release-upgrade"], effort="15 Min")),
    (r"^updates\|apt-get update fehlgeschlagen", dict(
        why="Ohne aktuelle Paketlisten kann ubusec ausstehende Updates nicht zuverlässig erkennen.",
        steps=["$ sudo apt update", "Fehlermeldungen (Quellen, Schlüssel, DNS) beheben."], effort="15 Min")),

    # ----------------------------------------------------------------- cve ---
    (r"^cve\|\d+ Sicherheitsmeldungen \(USN\) der Stufe (Critical|High)", dict(
        why="Für installierte Pakete sind schwere Sicherheitslücken mit verfügbarem Fix bekannt. Genau nach solchen "
            "Lücken suchen automatisierte Angriffe.",
        steps=["$ sudo apt update && sudo apt upgrade",
               "Einzelne Meldung gezielt beheben: sudo pro fix USN-xxxx-x",
               "Bleibt die Meldung nach dem Upgrade bestehen, liegt der Fix in ESM: sudo pro attach <token>"],
        effort="15 Min")),
    (r"^cve\|\d+ Sicherheitsmeldungen", dict(
        why="Für installierte Pakete sind Sicherheitslücken mit verfügbarem Fix bekannt.",
        steps=["$ sudo apt update && sudo apt upgrade",
               "Bleibt die Meldung bestehen: Fix liegt in ESM (Ubuntu Pro), sudo pro attach <token>"],
        effort="15 Min")),
    (r"^cve\|Ubuntu-OVAL-Daten konnten nicht", dict(
        why="Ohne die Schwachstellendaten von Canonical findet die CVE-Prüfung nichts.",
        steps=["Prüfen, ob der Server security-metadata.canonical.com per HTTPS erreicht.",
               "$ curl -I https://security-metadata.canonical.com/oval/"], effort="15 Min")),

    # -------------------------------------------------------------- config ---
    (r"^config\|Lynis-Warnung", dict(
        why="Lynis stuft diesen Punkt als Warnung ein, also als konkretes Sicherheitsproblem, nicht nur als Empfehlung.",
        steps=["Details und Lösungsvorschlag anzeigen:", "$ sudo lynis show details <TEST-ID>"], effort="prüfen")),
    (r"^config\|Lynis-Härtungsindex", dict(
        why="Der Index fasst zusammen, wie viele empfohlene Härtungsmaßnahmen umgesetzt sind. Jeder Vorschlag ist ein "
            "kleiner Baustein; ab etwa 75 gilt ein Server als ordentlich gehärtet.",
        steps=["Vorschläge der Reihe nach durchgehen (Liste unten auf der Seite „Empfehlungen“).",
               "$ sudo lynis show details <TEST-ID>"], effort="1 Std")),
    (r"^config\|SSH: Root-Login mit Passwort", dict(
        why="Root ist der erste Benutzername, den Angreifer ausprobieren. Mit Passwort-Login genügt ein erratenes "
            "Passwort für die volle Kontrolle.",
        steps=["Zuerst sicherstellen, dass die Anmeldung per SSH-Schlüssel funktioniert!",
               "In /etc/ssh/sshd_config.d/99-hardening.conf eintragen: PermitRootLogin prohibit-password",
               "$ sudo sshd -t && sudo systemctl reload ssh",
               "Neue SSH-Sitzung testen, bevor die alte geschlossen wird."], effort="15 Min")),
    (r"^config\|SSH: Passwort-Anmeldung aktiv", dict(
        why="Jeder Server im Internet bekommt täglich tausende Passwort-Rateversuche. Mit Schlüssel-Anmeldung laufen "
            "diese ins Leere.",
        steps=["SSH-Schlüssel für alle Benutzer einrichten und testen (ssh-copy-id).",
               "In /etc/ssh/sshd_config.d/99-hardening.conf: PasswordAuthentication no und KbdInteractiveAuthentication no",
               "$ sudo sshd -t && sudo systemctl reload ssh",
               "Virtualmin: SFTP-Benutzer mit Passwort brauchen ggf. einen Match-Block als Ausnahme."], effort="15 Min")),
    (r"^config\|SSH: Leere Passwörter", dict(
        why="Konten ohne Passwort wären per SSH ohne jede Hürde zugänglich.",
        steps=["In der SSH-Konfiguration: PermitEmptyPasswords no", "$ sudo sshd -t && sudo systemctl reload ssh"],
        effort="5 Min")),
    (r"^config\|SSH: X11Forwarding", dict(
        why="Auf Servern ohne grafische Oberfläche unnötig; jede unnötige Funktion ist zusätzliche Angriffsfläche.",
        steps=["In der SSH-Konfiguration: X11Forwarding no", "$ sudo systemctl reload ssh"], effort="5 Min")),
    (r"^config\|SSH: MaxAuthTries", dict(
        why="Weniger Versuche pro Verbindung bremsen Rateangriffe.",
        steps=["In der SSH-Konfiguration: MaxAuthTries 3", "$ sudo systemctl reload ssh"], effort="5 Min")),
    (r"^config\|\d+ Kernel-Parameter", dict(
        why="Diese Kernel-Einstellungen erschweren das Ausnutzen von Lücken und bestimmte Netzwerkangriffe.",
        steps=["Werte aus der Liste in /etc/sysctl.d/99-ubusec.conf eintragen, z. B. fs.protected_symlinks = 1",
               "$ sudo sysctl --system",
               "Vorsicht bei Servern mit Docker/VPN: ip_forward und Redirect-Werte können dort nötig sein."],
        effort="15 Min")),
    (r"^config\|Weitere Konten mit UID 0", dict(
        why="Jedes Konto mit UID 0 hat volle Root-Rechte. Zusätzliche UID-0-Konten sind ein klassisches Zeichen für "
            "eine versteckte Hintertür.",
        steps=["$ sudo grep ':0:' /etc/passwd", "Herkunft klären; unbekannte Konten sperren: sudo usermod -L <name>"],
        effort="prüfen", alarm=True)),
    (r"^config\|Konten ohne Passwort", dict(
        why="Ein Konto ohne Passwort kann je nach Dienst ohne Anmeldung genutzt werden.",
        steps=["Konto sperren oder Passwort setzen:", "$ sudo passwd -l <name>"], effort="5 Min")),
    (r"^config\|sudo ohne Passwort", dict(
        why="Wer das Benutzerkonto übernimmt, wird mit NOPASSWD sofort root, ohne weitere Hürde.",
        steps=["$ sudo visudo -f /etc/sudoers.d/<datei>",
               "NOPASSWD entfernen oder auf einzelne, ungefährliche Befehle beschränken."], effort="15 Min")),
    (r"^config\|AppArmor ist nicht aktiv", dict(
        why="AppArmor sperrt Dienste in ihre vorgesehenen Bereiche. Ohne es kann ein übernommener Dienst mehr anrichten.",
        steps=["$ sudo systemctl enable --now apparmor", "$ sudo aa-status"], effort="5 Min")),
    (r"^config\|Kein Brute-Force-Schutz", dict(
        why="fail2ban sperrt IP-Adressen, die wiederholt falsche Passwörter probieren (SSH, Mail, Webmin, WordPress-Login).",
        steps=["$ sudo apt install fail2ban",
               "/etc/fail2ban/jail.local anlegen mit [sshd] enabled = true",
               "$ sudo systemctl enable --now fail2ban",
               "Virtualmin bringt unter „Webmin → Networking → Fail2Ban“ eine Oberfläche dafür mit."], effort="15 Min")),
    (r"^config\|\d+ fehlgeschlagene SSH-Anmeldungen", dict(
        why="Zeigt, wie stark der Server angegriffen wird. Mit Schlüssel-Login und fail2ban ist das unkritisch.",
        steps=["Kein Handlungsbedarf, solange Passwort-Login aus ist bzw. fail2ban läuft."], effort="—")),

    # --------------------------------------------------------------- perms ---
    (r"^perms\|Unsichere Rechte .* auf /etc/(shadow|gshadow)", dict(
        why="Diese Datei enthält die Passwort-Hashes. Lesbar für alle heißt: jeder Benutzer kann sie offline knacken.",
        steps=["$ sudo chown root:shadow /etc/shadow /etc/gshadow", "$ sudo chmod 640 /etc/shadow /etc/gshadow"],
        effort="5 Min")),
    (r"^perms\|Unsichere Rechte", dict(
        why="Wer diese Datei verändern kann, kann sich Root-Rechte verschaffen oder die Anmeldung manipulieren.",
        steps=["Schreibrechte für Gruppe/Andere entfernen:", "$ sudo chmod go-w <datei>",
               "Für SSH-Hostschlüssel: sudo chmod 600 /etc/ssh/ssh_host_*_key"], effort="5 Min")),
    (r"^perms\|.* gehört nicht root", dict(
        why="Systemdateien müssen root gehören, sonst kann ihr Besitzer das System manipulieren.",
        steps=["$ sudo chown root:root <datei>"], effort="5 Min")),
    (r"^perms\|\d+ Dateien für alle beschreibbar", dict(
        why="Jeder Benutzer und jeder übernommene Dienst (z. B. eine gehackte Website) kann diese Dateien verändern.",
        steps=["$ sudo chmod o-w <datei>",
               "Bei Websites: Dateien 644, Ordner 755 – nie 777.",
               "Alle auf einmal (nach Prüfung der Liste): xargs -a <liste> -d '\\n' sudo chmod o-w"], effort="15 Min")),
    (r"^perms\|\d+ Verzeichnisse für alle beschreibbar", dict(
        why="In solchen Ordnern kann jeder Dateien anderer löschen oder austauschen.",
        steps=["Schreibrecht entziehen: sudo chmod o-w <ordner>",
               "Oder, falls gemeinsam genutzt (wie /tmp): sudo chmod +t <ordner>"], effort="15 Min")),
    (r"^perms\|\d+ Dateien ohne gültigen Besitzer", dict(
        why="Meist Reste gelöschter Benutzer. Ein neu angelegter Benutzer mit derselben ID würde sie automatisch besitzen.",
        steps=["Liste prüfen; nicht mehr benötigte Dateien löschen, sonst: sudo chown root:root <datei>"],
        effort="15 Min")),
    (r"^perms\|\d+ SUID/SGID-Programme gehören zu keinem Paket", dict(
        why="SUID-Programme laufen mit den Rechten ihres Besitzers, oft root. Eines, das zu keinem Paket gehört, "
            "ist ein typisches Versteck für eine Root-Hintertür.",
        steps=["$ ls -l <datei> && sha256sum <datei>",
               "Herkunft klären (selbst installierte Software unter /usr/local oder /opt ist möglich).",
               "Unbekannt? SUID-Bit entfernen und Datei sichern: sudo chmod u-s,g-s <datei>"],
        effort="prüfen", alarm=True)),
    (r"^perms\|Home-Verzeichnisse für andere", dict(
        why="Andere Benutzer können Dateien in diesen Home-Verzeichnissen lesen.",
        steps=["$ sudo chmod 750 /home/<name>",
               "Virtualmin: Webserver-Zugriff läuft über die Gruppe – vorher prüfen, ob die Websites danach laufen."],
        effort="15 Min")),
    (r"^perms\|authorized_keys für andere beschreibbar", dict(
        why="Wer diese Datei beschreiben kann, kann einen eigenen Schlüssel eintragen und sich als dieser Benutzer anmelden.",
        steps=["$ chmod 600 <datei> && chmod 700 $(dirname <datei>)"], effort="5 Min")),

    # ------------------------------------------------------------ firewall ---
    (r"^firewall\|Keine aktive Firewall", dict(
        why="Ohne Firewall ist jeder Dienst, der auf einem Netzwerk-Port lauscht, aus dem Internet erreichbar – auch "
            "solche, die nur intern gedacht sind (Datenbanken, Caches).",
        steps=["Zuerst SSH erlauben, sonst sperrst du dich aus:", "$ sudo ufw allow OpenSSH",
               "$ sudo ufw allow 80,443/tcp",
               "Mailserver: sudo ufw allow 25,465,587,993/tcp",
               "$ sudo ufw default deny incoming && sudo ufw enable",
               "Virtualmin hat alternativ ein eigenes Firewall-Modul (Webmin → Networking)."], effort="15 Min")),
    (r"^firewall\|ufw: Eingehender Verkehr ist standardmäßig erlaubt", dict(
        why="Die Firewall ist an, lässt aber alles durch, was nicht ausdrücklich verboten ist.",
        steps=["Benötigte Ports erlauben (mindestens SSH), dann:", "$ sudo ufw default deny incoming"],
        effort="15 Min")),
    (r"^firewall\|ufw filtert kein IPv6", dict(
        why="Über IPv6 sind alle Dienste ungefiltert erreichbar.",
        steps=["In /etc/default/ufw: IPV6=yes", "$ sudo ufw disable && sudo ufw enable"], effort="5 Min")),
    (r"^firewall\|Riskante Dienste lauschen öffentlich", dict(
        why="Datenbanken, Caches und ähnliche Dienste sind nicht dafür gebaut, direkt aus dem Internet erreichbar zu sein. "
            "Sie werden laufend automatisiert gescannt.",
        steps=["Dienst nur lokal binden, z. B. MySQL/MariaDB: bind-address = 127.0.0.1",
               "Redis: bind 127.0.0.1 ::1",
               "Oder per Firewall sperren: sudo ufw deny <port>"], effort="15 Min")),
    (r"^firewall\|Admin-/Web-Oberflächen öffentlich", dict(
        why="Webmin/Virtualmin-Oberflächen geben bei erfolgreichem Angriff Root-Zugriff. Sie sollten nur von deinen "
            "eigenen Adressen erreichbar sein.",
        steps=["$ sudo ufw allow from <deine-IP> to any port 10000 proto tcp",
               "$ sudo ufw deny 10000/tcp",
               "Alternativ in Webmin: Webmin-Konfiguration → IP-Zugriffskontrolle.",
               "Mit wechselnder IP: Zugriff über VPN (z. B. WireGuard) oder SSH-Tunnel."], effort="15 Min")),
    (r"^firewall\|Öffentlich lauschende Ports", dict(
        why="Überblick: Jeder dieser Ports ist ein möglicher Zugang. Was nicht gebraucht wird, sollte abgeschaltet werden.",
        steps=["Unbekannten Dienst identifizieren: sudo ss -tulpn | grep :<port>",
               "Nicht benötigte Dienste stoppen: sudo systemctl disable --now <dienst>"], effort="prüfen")),

    # ----------------------------------------------------------- integrity ---
    (r"^integrity\|\d+ Programme/Bibliotheken weichen", dict(
        why="Programmdateien dürfen sich nur durch Paket-Updates ändern. Eine Abweichung kann ein manipuliertes "
            "Systemprogramm (Rootkit) bedeuten.",
        steps=["Paket ermitteln: dpkg -S <datei>", "Neu installieren: sudo apt install --reinstall <paket>",
               "Erneut scannen. Tritt die Abweichung wieder auf oder ist sie nicht erklärbar: Notfall-Hinweise befolgen."],
        effort="prüfen", alarm=True)),
    (r"^integrity\|\d+ weitere Paketdateien verändert", dict(
        why="Nicht-ausführbare Paketdateien wurden geändert – oft harmlos (manuelle Anpassungen), sollte aber erklärbar sein.",
        steps=["Paket ermitteln: dpkg -S <datei>", "Falls nicht beabsichtigt: sudo apt install --reinstall <paket>"],
        effort="prüfen")),
    (r"^integrity\|AIDE:", dict(
        why="AIDE hat Dateiänderungen gegenüber dem gespeicherten Stand festgestellt.",
        steps=["Änderungsliste im AIDE-Log prüfen (Link in den Details).",
               "Wenn alle Änderungen erklärbar sind (Updates, eigene Arbeit): Baseline übernehmen."], effort="prüfen")),

    # ------------------------------------------------------------ baseline ---
    (r"^baseline\|Neue Benutzerkonten", dict(
        why="Angreifer legen gern eigene Konten an, um wiederzukommen.",
        steps=["Hast du (oder Virtualmin beim Anlegen einer Domain) dieses Konto erstellt? Dann Baseline übernehmen.",
               "Unbekannt: sperren mit sudo usermod -L -e 1 <name>, Anmeldungen prüfen mit last <name>"],
        effort="prüfen", alarm=True)),
    (r"^baseline\|Neue sudo-Regeln", dict(
        why="Eine neue sudo-Regel kann einem Benutzer Root-Rechte geben.",
        steps=["$ sudo visudo -c && sudo cat /etc/sudoers.d/*", "Unbekannte Regel entfernen."],
        effort="prüfen", alarm=True)),
    (r"^baseline\|Neue SSH-Schlüssel", dict(
        why="Ein fremder Schlüssel in authorized_keys ist eine dauerhafte Hintertür.",
        steps=["Schlüssel anhand des Fingerabdrucks zuordnen: ssh-keygen -lf <datei>",
               "Unbekannte Zeile aus der Datei löschen."], effort="prüfen", alarm=True)),
    (r"^baseline\|Neue öffentlich lauschende Ports", dict(
        why="Ein neu geöffneter Port kann ein neuer Dienst sein – oder eine Hintertür.",
        steps=["$ sudo ss -tulpn | grep :<port>", "Unbekannter Prozess: ls -l /proc/<PID>/exe"],
        effort="prüfen", alarm=True)),
    (r"^baseline\|Neue Cronjobs", dict(
        why="Cronjobs sind der häufigste Weg, mit dem sich Malware nach einem Neustart wieder startet.",
        steps=["Eintrag prüfen: Wer hat ihn angelegt, was wird ausgeführt?", "Unbekannt: Datei bzw. Zeile entfernen."],
        effort="prüfen", alarm=True)),
    (r"^baseline\|Neu aktivierte systemd", dict(
        why="Neu aktivierte Dienste starten automatisch beim Booten.",
        steps=["$ systemctl cat <dienst>", "Unbekannt: sudo systemctl disable --now <dienst>"], effort="prüfen")),
    (r"^baseline\|Neue SUID/SGID-Dateien", dict(
        why="Neue SUID-Dateien können Root-Rechte verschaffen.",
        steps=["$ ls -l <datei> && dpkg -S <datei>", "Unbekannt: sudo chmod u-s,g-s <datei>"],
        effort="prüfen", alarm=True)),

    # ------------------------------------------------------------- rootkit ---
    (r"^rootkit\|rkhunter: .*(file properties|Dateieigenschaften)", dict(
        why="rkhunter hat eine geänderte Systemdatei gefunden. Direkt nach Updates ist das meist harmlos.",
        steps=["Gab es kurz zuvor ein Update? Dann Referenz aktualisieren: sudo rkhunter --propupd",
               "Kein Update: Datei mit dpkg --verify <paket> gegenprüfen."], effort="prüfen")),
    (r"^rootkit\|rkhunter:", dict(
        why="rkhunter meldet eine Auffälligkeit. Einige Meldungen sind auf Ubuntu bekannte Fehlalarme.",
        steps=["Details im rkhunter-Log nachlesen (Rohdaten).",
               "Erklärbarer Fehlalarm: als Fehlalarm ausblenden.",
               "Rootkit-Meldung: Notfall-Hinweise befolgen."], effort="prüfen")),
    (r"^rootkit\|chkrootkit: .*INFECTED", dict(
        why="chkrootkit hat Spuren eines bekannten Rootkits gefunden.",
        steps=["Gegenprüfen mit rkhunter und einem zweiten Scan.", "Bestätigt: Notfall-Hinweise befolgen."],
        effort="prüfen", alarm=True)),
    (r"^rootkit\|chkrootkit meldet", dict(
        why="Oft harmlos (z. B. versteckte Dateien von Programmen), aber jede Zeile sollte erklärbar sein.",
        steps=["Meldungen im chkrootkit-Log prüfen.", "Bekannte Fehlalarme ausblenden."], effort="prüfen")),
    (r"^rootkit\|unhide", dict(
        why="Ein Prozess oder Port, der in den normalen Systemlisten nicht auftaucht, deutet auf ein Kernel-Rootkit hin. "
            "Sehr kurzlebige Prozesse können Fehlalarme auslösen.",
        steps=["Scan wiederholen. Tritt die Meldung erneut auf: Notfall-Hinweise befolgen."],
        effort="prüfen", alarm=True)),
    (r"^rootkit\|/etc/ld.so.preload", dict(
        why="Diese Datei lädt eine Bibliothek in jedes Programm. Rootkits nutzen das, um Prozesse und Dateien zu verstecken.",
        steps=["Inhalt und genannte Bibliothek sichern: sudo cp /etc/ld.so.preload <bibliothek> /root/beweise/",
               "Ohne bekannte Ursache (z. B. Sicherheitssoftware): Notfall-Hinweise befolgen."],
        effort="prüfen", alarm=True)),
    (r"^rootkit\|Prozesse laufen aus temporären", dict(
        why="Legitime Programme laufen praktisch nie aus /tmp oder /dev/shm. Malware nutzt diese Ordner, weil sie "
            "überall beschreibbar sind.",
        steps=["Prozess untersuchen: ls -l /proc/<PID>/exe; cat /proc/<PID>/cmdline; sudo ss -tp | grep <PID>",
               "Programm sichern: sudo cp /proc/<PID>/exe /root/beweise/",
               "Beenden: sudo kill -9 <PID>", "Herkunft suchen (Cron, Dienste, Webanwendungen)."],
        effort="sofort", alarm=True)),
    (r"^rootkit\|Prozesse laufen aus gelöschten", dict(
        why="Malware löscht oft ihre eigene Datei, um nicht gefunden zu werden, und läuft im Speicher weiter.",
        steps=["$ ls -l /proc/<PID>/exe", "Bekanntes Programm nach Update? Dienst neu starten. Sonst: wie oben untersuchen."],
        effort="prüfen", alarm=True)),
    (r"^rootkit\|Prozesse mit Namen bekannter Cryptominer", dict(
        why="Cryptominer sind die häufigste Malware auf gehackten Linux-Servern. Ihr Fund bedeutet fast immer einen Einbruch.",
        steps=["Prozess sichern und beenden (siehe Details).",
               "Persistenz suchen: crontab -l -u <benutzer>, /etc/cron.d, systemd-Dienste, ~/.ssh/authorized_keys",
               "Einfallstor finden: veraltete Webanwendung, schwaches Passwort, offener Dienst."],
        effort="sofort", alarm=True)),
    (r"^rootkit\|Ausgehende Verbindungen zu typischen Mining", dict(
        why="Verbindungen zu typischen Mining-Pool-Ports deuten auf einen Cryptominer hin.",
        steps=["Prozess zur Verbindung finden: sudo ss -tnp | grep <ziel>", "Weiter wie bei Cryptominern."],
        effort="sofort", alarm=True)),
    (r"^rootkit\|Netzwerkschnittstellen im Promiscuous", dict(
        why="Im Promiscuous-Mode liest eine Netzwerkkarte fremden Verkehr mit (Sniffer). Bei Docker/VM-Bridges kann das normal sein.",
        steps=["$ ip link", "Unerwartet: Prozess suchen mit sudo lsof -i"], effort="prüfen")),
    (r"^rootkit\|Programmdateien \(ELF\) in temporären", dict(
        why="Programme in /tmp oder /dev/shm sind typisch für heruntergeladene Malware.",
        steps=["$ file <datei>; sha256sum <datei>", "Hash bei VirusTotal prüfen, dann löschen."],
        effort="prüfen", alarm=True)),
    (r"^rootkit\|Ausführbare Skripte in temporären", dict(
        why="Meist harmlose Installationsreste, gelegentlich Malware-Dropper.",
        steps=["Inhalt ansehen: less <datei>", "Nicht benötigt: löschen."], effort="5 Min")),
    (r"^rootkit\|Versteckte Dateien", dict(
        why="Malware versteckt sich gern in Punkt-Ordnern in /tmp oder /dev/shm.",
        steps=["$ ls -la <pfad>", "Unbekannt: Inhalt prüfen, dann löschen."], effort="5 Min")),
    (r"^rootkit\|Verdächtige Befehle in Autostart", dict(
        why="Befehle, die Code aus dem Internet laden und direkt ausführen, sind ein typisches Muster von Malware-Persistenz.",
        steps=["Zeile prüfen: Hast du sie selbst eingerichtet?", "Unbekannt: Zeile/Datei entfernen und Notfall-Hinweise befolgen."],
        effort="prüfen", alarm=True)),

    # ------------------------------------------------------------- malware ---
    (r"^malware\|ClamAV: \d+ infizierte", dict(
        why="ClamAV hat Dateien mit bekannter Schadsoftware gefunden.",
        steps=["In Quarantäne verschieben: sudo mkdir -p /root/quarantaene && sudo mv <datei> /root/quarantaene/",
               "Webseiten-Funde: CMS, Plugins und Themes aktualisieren, Admin-Passwörter ändern.",
               "Herausfinden, wie die Datei auf den Server kam (Upload, FTP, Webanwendung)."],
        effort="1 Std", alarm=True)),
    (r"^malware\|ClamAV-Signatur", dict(
        why="Mit veralteten Signaturen erkennt ClamAV neue Schadsoftware nicht.",
        steps=["$ sudo systemctl restart clamav-freshclam", "$ sudo freshclam"], effort="5 Min")),

    # ----------------------------------------------------------------- web ---
    (r"^web\|PHP-Dateien in Upload", dict(
        why="In Upload-Ordnern haben PHP-Dateien nichts zu suchen. Angreifer laden dort Webshells über unsichere "
            "Upload-Formulare hoch.",
        steps=["Datei ansehen und meist löschen.",
               "PHP-Ausführung im Upload-Ordner sperren (Apache, .htaccess in wp-content/uploads): "
               "<FilesMatch \"\\.ph(p[0-9]?|tml)$\"> Require all denied </FilesMatch>",
               "WordPress, Plugins und Themes aktualisieren."], effort="15 Min", alarm=True)),
    (r"^web\|\d+ PHP-Dateien mit typischen Webshell", dict(
        why="Diese Dateien enthalten Muster, die typisch für Webshells (Fernsteuerungen über den Browser) sind. "
            "Einzelne Plugins nutzen ähnlichen Code legitim.",
        steps=["Datei ansehen: Ist sie Teil eines bekannten Plugins (Original vergleichen)?",
               "Unbekannt: löschen, Website-Zugänge ändern, CMS aktualisieren."], effort="prüfen", alarm=True)),
    (r"^web\|Linux Malware Detect: \d+ Funde", dict(
        why="Linux Malware Detect hat bekannte Web-Malware gefunden.",
        steps=["Bericht anzeigen: sudo maldet --report <ID>",
               "In Quarantäne: sudo maldet -q <ID>", "Einfallstor schließen (CMS-Updates, Passwörter)."],
        effort="1 Std", alarm=True)),

    # --------------------------------------------------------------- sites ---
    (r"^sites\|TLS-Zertifikat abgelaufen", dict(
        why="Besucher sehen eine Sicherheitswarnung, Browser blockieren die Seite, E-Mail-Programme verweigern die Verbindung.",
        steps=["Virtualmin: Domain wählen → Server Configuration → SSL Certificate → Let's Encrypt → Request Certificate",
               "Automatische Verlängerung prüfen: Virtualmin → System Settings → Virtualmin Configuration → SSL settings"],
        effort="5 Min")),
    (r"^sites\|TLS-Zertifikat läuft bald ab", dict(
        why="Let's-Encrypt-Zertifikate verlängern sich normalerweise 30 Tage vor Ablauf von selbst. Wird es knapp, ist die "
            "automatische Verlängerung meist gescheitert (z. B. DNS zeigt nicht auf den Server).",
        steps=["Virtualmin: Domain → Server Configuration → SSL Certificate → Let's Encrypt → Request Certificate",
               "Fehlermeldung beachten – häufigste Ursache: eine Alias-Domain zeigt nicht mehr auf diesen Server."],
        effort="15 Min")),
    (r"^sites\|TLS-Zertifikat ungültig", dict(
        why="Das Zertifikat passt nicht zum Domainnamen oder stammt nicht von einer anerkannten Stelle. Besucher bekommen eine Warnung.",
        steps=["Virtualmin: Domain → Server Configuration → SSL Certificate → Let's Encrypt für alle Namen (mit und ohne www) anfordern."],
        effort="15 Min")),
    (r"^sites\|HTTPS nicht erreichbar", dict(
        why="Die Seite ist nicht verschlüsselt erreichbar – Anmeldedaten und Formulare gehen im Klartext durchs Netz.",
        steps=["Virtualmin: Domain → Edit Virtual Server → Enabled features → SSL website aktivieren",
               "Danach Let's-Encrypt-Zertifikat anfordern."], effort="15 Min")),
    (r"^sites\|Veraltete TLS-Versionen", dict(
        why="TLS 1.0 und 1.1 gelten als unsicher und werden von aktuellen Browsern nicht mehr verwendet.",
        steps=["In /etc/apache2/mods-available/ssl.conf: SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1",
               "$ sudo apache2ctl configtest && sudo systemctl reload apache2"], effort="5 Min")),
    (r"^sites\|HTTP leitet nicht auf HTTPS um", dict(
        why="Wer die Adresse ohne https:// eintippt, landet auf der unverschlüsselten Seite.",
        steps=["Virtualmin: Domain → Web Configuration → Website Redirects → „Redirect all requests to SSL site“ aktivieren"],
        effort="5 Min")),
    (r"^sites\|(HSTS|Content-Security-Policy fehlt|X-Content-Type-Options|Schutz vor Einbettung|Referrer-Policy|Permissions-Policy)", dict(
        why="Sicherheits-Header weisen den Browser an, sich besser zu schützen: nur HTTPS verwenden (HSTS), Dateitypen nicht "
            "zu erraten (nosniff), die Seite nicht in fremde Seiten einbetten zu lassen (Clickjacking) und weniger über "
            "Besucher preiszugeben. Sie lassen sich für alle Domains auf einmal setzen.",
        steps=["Datei /etc/apache2/conf-available/ubusec-headers.conf anlegen mit:",
               "$ <IfModule mod_headers.c>\n  Header always set Strict-Transport-Security \"max-age=31536000\" env=HTTPS\n"
               "  Header always set X-Content-Type-Options \"nosniff\"\n  Header always set X-Frame-Options \"SAMEORIGIN\"\n"
               "  Header always set Referrer-Policy \"strict-origin-when-cross-origin\"\n"
               "  Header always set Permissions-Policy \"camera=(), microphone=(), geolocation=()\"\n</IfModule>",
               "$ sudo a2enmod headers && sudo a2enconf ubusec-headers",
               "$ sudo apache2ctl configtest && sudo systemctl reload apache2",
               "Nextcloud danach unter Verwaltung → Übersicht prüfen; es erwartet teils eigene Werte (z. B. Referrer-Policy no-referrer).",
               "Content-Security-Policy nicht pauschal setzen – siehe eigener Hinweis."], effort="15 Min")),
    (r"^sites\|Content-Security-Policy (fehlt|nur im Testmodus)", dict(
        why="Eine CSP legt fest, von wo eine Seite Skripte laden darf, und entschärft so eingeschleusten Code (XSS). "
            "Bei WordPress mit vielen Plugins ist eine strenge CSP aufwendig – eine falsche legt die Seite lahm.",
        steps=["Zuerst nur beobachten (bricht nichts): Header always set Content-Security-Policy-Report-Only "
               "\"default-src 'self'; img-src 'self' data: https:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'\"",
               "In der Browser-Konsole (F12) prüfen, was blockiert würde, Regeln ergänzen.",
               "Erst dann „-Report-Only“ entfernen. Minimalvariante ohne Risiko: Content-Security-Policy \"frame-ancestors 'self'\""],
        effort="1 Std")),
    (r"^sites\|HSTS gilt zu kurz", dict(
        why="HSTS wirkt erst richtig, wenn der Browser es lange speichert (empfohlen: ein Jahr).",
        steps=["max-age auf 31536000 setzen."], effort="5 Min")),
    (r"^sites\|Softwareversionen im HTTP-Header", dict(
        why="Versionsnummern helfen Angreifern, gezielt passende Lücken zu suchen.",
        steps=["In /etc/apache2/conf-enabled/security.conf: ServerTokens Prod und ServerSignature Off",
               "In der php.ini (auch Virtualmin-Domains unter ~/etc/php*/php.ini): expose_php = Off",
               "$ sudo systemctl reload apache2"], effort="5 Min")),
    (r"^sites\|Apache verrät Versionsdetails", dict(
        why="Apache zeigt seine genaue Version in Headern und auf Fehlerseiten.",
        steps=["In /etc/apache2/conf-enabled/security.conf: ServerTokens Prod und ServerSignature Off",
               "$ sudo apache2ctl configtest && sudo systemctl reload apache2"], effort="5 Min")),
    (r"^sites\|Apache: HTTP-Methode TRACE", dict(
        why="TRACE wird nicht gebraucht und war früher Baustein für Angriffe auf Cookies.",
        steps=["In /etc/apache2/conf-enabled/security.conf: TraceEnable Off", "$ sudo systemctl reload apache2"], effort="5 Min")),
    (r"^sites\|(Git-Repository|SVN-Daten) öffentlich", dict(
        why="Über das öffentliche Repository lässt sich der komplette Quellcode samt Verlauf herunterladen – oft mit Passwörtern.",
        steps=["Zugriff sperren, z. B. in der .htaccess der Website: RedirectMatch 404 /\\.(git|svn)",
               "Besser: Repository außerhalb des Webverzeichnisses ablegen und nur die Dateien veröffentlichen.",
               "Im Repository enthaltene Passwörter ändern."], effort="15 Min", alarm=True)),
    (r"^sites\|(\.env-Datei|Sicherungskopie der WordPress|Sicherungskopie einer PHP|Datenbank-Dump|Backup-Archiv) ", dict(
        why="Diese Datei kann jeder herunterladen. Sie enthält Zugangsdaten oder ganze Datenbanken.",
        steps=["Datei sofort aus dem Webverzeichnis entfernen (nicht nur umbenennen).",
               "Enthaltene Passwörter (Datenbank, API-Schlüssel) ändern – man muss davon ausgehen, dass sie bereits abgerufen wurden.",
               "Zugriffsprotokoll prüfen: sudo grep '<dateiname>' /var/log/virtualmin/*access_log"],
        effort="sofort", alarm=True)),
    (r"^sites\|phpinfo\(\)", dict(
        why="phpinfo() verrät Pfade, Versionen, Module und Umgebungsvariablen – eine Bauanleitung für Angreifer.",
        steps=["Datei löschen."], effort="5 Min")),
    (r"^sites\|Apache-(Status|Info)seite", dict(
        why="Die Statusseite zeigt aufgerufene Adressen und Besucher-IPs in Echtzeit.",
        steps=["Zugriff auf localhost beschränken (Standard in /etc/apache2/mods-enabled/status.conf: Require local)",
               "Oder Modul abschalten: sudo a2dismod status && sudo systemctl reload apache2"], effort="5 Min")),
    (r"^sites\|WordPress-Fehlerprotokoll öffentlich", dict(
        why="debug.log enthält Pfade, Fehlermeldungen und manchmal Daten von Besuchern.",
        steps=["Datei löschen und in wp-config.php: define('WP_DEBUG_LOG', '/home/<benutzer>/logs/wp-debug.log'); oder Debug abschalten."],
        effort="5 Min")),
    (r"^sites\|Adminer", dict(
        why="Adminer gibt über den Browser Zugriff auf Datenbanken; öffentlich erreichbar ist es ein beliebtes Angriffsziel.",
        steps=["Datei löschen, wenn nicht gebraucht. Sonst per .htaccess auf eigene IP beschränken (Require ip …)."], effort="5 Min")),
    (r"^sites\|(\.DS_Store|composer\.lock|PHP-Fehlerprotokoll)", dict(
        why="Verrät Dateinamen, Bibliotheksversionen oder Fehlerdetails.",
        steps=["Datei löschen oder per .htaccess sperren: <FilesMatch \"^(\\.DS_Store|composer\\.(json|lock)|error_log)$\"> Require all denied </FilesMatch>"],
        effort="5 Min")),
    (r"^sites\|Verzeichnisauflistung aktiv", dict(
        why="Jeder kann alle Dateien des Ordners sehen und herunterladen, auch solche, die nirgends verlinkt sind.",
        steps=["Für alle Seiten abschalten: in /etc/apache2/apache2.conf bei <Directory /home> die Option -Indexes setzen",
               "Oder pro Website in der .htaccess: Options -Indexes"], effort="5 Min")),
    (r"^sites\|Source-Maps", dict(
        why="Source-Maps machen den lesbaren Original-Quellcode der Skripte sichtbar. Das ist meist unkritisch (der Code wird "
            "ohnehin an den Browser geschickt), verrät aber Kommentare, Dateistruktur und manchmal interne Hinweise.",
        steps=["Bei eigenen Projekten: Source-Maps beim Bauen für die Produktion abschalten.",
               "Bei Plugins: in der Regel unkritisch; bei Bedarf per .htaccess sperren: <FilesMatch \"\\.map$\"> Require all denied </FilesMatch>"],
        effort="5 Min")),
    (r"^sites\|Kein SPF-Eintrag", dict(
        why="Ohne SPF kann jeder E-Mails mit deiner Domain als Absender verschicken, und deine echten Mails landen eher im Spam.",
        steps=["DNS-TXT-Eintrag für die Domain anlegen, z. B.: v=spf1 mx a -all",
               "Virtualmin: Domain → DNS Settings → SPF Record (erzeugt den Eintrag automatisch)",
               "Externe Absender (Newsletter, Mailprovider) mit include: ergänzen."], effort="15 Min")),
    (r"^sites\|Mehrere SPF-Einträge", dict(
        why="Mehrere SPF-Einträge machen SPF komplett ungültig – Empfänger werten ihn als Fehler.",
        steps=["Alle Einträge zu einem einzigen v=spf1 … zusammenführen."], effort="15 Min")),
    (r"^sites\|SPF erlaubt jedem Server", dict(
        why="+all bedeutet: jeder Server der Welt darf im Namen der Domain senden – SPF ist damit wirkungslos.",
        steps=["Abschluss auf -all (oder ~all mit DMARC p=reject) ändern."], effort="5 Min")),
    (r"^sites\|SPF ohne verbindlichen Abschluss", dict(
        why="Ohne -all oder ~all am Ende macht SPF keine klare Aussage über fremde Absender.",
        steps=["SPF-Eintrag mit -all beenden, wenn alle Absender aufgeführt sind, sonst ~all und DMARC p=quarantine/reject."],
        effort="5 Min")),
    (r"^sites\|SPF nur mit ~all", dict(
        why="~all (Softfail) markiert fremde Absender nur als verdächtig. Erst zusammen mit einer strengen DMARC-Richtlinie "
            "werden gefälschte Mails tatsächlich abgewiesen. Das meldete auch dein externer Scan als „SPF ohne Ablehnung“.",
        steps=["Empfohlener Weg: DMARC von p=none über p=quarantine auf p=reject anheben (siehe DMARC-Hinweis).",
               "Alternativ SPF auf -all ändern – aber nur, wenn wirklich alle sendenden Dienste (Server, Mautic, Mailprovider) eingetragen sind."],
        effort="15 Min")),
    (r"^sites\|Kein DMARC-Eintrag", dict(
        why="DMARC sagt Empfängern, was mit Mails passieren soll, die SPF/DKIM nicht bestehen, und liefert dir Berichte über Missbrauch.",
        steps=["DNS-TXT-Eintrag _dmarc.<domain> anlegen: v=DMARC1; p=none; rua=mailto:dmarc@<domain>",
               "Nach zwei bis vier Wochen Berichte prüfen, dann p=quarantine und später p=reject."], effort="15 Min")),
    (r"^sites\|DMARC nur im Beobachtungsmodus", dict(
        why="Mit p=none werden gefälschte Mails nur gemeldet, aber zugestellt.",
        steps=["Wenn die DMARC-Berichte keine legitimen Fehlschläge zeigen: p=quarantine, später p=reject."], effort="15 Min")),
    (r"^sites\|Kein CAA-Eintrag", dict(
        why="Ein CAA-Eintrag legt fest, welche Zertifizierungsstellen Zertifikate für die Domain ausstellen dürfen.",
        steps=["DNS-Eintrag vom Typ CAA anlegen: 0 issue \"letsencrypt.org\"",
               "Gilt automatisch auch für Subdomains."], effort="5 Min")),
    (r"^sites\|Domain nicht auflösbar", dict(
        why="Die Domain ist in Virtualmin angelegt, zeigt aber nicht (mehr) auf diesen Server.",
        steps=["Nicht mehr genutzte Domains in Virtualmin deaktivieren oder unter Einstellungen → Scan-Einstellungen ausschließen."],
        effort="5 Min")),
    (r"^sites\|testssl\.sh", dict(
        why="testssl.sh hat Schwächen in der TLS-Konfiguration gefunden (z. B. schwache Verschlüsselung).",
        steps=["Empfohlene Apache-Einstellungen: https://ssl-config.mozilla.org (Profil „Intermediate“)"], effort="15 Min")),

    # ---------------------------------------------------------------- apps ---
    (r"^apps\|WordPress-Version mit bekannten Sicherheitslücken", dict(
        why="Für diese WordPress-Version sind Sicherheitslücken öffentlich bekannt. Veraltete WordPress-Installationen werden "
            "automatisiert angegriffen.",
        steps=["Backup anlegen, dann im WordPress-Backend: Dashboard → Aktualisierungen",
               "Automatische Hintergrund-Updates für Sicherheitsversionen nicht abschalten."], effort="15 Min")),
    (r"^apps\|WordPress nicht aktuell", dict(
        why="Es gibt eine neuere WordPress-Version. Die installierte hat keine bekannten Lücken, bekommt aber bald keine Korrekturen mehr.",
        steps=["Backup anlegen, dann Dashboard → Aktualisierungen."], effort="15 Min")),
    (r"^apps\|WordPress-Plugins mit bekannten Sicherheitslücken", dict(
        why="Für diese Plugin-Versionen sind Lücken dokumentiert. Plugins sind das häufigste Einfallstor bei WordPress.",
        steps=["Plugin sofort aktualisieren; gibt es keinen Fix, deaktivieren und löschen."], effort="15 Min", alarm=True)),
    (r"^apps\|WordPress-(Plugins|Themes) mit verfügbaren Updates", dict(
        why="Updates schließen oft Sicherheitslücken, auch wenn das nicht dabeisteht.",
        steps=["WordPress-Backend → Plugins bzw. Design → Themes → aktualisieren",
               "Automatische Updates für vertrauenswürdige Plugins aktivieren (Plugins → „Automatische Aktualisierungen aktivieren“).",
               "Nicht genutzte Plugins und Themes löschen – auch deaktivierte können angreifbar sein."], effort="15 Min")),
    (r"^apps\|Plugins ohne Eintrag im WordPress-Verzeichnis", dict(
        why="Diese Plugins stammen nicht aus dem offiziellen Verzeichnis (Premium-Plugins oder eigene). ubusec kann ihre Aktualität "
            "nicht prüfen.",
        steps=["Beim Hersteller prüfen, ob Updates vorliegen; Lizenz für automatische Updates hinterlegen."], effort="prüfen")),
    (r"^apps\|WordPress: Debug-Modus", dict(
        why="Fehlermeldungen mit Pfaden und Details werden Besuchern angezeigt.",
        steps=["In wp-config.php: define('WP_DEBUG', false); oder zusätzlich define('WP_DEBUG_DISPLAY', false);"], effort="5 Min")),
    (r"^apps\|WordPress: Datei-Editor", dict(
        why="Wer ein Admin-Konto übernimmt, kann über den eingebauten Editor direkt PHP-Code auf dem Server ändern.",
        steps=["In wp-config.php ergänzen: define('DISALLOW_FILE_EDIT', true);"], effort="5 Min")),
    (r"^apps\|WordPress: wp-config.php für alle", dict(
        why="Andere Benutzer und Dienste auf dem Server können die Datenbank-Zugangsdaten lesen.",
        steps=["$ chmod 640 <pfad>/wp-config.php"], effort="5 Min")),
    (r"^apps\|WordPress: PHP-Ausführung im Upload-Ordner", dict(
        why="Gelingt es einem Angreifer, eine PHP-Datei hochzuladen, kann er sie im Upload-Ordner direkt ausführen.",
        steps=["Datei wp-content/uploads/.htaccess anlegen mit:",
               "$ <FilesMatch \"\\.(php|phtml|php[0-9])$\">\n  Require all denied\n</FilesMatch>"], effort="5 Min")),
    (r"^apps\|WordPress: xmlrpc.php", dict(
        why="Über xmlrpc.php lassen sich in einer Anfrage hunderte Passwörter durchprobieren. Gebraucht wird es kaum noch "
            "(Ausnahme: alte Apps, Jetpack).",
        steps=["In der .htaccess der Website: <Files xmlrpc.php> Require all denied </Files>",
               "Oder ein Sicherheits-Plugin nutzen, das XML-RPC abschaltet."], effort="5 Min")),
    (r"^apps\|WordPress: Benutzernamen öffentlich", dict(
        why="Mit bekannten Benutzernamen muss ein Angreifer nur noch das Passwort raten.",
        steps=["Starke Passwörter und Zwei-Faktor-Anmeldung für alle Admins (z. B. Plugin „Two Factor“).",
               "REST-Endpunkt für Gäste sperren, z. B. mit einem Sicherheits-Plugin."], effort="15 Min")),
    (r"^apps\|Nextcloud-Version erhält keine", dict(
        why="Diese Nextcloud-Version bekommt keine Sicherheitsupdates mehr.",
        steps=["Backup anlegen, dann schrittweise je eine Hauptversion aktualisieren (Verwaltung → Übersicht → Updater).",
               "Kommandozeile: sudo -u <benutzer> php updater/updater.phar"], effort="1 Std")),
    (r"^apps\|Nextcloud-(Wartungsupdate|Update) verfügbar", dict(
        why="Wartungsupdates enthalten Sicherheitskorrekturen.",
        steps=["Nextcloud → Verwaltung → Übersicht → „Updater öffnen“", "Oder: sudo -u <benutzer> php updater/updater.phar"],
        effort="15 Min")),
    (r"^apps\|Nextcloud-App-Updates", dict(
        why="Auch Apps in Nextcloud können Sicherheitslücken haben.",
        steps=["$ sudo -u <benutzer> php occ app:update --all"], effort="5 Min")),
    (r"^apps\|Nextcloud: Datenverzeichnis öffentlich", dict(
        why="Die Dateien aller Nextcloud-Benutzer sind direkt über den Browser abrufbar.",
        steps=["Sofort sperren: Datenverzeichnis außerhalb des Webverzeichnisses verschieben (occ maintenance:mode --on, "
               "verschieben, 'datadirectory' in config.php anpassen) oder per Apache-Regel sperren.",
               "Prüfen, ob die .htaccess im Datenverzeichnis gelesen wird (AllowOverride All)."], effort="sofort", alarm=True)),
    (r"^apps\|Nextcloud: (Debug-Modus|config\.php)", dict(
        why="Debug-Modus verrät interne Details; eine für alle lesbare config.php gibt Datenbank-Zugangsdaten preis.",
        steps=["In config/config.php: 'debug' => false,", "$ chmod 640 <pfad>/config/config.php"], effort="5 Min")),
    (r"^apps\|Mautic-Hauptversion veraltet", dict(
        why="Ältere Mautic-Hauptversionen erhalten keine Sicherheitsupdates mehr.",
        steps=["Backup (Dateien + Datenbank), dann nach der offiziellen Anleitung aktualisieren: https://docs.mautic.org (Upgrading)"],
        effort="1 Std")),
    (r"^apps\|Mautic-Update verfügbar", dict(
        why="Neuere Mautic-Versionen enthalten Fehler- und Sicherheitskorrekturen.",
        steps=["$ sudo -u <benutzer> php bin/console mautic:update:find", "$ sudo -u <benutzer> php bin/console mautic:update:apply"],
        effort="15 Min")),
    (r"^apps\|Mautic: (interne Verzeichnisse|local\.php)", dict(
        why="Interne Ordner enthalten Konfiguration, Protokolle und Zugangsdaten.",
        steps=["Mautic so einrichten, dass nur der Ordner docroot/ (Mautic 5) öffentlich ist.",
               "Verzeichnisauflistung abschalten (Options -Indexes); local.php: chmod 640"], effort="15 Min")),
    (r"^apps\|Roundcube-(Sicherheitsupdate|Version erhält)", dict(
        why="Roundcube hatte mehrfach schwere, aktiv ausgenutzte Lücken (z. B. Zugriff auf Postfächer über manipulierte Mails). "
            "Als öffentlich erreichbare Webmail muss es aktuell sein.",
        steps=["Backup, dann: aktuelle Version von https://roundcube.net/download laden und mit bin/installto.sh <pfad> einspielen.",
               "Wenn Roundcube aus Virtualmin/Paketen stammt: sudo apt update && sudo apt upgrade"], effort="15 Min")),
    (r"^apps\|Neuere Roundcube-Versionslinie", dict(
        why="Die installierte Versionslinie wird noch gepflegt, eine neuere ist verfügbar.",
        steps=["Bei Gelegenheit auf die neue Versionslinie wechseln (bin/installto.sh)."], effort="1 Std")),
    (r"^apps\|Roundcube: (Installer|Protokolldateien)", dict(
        why="Der Installer erlaubt das Auslesen und Ändern der Konfiguration; Protokolle enthalten E-Mail-Adressen und Fehlerdetails.",
        steps=["Installer-Verzeichnis löschen: rm -r <pfad>/installer und in config.inc.php enable_installer entfernen",
               "logs/ und temp/ dürfen nicht öffentlich sein (.htaccess mit Require all denied, AllowOverride prüfen)."],
        effort="5 Min")),
    (r"^apps\|(Datenbank-Dumps|Schlüssel- oder Zugangsdateien|Sicherungskopien|Archive/Backups) .*öffentlich", dict(
        why="Diese Dateien liegen im Webverzeichnis und können heruntergeladen werden.",
        steps=["Dateien sofort aus dem Webverzeichnis entfernen (z. B. nach /home/<benutzer>/backups).",
               "Enthaltene Zugangsdaten ändern."], effort="sofort", alarm=True)),
    (r"^apps\|Sensible Dateien im Webverzeichnis \(gesperrt", dict(
        why="Die Dateien sind derzeit nicht abrufbar, gehören aber nicht ins Webverzeichnis – eine Konfigurationsänderung kann sie freilegen.",
        steps=["Außerhalb des Webverzeichnisses ablegen, z. B. /home/<benutzer>/backups/"], effort="5 Min")),
    (r"^apps\|phpinfo\(\)-Dateien", dict(
        why="phpinfo() verrät Serverdetails.", steps=["Datei löschen."], effort="5 Min")),
    (r"^apps\|PHP-Anwendung verbindet sich als MySQL-root", dict(
        why="Wird die Anwendung übernommen (z. B. per SQL-Injection), hat der Angreifer Zugriff auf alle Datenbanken des Servers.",
        steps=["Eigenen Datenbankbenutzer nur für diese Datenbank anlegen:",
               "$ CREATE USER 'app'@'localhost' IDENTIFIED BY '<passwort>'; GRANT SELECT,INSERT,UPDATE,DELETE ON appdb.* TO 'app'@'localhost';",
               "Zugangsdaten in der Anwendung umstellen."], effort="15 Min")),
    (r"^apps\|Möglicher SQL-Injection-Code", dict(
        why="Benutzereingaben ($_GET, $_POST …) werden direkt in einen SQL-Befehl eingebaut. Damit lassen sich oft beliebige "
            "Datenbankabfragen ausführen. Hinweis aus automatischer Code-Analyse – bitte jede Stelle ansehen.",
        steps=["Vorbereitete Anweisungen verwenden:",
               "$ $stmt = $pdo->prepare('SELECT * FROM schueler WHERE id = ?'); $stmt->execute([$_GET['id']]);",
               "Bei mysqli: $stmt = $db->prepare('… WHERE id = ?'); $stmt->bind_param('i', $id);"], effort="1 Std")),
    (r"^apps\|Ungefilterte Ausgabe von Benutzereingaben", dict(
        why="Eingaben werden ungefiltert ausgegeben – damit lässt sich fremdes JavaScript in die Seite schleusen (XSS).",
        steps=["Ausgaben immer maskieren:", "$ echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');"], effort="15 Min")),
    (r"^apps\|PHP-Version ohne Sicherheitsupdates", dict(
        why="Diese PHP-Version (nicht aus dem Ubuntu-Archiv, z. B. aus einem PPA) bekommt keine Sicherheitsupdates mehr.",
        steps=["Betroffene Domains in Virtualmin auf eine aktuelle PHP-Version umstellen (Domain → Web Configuration → PHP Options).",
               "Danach die alte Version entfernen: sudo apt purge phpX.Y-*"], effort="1 Std")),
    (r"^apps\|PHP: display_errors", dict(
        why="Fehlermeldungen mit Pfaden und Code-Details werden Besuchern angezeigt.",
        steps=["In der genannten php.ini: display_errors = Off und log_errors = On"], effort="5 Min")),
    (r"^apps\|PHP: allow_url_include", dict(
        why="Erlaubt das Einbinden von Code über das Internet – ein klassischer Weg für Angriffe.",
        steps=["In der php.ini: allow_url_include = Off"], effort="5 Min")),
    (r"^apps\|PHP: (expose_php|Session-Cookies)", dict(
        why="expose_php verrät die PHP-Version; Session-Cookies ohne HttpOnly können per JavaScript gestohlen werden.",
        steps=["In der php.ini: expose_php = Off und session.cookie_httponly = 1"], effort="5 Min")),
    (r"^apps\|MySQL/MariaDB: (anonyme|Benutzer ohne Passwort)", dict(
        why="Ohne Passwort kann sich jeder lokale Prozess (z. B. eine gehackte Website) mit der Datenbank verbinden.",
        steps=["$ sudo mariadb-secure-installation", "Oder gezielt: DROP USER ''@'localhost'; bzw. ALTER USER … IDENTIFIED BY '…';"],
        effort="15 Min")),
    (r"^apps\|MySQL/MariaDB: root darf sich von außen", dict(
        why="root ist der wichtigste Datenbank-Zugang und sollte nur lokal nutzbar sein.",
        steps=["$ DROP USER 'root'@'%';  (oder den betroffenen Host)", "Firewall: Port 3306 nicht öffentlich freigeben."],
        effort="5 Min")),
    (r"^apps\|MySQL/MariaDB: Benutzer dürfen sich von beliebigen", dict(
        why="Webanwendungen auf demselben Server brauchen nur Zugriff von localhost.",
        steps=["Benutzer auf localhost beschränken: RENAME USER 'app'@'%' TO 'app'@'localhost';"], effort="15 Min")),
    (r"^apps\|MySQL/MariaDB: Testdatenbank", dict(
        why="Die Testdatenbank ist für alle Benutzer beschreibbar und wird nicht gebraucht.",
        steps=["$ sudo mariadb -e 'DROP DATABASE test;'"], effort="5 Min")),
    (r"^apps\|(MariaDB|MySQL)-Version erhält keine", dict(
        why="Für diese Datenbankversion gibt es keine Sicherheitsupdates mehr.",
        steps=["Auf eine unterstützte Version aktualisieren (vorher alle Datenbanken sichern)."], effort="1 Std")),

    # --------------------------------------------------------------- tools ---
    (r"^tools\|Updates für Prüfwerkzeuge", dict(
        why="Neuere Versionen der Prüfwerkzeuge erkennen neue Bedrohungen und haben weniger Fehlalarme. Ein veralteter "
            "Scanner meldet „alles in Ordnung“, weil er Neues schlicht nicht kennt.",
        steps=["Weboberfläche → Werkzeuge → „Werkzeuge aktualisieren“", "Oder auf dem Server: sudo ubusec --update-tools"],
        effort="5 Min")),
    (r"^tools\|ClamAV-Virensignaturen", dict(
        why="Ohne aktuelle Signaturen erkennt ClamAV keine neue Schadsoftware. Täglich kommen tausende neue Signaturen dazu.",
        steps=["$ sudo systemctl enable --now clamav-freshclam", "Prüfen: sudo journalctl -u clamav-freshclam -n 20",
               "Häufige Ursache: der Server erreicht database.clamav.net nicht (Firewall, DNS)."], effort="5 Min")),
    (r"^tools\|ClamAV-Signaturdienst", dict(
        why="Der Dienst clamav-freshclam holt mehrmals täglich neue Signaturen. Ohne ihn sind sie nur nach einem Scan aktuell.",
        steps=["$ sudo systemctl enable --now clamav-freshclam"], effort="5 Min")),
    (r"^tools\|CVE-Daten", dict(
        why="Die Schwachstellen-Datenbank von Canonical wird mehrmals täglich ergänzt. Veraltete Daten übersehen neue Lücken.",
        steps=["$ curl -I https://security-metadata.canonical.com/oval/", "Firewall- und DNS-Einstellungen für ausgehende Verbindungen prüfen."],
        effort="15 Min")),
    (r"^tools\|Lynis veraltet", dict(
        why="Ubuntu liefert Lynis oft in einer Version aus, die ein bis zwei Jahre alt ist. Neue Prüfungen und Korrekturen fehlen dann.",
        steps=["Weboberfläche → Werkzeuge → „Lynis-Paketquelle des Herstellers einrichten“",
               "Oder auf dem Server: sudo ubusec --lynis-upstream",
               "Danach kommen Lynis-Updates direkt vom Hersteller (CISOfy) über apt."], effort="5 Min")),
    (r"^tools\|Neue ubusec-Version", dict(
        why="Eine neue ubusec-Version ist auf GitHub erschienen – mit neuen Prüfungen oder Korrekturen.",
        steps=["Änderungen ansehen: Weboberfläche → Werkzeuge", "$ sudo ubusec --update"], effort="5 Min")),

    # ------------------------------------------------------------ allgemein ---
    (r"\|.* nicht installiert – Teilprüfung übersprungen", dict(
        why="Ohne dieses Werkzeug fehlt ein Teil der Prüfung.",
        steps=["$ sudo ubusec --install"], effort="5 Min")),
]

_COMPILED = [(re.compile(p), h) for p, h in _H]

GENERIC = dict(why="", steps=[], effort="prüfen")


def hint_for(module, message, details=()):
    key = f"{module}|{message}"
    for rx, h in _COMPILED:
        if rx.search(key):
            return h
    fix = [d.split(":", 1)[1].strip() for d in details if d.startswith("Beheben")]
    return dict(GENERIC, steps=[f"$ {f}" for f in fix])
