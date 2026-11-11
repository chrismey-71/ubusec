#!/usr/bin/env python3
"""ubusec – Weboberfläche.

Läuft als unprivilegierter Benutzer "ubusec". Liest Berichte aus /var/log/ubusec
und legt Scan-Aufträge in /var/lib/ubusec/queue ab; ausgeführt werden sie von
root über die systemd-Unit ubusec-queue.path, die jeden Auftrag erneut prüft.

  ubusec_web.py serve                 Server starten (über systemd)
  ubusec_web.py useradd NAME [--totp] Benutzer anlegen / Passwort ändern (als root)
  ubusec_web.py userdel NAME          Benutzer löschen (als root)
"""
import base64
import getpass
import glob
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from datetime import datetime
from functools import wraps

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from hints import INCIDENT, hint_for  # noqa: E402

CONF_DIR = os.environ.get("UBUSEC_CONF", "/etc/ubusec")
STATE_DIR = os.environ.get("UBUSEC_STATE", "/var/lib/ubusec")
LOG_DIR = os.environ.get("UBUSEC_LOG", "/var/log/ubusec")
QUEUE_DIR = os.path.join(STATE_DIR, "queue")
WEB_STATE = os.path.join(STATE_DIR, "web")
USERS_FILE = os.path.join(WEB_STATE, "users")
OLD_USERS_FILE = os.path.join(CONF_DIR, "web-users")      # bis Version 1.1
LOGINS_FILE = os.path.join(WEB_STATE, "logins.json")
IGNORE_FILE = os.path.join(CONF_DIR, "ignore.list")
DAYS = [("Mon", "Mo"), ("Tue", "Di"), ("Wed", "Mi"), ("Thu", "Do"), ("Fri", "Fr"), ("Sat", "Sa"), ("Sun", "So")]
# gleiche Prüfregeln wie in ubusec (root prüft dort noch einmal)
SETTING_RX = {
    "MAIL_TO": r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(,[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}){0,4})?",
    "NTFY_URL": r"(https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~%-]*){0,6})?",
    "NOTIFY_MIN": r"KRITISCH|HOCH|MITTEL",
    "NOTIFY_ONLY_NEW": r"[01]",
    "KEEP_DAYS": r"([7-9]|[1-9][0-9]|[12][0-9][0-9]|3[0-5][0-9]|36[0-5])",
    "CLAM_PATHS_QUICK": r"/[A-Za-z0-9._/-]*( /[A-Za-z0-9._/-]*){0,19}",
    "CLAM_MAX_FILESIZE": r"(25|50|100|200|400)M",
    "WEB_PATHS": r"/[A-Za-z0-9._/-]*( /[A-Za-z0-9._/-]*){0,19}",
    "SITES_EXCLUDE": r"[A-Za-z0-9.*_ -]{0,500}",
    "SITES_EXTRA": r"[A-Za-z0-9. -]{0,500}",
    "SITES_TESTSSL": r"[01]",
    "WPSCAN_API_TOKEN": r"[A-Za-z0-9]{0,64}",
    "CLAM_PARALLEL": r"([0-9]|1[0-6])",
    "CLAM_ENGINE": r"auto|clamscan",
    "CLAM_QUICK_CHANGED": r"[01]",
    "UPDATE_CHECK": r"[01]",
    "CLAM_EXCLUDE_DB": r"[01]", "CLAM_EXCLUDE_BACKUPS": r"[01]", "CLAM_EXCLUDE_LOGS": r"[01]",
    "CLAM_EXCLUDE_MAIL": r"[01]", "CLAM_EXCLUDE_NEXTCLOUD": r"[01]",
    "CLAM_EXCLUDE_CUSTOM": r"(/[A-Za-z0-9._/-]*( /[A-Za-z0-9._/-]*){0,29})?",
}
CHECKBOX_KEYS = {"UPDATE_CHECK", "CLAM_QUICK_CHANGED", "NOTIFY_ONLY_NEW", "SITES_TESTSSL", "CLAM_EXCLUDE_DB", "CLAM_EXCLUDE_BACKUPS", "CLAM_EXCLUDE_LOGS",
                 "CLAM_EXCLUDE_MAIL", "CLAM_EXCLUDE_NEXTCLOUD"}
PATH_KEYS = {"CLAM_PATHS_QUICK", "WEB_PATHS", "SITES_EXCLUDE", "SITES_EXTRA", "CLAM_EXCLUDE_CUSTOM"}
SETTING_LABEL = {
    "MAIL_TO": "E-Mail-Adresse", "NTFY_URL": "ntfy-Adresse", "KEEP_DAYS": "Aufbewahrung",
    "CLAM_PATHS_QUICK": "Ordner für den Virenscan", "WEB_PATHS": "Webverzeichnisse",
    "SITES_EXCLUDE": "Ausgeschlossene Domains", "SITES_EXTRA": "Zusätzliche Domains", "WPSCAN_API_TOKEN": "WPScan-Token",
    "CLAM_PARALLEL": "Parallele Prüfungen", "CLAM_ENGINE": "Virenscanner", "CLAM_EXCLUDE_CUSTOM": "Weitere ausgenommene Ordner",
}

MODULES = [
    ("tools", "Prüfwerkzeuge", "Sind ClamAV, Lynis, rkhunter & Co. und ihre Signaturen aktuell?"),
    ("updates", "Updates & Neustarts", "Ausstehende Updates, Neustartbedarf, Support-Status"),
    ("cve", "CVE-Schwachstellen", "Bekannte Lücken installierter Pakete (Ubuntu OVAL)"),
    ("config", "Konfiguration & Härtung", "Lynis-Audit, SSH, Kernel-Parameter, Konten"),
    ("perms", "Dateiberechtigungen", "Kritische Dateien, world-writable, SUID – dauert einige Minuten"),
    ("firewall", "Firewall & Ports", "Aktive Firewall, offene und riskante Ports"),
    ("integrity", "Datei-Integrität", "Veränderte Programmdateien, AIDE"),
    ("baseline", "Änderungen ggü. Baseline", "Neue Konten, Schlüssel, Ports, Cronjobs, Dienste"),
    ("rootkit", "Rootkits & Einbruchsspuren", "rkhunter, chkrootkit, verdächtige Prozesse und Dateien"),
    ("malware", "Malware (ClamAV)", "Virenscan – beim Vollscan über das ganze System"),
    ("web", "Webshells & Web-Malware", "PHP-Webshells, PHP in Upload-Ordnern"),
    ("sites", "Websites & Domains", "HTTPS, Zertifikate, Sicherheits-Header, offene Dateien, SPF/DMARC/CAA"),
    ("apps", "Webanwendungen", "WordPress, Nextcloud, Mautic, Roundcube, eigene PHP-Apps, PHP, MySQL"),
]
MOD_TITLE = {m: t for m, t, _ in MODULES}
QUICK = ["tools", "updates", "cve", "firewall", "integrity", "baseline", "rootkit", "malware"]
SEVERITIES = ["KRITISCH", "HOCH", "MITTEL", "NIEDRIG", "INFO"]
SEV_NAME = {"KRITISCH": "Kritisch", "HOCH": "Hoch", "MITTEL": "Mittel", "NIEDRIG": "Niedrig", "INFO": "Info"}
def read_version():
    here = os.path.dirname(os.path.abspath(__file__))
    for p in (os.path.join(here, "VERSION"), os.path.join(here, "..", "ubusec")):
        try:
            txt = open(p, encoding="utf-8", errors="replace").read(4096)
        except OSError:
            continue
        m = re.search(r'UBUSEC_VERSION="([^"]+)"', txt) or re.match(r"\s*([0-9][0-9A-Za-z.\-]*)\s*$", txt)
        if m:
            return m.group(1)
    return "?"


VERSION = read_version()
REPORT_ID = re.compile(r"^\d{8}-\d{6}-(quick|full)$")
USERNAME = re.compile(r"^[A-Za-z0-9._-]{1,32}$")


# =============================================================================
#  Konfiguration
# =============================================================================
def read_conf():
    conf = {"BIND": "127.0.0.1", "PORT": "8765", "SECURE_COOKIES": "0",
            "TRUST_PROXY": "0", "SESSION_MINUTES": "30"}
    try:
        for line in open(os.path.join(CONF_DIR, "web.conf"), encoding="utf-8"):
            line = line.split("#", 1)[0].strip()
            if "=" in line:
                k, v = line.split("=", 1)
                conf[k.strip()] = v.strip().strip('"\'')
    except FileNotFoundError:
        pass
    return conf


# =============================================================================
#  Passwörter (scrypt) und TOTP (RFC 6238)
# =============================================================================
SCRYPT = dict(n=2 ** 15, r=8, p=1, maxmem=64 * 1024 * 1024, dklen=32)


def hash_pw(pw):
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, **SCRYPT)
    return "scrypt$%s$%s" % (base64.b64encode(salt).decode(), base64.b64encode(h).decode())


def check_pw(pw, stored):
    try:
        kind, salt, h = stored.split("$")
        if kind != "scrypt":
            return False
        calc = hashlib.scrypt(pw.encode(), salt=base64.b64decode(salt), **SCRYPT)
        return hmac.compare_digest(calc, base64.b64decode(h))
    except Exception:
        return False


DUMMY_HASH = hash_pw(secrets.token_hex(8))  # gleiche Rechenzeit bei unbekanntem Benutzer


def totp_at(secret_b32, counter):
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)
    d = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = d[-1] & 0x0F
    return "%06d" % ((struct.unpack(">I", d[o:o + 4])[0] & 0x7FFFFFFF) % 1000000)


def totp_check(secret_b32, code, last_used=-1):
    """Gibt den verwendeten Zähler zurück oder None. Erlaubt ±30 s, keine Wiederverwendung."""
    code = re.sub(r"\s", "", code or "")
    if not re.fullmatch(r"\d{6}", code):
        return None
    now = int(time.time() // 30)
    for c in (now - 1, now, now + 1):
        if c > last_used and hmac.compare_digest(totp_at(secret_b32, c), code):
            return c
    return None


def load_users():
    users = {}
    path = USERS_FILE if os.path.exists(USERS_FILE) else OLD_USERS_FILE
    try:
        for line in open(path, encoding="utf-8"):
            parts = line.strip().split(":")
            if len(parts) >= 2 and USERNAME.match(parts[0]):
                users[parts[0]] = {"hash": parts[1], "totp": parts[2] if len(parts) > 2 else ""}
    except (FileNotFoundError, PermissionError):
        pass
    return users


def pw_version(u):
    """Kennung des aktuellen Passworts – ändert sich mit jedem neuen Passwort (beendet alte Sitzungen)."""
    return hashlib.sha256(u["hash"].encode()).hexdigest()[:16]


def save_users(users):
    tmp = USERS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        for n, u in sorted(users.items()):
            f.write("%s:%s:%s\n" % (n, u["hash"], u.get("totp", "")))
    os.chmod(tmp, 0o600)
    os.replace(tmp, USERS_FILE)


# =============================================================================
#  Berichte
# =============================================================================
_cache = {}
_cache_lock = threading.Lock()


def load_report(path):
    try:
        st = os.stat(path)
    except OSError:
        return None
    with _cache_lock:
        c = _cache.get(path)
        if c and c[0] == st.st_mtime:
            return c[1]
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError):
        return None
    for i, fd in enumerate(doc.get("findings", [])):
        fd["idx"] = i
        fd["hint"] = hint_for(fd["module"], fd["message"], fd.get("details", []))
        fd["verify"] = verify_spec(fd)
    for fd in doc.get("findings", []):
        fd["fixes"] = fix_specs(fd, doc)
    with _cache_lock:
        _cache[path] = (st.st_mtime, doc)
    return doc


# ------------------------------------------------------------ Nachprüfung auf Knopfdruck ---
VERIFY_DIR = os.path.join(STATE_DIR, "verify")
VERIFY_PENDING = os.path.join(WEB_STATE, "verify-pending")
_PATH_TOKEN = re.compile(r"(?<![\w.])(/(?:tmp|var|dev|etc|usr|bin|sbin|lib|lib64|opt|home|root|srv|run)/[A-Za-z0-9._/@+:-]{1,300})")
VERIFY_TEXT = {
    "binaries": ("Soll ubusec das für dich prüfen?",
                 "ubusec lädt das Ubuntu-Paket in der installierten Version frisch herunter und vergleicht die Programme "
                 "byte-genau mit dem Original. Ändert nichts am System."),
    "pkgfiles": ("Soll ubusec das für dich prüfen?",
                 "ubusec lädt die zugehörigen Ubuntu-Pakete frisch herunter und vergleicht die Dateien byte-genau mit dem "
                 "Original. Ändert nichts am System."),
    "fileinfo": ("Soll ubusec die Dateien für dich ansehen?",
                 "Steckbrief je Datei: Art, Größe, Besitzer, Änderungsdatum, Prüfsumme, zugehöriges Paket und welche "
                 "Prozesse sie gerade nutzen. Ändert nichts am System."),
    "phpscan": ("Soll ubusec die Dateien auf Schadcode prüfen?",
                "Untersucht jede Datei auf typische Befehle von Webshells (eval/base64, Ausführen von Eingaben, Upload-Funktionen) "
                "und prüft sie mit dem Virenscanner. Zeigt außerdem Größe, Besitzer, Datum und die erste Zeile. Ändert nichts."),
    "ports": ("Soll ubusec für dich nachsehen, wer dort lauscht?",
              "Zeigt je Port das Programm, seinen Speicherort, ob es aus einem Ubuntu-Paket stammt und ob es öffentlich "
              "oder nur lokal erreichbar ist. Ändert nichts am System."),
}


def verify_spec(f):
    """Welche Nachprüfung passt zu diesem Befund? (Art, Argumente) oder None – nur aus dem Befund abgeleitet."""
    mod, msg, det = f.get("module"), f.get("message", ""), f.get("details", [])
    text = " ".join([msg] + det)
    kind, args = None, []
    if mod == "rootkit" and "INFECTED" in text and "bindshell" not in text:
        kind = "binaries"
        args = re.findall(r"Checking `([a-z0-9._+-]{1,40})'", text)
        for d in det:
            m = re.match(r"Paket \S+: (.*)$", d)
            if m:
                args += [re.sub(r"\(.*", "", x) for x in m.group(1).split()]
    elif mod == "integrity" and ("Paket-Original" in msg or "Paketdateien verändert" in msg):
        kind, args = "pkgfiles", [d for d in det if re.fullmatch(r"/[A-Za-z0-9._/@+:-]{1,300}", d)]
    elif mod in ("firewall",) and re.search(r"lauschen öffentlich|öffentlich erreichbar", msg) or \
            (mod == "rootkit" and "bindshell" in text):
        kind = "ports"
        args = re.findall(r"(?<![\d.])(\d{1,5})/(?:tcp|udp)", msg) or re.findall(r"ports?:\s*([\d ]+)", text)
        args = [a for x in args for a in str(x).split()]
    elif mod == "rootkit" and re.search(r"BPFDoor|Packet Sniffer|Paketdateien wurden verändert", msg):
        kind = "pkgfiles"
        args = [m for m in _PATH_TOKEN.findall(text) if not m.startswith((LOG_DIR + "/", STATE_DIR + "/", "/proc/"))]
    elif mod == "web" and re.search(r"PHP-Dateien in Upload|Webshell-Mustern|Testdateien von Anwendungen", msg):
        kind, args = "phpscan", [d for d in det if re.fullmatch(r"/[A-Za-z0-9._/@+:-]{1,300}", d)]
    elif mod == "rootkit" and re.search(r"temporären|/dev/shm|versteckte|Hidden|aus gelöschten|Linux\.Xor\.DDoS", text):
        kind = "fileinfo"
        # ubusecs eigene Rohdaten-Listen („… und N weitere“) nicht mitprüfen
        args = [m.rstrip(":") for m in _PATH_TOKEN.findall(text) if not m.startswith((LOG_DIR + "/", STATE_DIR + "/"))]
    args = list(dict.fromkeys(a for a in args if a))[:20]
    if not kind or not args:
        return None
    vid = hashlib.sha256(("%s|%s" % (kind, " ".join(sorted(args)))).encode()).hexdigest()[:16]
    title, text = VERIFY_TEXT[kind]
    return {"kind": kind, "args": args, "id": vid, "title": title, "text": text}


def verify_result(vid):
    res = read_json(os.path.join(VERIFY_DIR, vid + ".json"), None)
    try:
        asked = os.path.getmtime(os.path.join(VERIFY_PENDING, vid))
    except OSError:
        asked = 0
    pending = asked and time.time() - asked < 1200 and (not res or res.get("time", 0) < asked - 1)
    return res, bool(pending)


# ------------------------------------------------------------ Korrekturen auf Knopfdruck ---
FIX_DIR = os.path.join(STATE_DIR, "fixes")
FIX_PENDING = os.path.join(WEB_STATE, "fix-pending")
FIX_TEXT = {
    "wp-chmod": ("wp-config.php schützen (chmod 640)",
                 "Setzt die Rechte von {t} auf 640: nur Besitzer und Gruppe dürfen die Datei lesen. Danach ruft ubusec die "
                 "Website auf und nimmt die Änderung sofort zurück, falls sie nicht mehr antwortet."),
    "wp-fileedit": ("Datei-Editor im Backend abschalten",
                    "Fügt in {t} vor „That's all, stop editing“ die Zeile define('DISALLOW_FILE_EDIT', true); ein. "
                    "Vorher wird gesichert; PHP prüft die Datei, und ubusec testet danach die Website."),
    "wp-archive-block": ("Archive in diesem Ordner für das Web sperren",
                         "Ergänzt {t}/.htaccess (oder legt sie an): .zip, .tar.gz usw. sind dann über die Website nicht mehr "
                         "abrufbar. Die Datei bleibt liegen – das Theme/Plugin braucht sie oft selbst (z. B. Impreza für "
                         "„US Core“). Rückgängig jederzeit möglich."),
    "wp-uploads": ("PHP-Ausführung im Upload-Ordner sperren",
                   "Ergänzt {t}/.htaccess (oder legt sie an) mit einer Sperre für .php-Dateien. Bilder und andere Uploads "
                   "bleiben abrufbar."),
    "wp-xmlrpc": ("xmlrpc.php sperren",
                  "Setzt ganz oben in {t}/.htaccess – vor den Blöcken von WordPress und Wordfence – eine Sperre für "
                  "xmlrpc.php. Nicht verwenden, wenn du die WordPress-App oder Jetpack nutzt."),
    "sysctl": ("Kernel-Parameter härten",
               "Schreibt die empfohlenen Werte nach /etc/sysctl.d/99-ubusec.conf und setzt sie sofort. IP-Weiterleitung "
               "(für Docker/VPN) bleibt unberührt."),
    "ssh-safe": ("SSH: X11Forwarding aus, MaxAuthTries 4",
                 "Legt /etc/ssh/sshd_config.d/01-ubusec.conf an, prüft sie mit sshd -t und lädt SSH neu. Bestehende "
                 "Sitzungen bleiben offen. Danach bitte sofort in einem neuen Terminal anmelden – bietet dein SSH-Programm "
                 "sehr viele Schlüssel an, kann die Grenze von 4 Versuchen greifen (dann „Rückgängig machen“)."),
    "ssh-root-keyonly": ("Root nur noch mit SSH-Schlüssel anmelden",
                         "Setzt PermitRootLogin prohibit-password (Datei /etc/ssh/sshd_config.d/00-ubusec-root.conf), "
                         "prüft mit sshd -t und lädt SSH neu. ubusec macht das nur, wenn du dich in den letzten 30 Tagen "
                         "schon einmal mit einem eingetragenen Schlüssel als root angemeldet hast – sonst wirst du auf die "
                         "Anleitung „SSH-Schlüssel“ verwiesen. Bestehende Sitzungen bleiben offen."),
    "postfix-banner": ("Postfix-Banner verkürzen, VRFY abschalten",
                       "Setzt smtpd_banner = $myhostname ESMTP und disable_vrfy_command = yes, prüft mit postfix check und "
                       "lädt Postfix neu. Mails werden weiter normal zugestellt."),
    "bind-version": ("BIND-Version verbergen",
                     "Ergänzt version \"none\"; im options-Block von /etc/bind/named.conf.options, prüft mit "
                     "named-checkconf und lädt BIND neu."),
    "php-ini": ("php.ini anpassen",
                "Setzt in {t} session.cookie_httponly = 1 und expose_php = Off und lädt PHP-FPM neu."),
    "quarantine": ("In die Sicherung verschieben",
                   "Verschiebt {t} aus dem Webverzeichnis in die Sicherung von ubusec. „Rückgängig machen“ legt die "
                   "Datei unverändert zurück."),
    "sticky": ("Sticky-Bit setzen",
               "Setzt für {t} das Sticky-Bit (chmod +t, wie bei /tmp): Alle dürfen dort weiter Dateien anlegen, aber nur der "
               "jeweilige Besitzer darf sie löschen oder umbenennen. Laufende Dienste merken davon nichts."),
    "svc-rpcbind": ("rpcbind abschalten",
                    "Stoppt rpcbind und startet es nicht mehr beim Hochfahren. ubusec prüft vorher, dass kein NFS genutzt "
                    "wird, und bricht sonst ab."),
}


def fix_specs(f, report):
    """Passende Korrekturen zu einem Befund – Ziele nur aus den Befunddetails, nie aus Benutzereingaben."""
    mod, msg, det = f.get("module"), f.get("message", ""), f.get("details", [])
    # Zuordnung Pfad → Domain aus allen WordPress-Hinweisen des Berichts („domain: in /pfad …“)
    dom = {}
    for g in report.get("findings", []):
        for d in g.get("details", []):
            m = re.match(r"^([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?:/\S*)?: in (/\S+)", d)
            if m:
                dom[os.path.dirname(m.group(2))] = m.group(1)
    out = []

    def add(kind, target, domain=""):
        if not domain:
            domain = next((v for k, v in dom.items() if target.startswith(k) or k.startswith(target)), "")
        fid = hashlib.sha256(("%s|%s" % (kind, target)).encode()).hexdigest()[:16]
        title, text = FIX_TEXT[kind]
        out.append({"kind": kind, "target": target, "domain": domain, "id": fid, "title": title,
                    "text": text.format(t=target)})
    for d in det:
        m = re.match(r"^Befehl: sudo chmod 640 (/\S+/wp-config\.php)$", d)
        if m and "wp-config.php für alle" in msg:
            add("wp-chmod", m.group(1))
        m = re.match(r"^([A-Za-z0-9.-]+)(?:/\S*)?: in (/\S+/wp-config\.php) vor", d)
        if m and "Datei-Editor" in msg:
            add("wp-fileedit", m.group(2), m.group(1))
        m = re.search(r"tee -a (/\S+/wp-content/uploads)/\.htaccess$", d)
        if m and "Upload-Ordner" in msg:
            add("wp-uploads", m.group(1))
        m = re.match(r"^([A-Za-z0-9.-]+)(?:/\S*)?: in (/\S+)/\.htaccess oberhalb", d)
        if m and "xmlrpc" in msg:
            add("wp-xmlrpc", m.group(2), m.group(1))
    if mod == "firewall" and re.search(r"(^|\s|: )111/(tcp|udp)\(rpcbind\)", msg):
        add("svc-rpcbind", "rpcbind")
    if mod == "perms" and "Verzeichnisse für alle beschreibbar ohne Sticky-Bit" in msg:
        for d in det:
            if re.fullmatch(r"/[A-Za-z0-9._/@+:-]{1,300}", d):
                add("sticky", d)
    if mod == "config" and "Kernel-Parameter (sysctl) nicht gehärtet" in msg:
        add("sysctl", "kernel")
    if mod == "config" and msg.startswith("SSH: Root-Login mit Passwort erlaubt"):
        add("ssh-root-keyonly", "sshd")
    if mod == "config" and re.match(r"SSH: (X11Forwarding aktiv|MaxAuthTries)", msg):
        add("ssh-safe", "sshd")
    if mod == "config" and "information disclosure in SMTP banner" in msg:
        add("postfix-banner", "postfix")
    if mod == "config" and "Found BIND version in banner" in msg:
        add("bind-version", "bind")
    if mod == "apps" and re.match(r"PHP: (Session-Cookies ohne HttpOnly|expose_php aktiv)", msg):
        for d in det:
            if re.fullmatch(r"/(etc/php|home)/[A-Za-z0-9._/-]{1,200}/php\.ini", d):
                add("php-ini", d)
    if mod == "web" and "PHP-Dateien in Upload" in msg:
        ups = []
        for d in det:
            if re.fullmatch(r"/[A-Za-z0-9._/@+:-]{1,300}\.(php[0-9]?|phtml)", d):
                add("quarantine", d)
                m = re.match(r"^(/.+/wp-content/uploads)/", d)
                if m and m.group(1) not in ups and "gesperrt" not in msg:
                    ups.append(m.group(1))
        for u in ups:
            add("wp-uploads", u)
    last_host = ""
    for d in det:
        mh = re.match(r"^https?://([A-Za-z0-9.-]+)/", d)
        if mh:
            last_host = mh.group(1)
        m = re.match(r"^(?:Datei|Ordner): (/\S+)$", d)
        if m and re.search(r"phpinfo|\.DS_Store|Roundcube: Installer", msg):
            add("quarantine", m.group(1))
        elif m and "Archive in Plugin" in msg and "/wp-content/" in m.group(1):
            dd = os.path.dirname(m.group(1))
            if not any(x["kind"] == "wp-archive-block" and x["target"] == dd for x in out):
                add("wp-archive-block", dd, last_host)
    for x in out:
        if not (re.fullmatch(r"/(home|var/www|srv|etc/php)/[A-Za-z0-9._/@+:-]{1,300}|rpcbind|kernel|sshd|postfix|bind", x["target"])
                or (x["kind"] == "sticky" and re.fullmatch(r"/[A-Za-z0-9._/@+:-]{1,300}", x["target"]))):
            x["blocked"] = True   # Pfad mit Sonderzeichen – nur von Hand
    return [x for x in out if not x.get("blocked")]


def fix_result(fid):
    res = read_json(os.path.join(FIX_DIR, fid + ".json"), None)
    try:
        asked = os.path.getmtime(os.path.join(FIX_PENDING, fid))
    except OSError:
        asked = 0
    pending = asked and time.time() - asked < 600 and (not res or res.get("time", 0) < asked - 1)
    return res, bool(pending)


def report_paths():
    return sorted(glob.glob(os.path.join(LOG_DIR, "report-*.json")), reverse=True)


def all_reports(limit=None):
    out = []
    for p in report_paths():
        d = load_report(p)
        if d:
            out.append(d)
            if limit and len(out) >= limit:
                break
    return out


def get_report(rid):
    if not REPORT_ID.match(rid or ""):
        return None
    return load_report(os.path.join(LOG_DIR, "report-%s.json" % rid))


def ignore_regexes():
    """Fehlalarm-Muster aus ignore.list – damit Ausgeblendetes sofort verschwindet, nicht erst beim nächsten Scan."""
    rx = []
    for e in ignore_entries() or []:
        try:
            rx.append(re.compile(e["pattern"]))
        except re.error:
            pass
    return rx


def recs_reset_time():
    try:
        return os.path.getmtime(os.path.join(STATE_DIR, "recs-reset"))
    except OSError:
        return 0


def current_state(reports):
    """Aktueller Gesamtstand: je Modul die Meldungen aus dem jüngsten Scan, der es geprüft hat
    (nur Scans nach einem „Empfehlungen neu beginnen“)."""
    reset = recs_reset_time()
    reports = [r for r in reports if r.get("started", 0) >= reset]
    seen, findings, sources = set(), [], {}
    ign = ignore_regexes()
    for r in reports:
        for m in r.get("modules", {}):
            if m in seen:
                continue
            seen.add(m)
            sources[m] = r
            for f in r["findings"]:
                if f["module"] == m and not any(x.search("%s|%s|" % (f["module"], f["message"])) for x in ign):
                    findings.append(dict(f, report=r["id"]))
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    order = {m: i for i, (m, _, _) in enumerate(MODULES)}
    findings.sort(key=lambda f: (rank.get(f["severity"], 9), order.get(f["module"], 99)))
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
    w = {"KRITISCH": 25, "HOCH": 10, "MITTEL": 4, "NIEDRIG": 1, "INFO": 0}
    score = max(0, 100 - sum(w[s] * counts[s] for s in SEVERITIES)) if reports else None
    return {"findings": findings, "counts": counts, "score": score, "sources": sources,
            "missing": [m for m, _, _ in MODULES if m not in seen]}


def _n(n, one, many):
    return "%d %s" % (n, one if n == 1 else many)


def verdict(state, host):
    c = state["counts"]
    rest = c["MITTEL"] + c["NIEDRIG"]
    if c["KRITISCH"]:
        head = "%s auf %s" % (_n(c["KRITISCH"], "kritisches Problem", "kritische Probleme"), host)
        text = "Das solltest du sofort ansehen. Unter „Zuerst erledigen“ steht, was zu tun ist."
        lvl = "kritisch"
    elif c["HOCH"]:
        head = "%s auf %s" % (_n(c["HOCH"], "wichtiges Problem", "wichtige Probleme"), host)
        text = "Nichts deutet auf einen akuten Einbruch hin, aber diese Punkte sollten zeitnah behoben werden."
        lvl = "hoch"
    elif rest:
        head = "Keine ernsten Probleme auf %s" % host
        text = "Es gibt %s, mit denen du den Server weiter absichern kannst." % _n(rest, "Verbesserungsvorschlag", "Verbesserungsvorschläge")
        lvl = "mittel"
    else:
        head = "Alles in Ordnung auf %s" % host
        text = "Die letzten Prüfungen haben keine Auffälligkeiten gefunden."
        lvl = "ok"
    if c["KRITISCH"] or c["HOCH"]:
        more = c["HOCH"] if c["KRITISCH"] else 0
        extra = []
        if more:
            extra.append(_n(more, "wichtiges", "wichtige"))
        if rest:
            extra.append(_n(rest, "kleinerer Punkt", "kleinere Punkte"))
        if extra:
            text += " Dazu kommen " + " und ".join(extra) + "."
    return {"headline": head, "text": text, "level": lvl}


def chart(history):
    pts = []
    n = len(history)
    for i, r in enumerate(history):
        x = 30 + (286 * i / (n - 1) if n > 1 else 143)
        y = 100 - 0.9 * r.get("score", 0)
        cls = "full" if r.get("mode") == "full" else "quick"
        pts.append({"x": round(x, 1), "y": round(y, 1), "score": r.get("score"), "id": r["id"], "cls": cls,
                    "label": datetime.fromtimestamp(r["started"]).strftime("%d.%m. %H:%M")})
    fmt = lambda r: datetime.fromtimestamp(r["started"]).strftime("%d.%m.")  # noqa: E731
    return {"points": pts, "first": fmt(history[0]) if history else "", "last": fmt(history[-1]) if history else ""}


def raw_files(r):
    try:
        base = r.get("raw_dir", "")
        return sorted(n for n in os.listdir(base)
                      if re.fullmatch(r"[A-Za-z0-9._-]{1,80}", n) and os.path.isfile(os.path.join(base, n))
                      and os.path.getsize(os.path.join(base, n)) > 0)
    except OSError:
        return []


SYSTEMD_RESULT = {
    "oom-kill": "Arbeitsspeicher voll – das System hat den Scan beendet",
    "timeout": "Zeitlimit überschritten",
    "signal": "Von außen beendet",
    "core-dump": "Programmabsturz",
    "exit-code": "Programmfehler",
    "watchdog": "Zeitüberwachung von systemd",
}


def systemd_abort_reason():
    """Grund für einen harten Abbruch, den ubusec selbst nicht mehr eintragen konnte."""
    try:
        r = subprocess.run(["systemctl", "show", "ubusec-queue.service", "ubusec-full.service", "ubusec-quick.service",
                            "-p", "Id", "-p", "Result"], capture_output=True, text=True, timeout=5)
    except Exception:
        return ""
    for block in r.stdout.strip().split("\n\n"):
        kv = dict(l.split("=", 1) for l in block.splitlines() if "=" in l)
        if kv.get("Result") in SYSTEMD_RESULT:
            return "%s (%s)" % (SYSTEMD_RESULT[kv["Result"]], kv.get("Id", ""))
    return "Grund unbekannt – vermutlich Neustart des Servers oder hartes Beenden"


def boot_time():
    try:
        for line in open("/proc/stat"):
            if line.startswith("btime "):
                return int(line.split()[1])
    except OSError:
        pass
    return 0


def read_status():
    st = {"running": False}
    try:
        with open(os.path.join(STATE_DIR, "status.json"), encoding="utf-8") as f:
            st = json.load(f)
    except (OSError, ValueError):
        pass
    # abgebrochenen oder hängengebliebenen Scan erkennen
    if st.get("running"):
        pid = st.get("pid")
        alive = True
        if isinstance(pid, int) and pid > 1:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                alive = False
            except PermissionError:
                alive = True          # läuft als root – existiert also
        if not alive or time.time() - st.get("updated", 0) > 16 * 3600 or st.get("updated", 0) < boot_time():
            st["running"] = False
            st["aborted"] = True
    elif st.get("exit") in (130, 99):
        st["aborted"] = True
    if st.get("aborted") and not st.get("abort_reason"):
        st["abort_reason"] = systemd_abort_reason()
    try:
        names = os.listdir(QUEUE_DIR)
        st["queued"] = any(n.endswith(".req") for n in names)
        st["ctl_pending"] = any(n.endswith(".ctl") for n in names)
        tu = read_json(os.path.join(STATE_DIR, "tools-update.state"), {}) or {}
        if tu.get("running") and time.time() - tu.get("time", 0) < 3600:
            st["ctl_pending"] = True
        # Auftrag liegt seit über 2 Minuten, ohne dass ein Scan läuft → Warteschlangendienst hängt
        ages = [time.time() - os.path.getmtime(os.path.join(QUEUE_DIR, n)) for n in names if n.endswith(".req")]
        if ages and not st.get("running") and max(ages) > 120:
            st["queue_stuck"] = int(max(ages) // 60)
    except OSError:
        st["queued"] = st["ctl_pending"] = False
    return st


def timer_info():
    out = []
    for unit, label in (("ubusec-quick.timer", "Schnellscan"), ("ubusec-full.timer", "Vollscan")):
        try:
            r = subprocess.run(["systemctl", "show", unit, "-p", "NextElapseUSecRealtime", "-p", "ActiveState",
                                "--timestamp=pretty"], capture_output=True, text=True, timeout=5)
            kv = dict(l.split("=", 1) for l in r.stdout.splitlines() if "=" in l)
            nxt = kv.get("NextElapseUSecRealtime", "")
            out.append({"label": label, "active": kv.get("ActiveState") == "active", "next": nxt})
        except Exception:
            out.append({"label": label, "active": False, "next": ""})
    return out


def effort_rank(e):
    """Aufwand als Zahl zum Sortieren: sofort < 5 Min < … < 1 Std < prüfen."""
    e = (e or "").strip().lower()
    if e == "sofort":
        return 1
    m = re.match(r"(\d+)\s*(min|std)", e)
    if m:
        return int(m.group(1)) * (60 if m.group(2) == "std" else 1)
    return 999   # „prüfen“ / unbekannt


def effort_group(e):
    r = effort_rank(e)
    return "kurz" if r <= 5 else "mittel" if r <= 30 else "lang" if r < 999 else "pruefen"


# ------------------------------------------------------------ Export der Empfehlungen ---
GROUP_TITLE = {"KRITISCH": "Sofort handeln", "HOCH": "Bald beheben", "MITTEL": "Bei Gelegenheit verbessern",
               "NIEDRIG": "Feinschliff"}


def export_context(state, todo, lynis):
    """Gemeinsame Daten für alle Exportformate."""
    host = next((r.get("host") for r in state["sources"].values() if r.get("host")), "")
    items = []
    for f in todo:
        h = f.get("hint") or {}
        src = state["sources"].get(f["module"], {})
        items.append({
            "severity": f["severity"], "module": MOD_TITLE.get(f["module"], f["module"]), "raw_module": f["module"],
            "message": f["message"],
            "details": [d for d in f.get("details", []) if not d.startswith("… und ")],
            # ubusec kürzt lange Listen schon beim Scan („… und 4 weitere → Datei“) – die Anzahl mitnehmen
            "more": sum(int(m.group(1)) for d in f.get("details", []) for m in [re.match(r"… und (\d+) weitere", d)] if m),
            "why": h.get("why", ""), "effort": h.get("effort", ""),
            "steps": [(st[2:], True) if st.startswith("$ ") else (st, False) for st in h.get("steps", [])],
            "checked": datetime.fromtimestamp(src.get("finished", 0)).strftime("%d.%m.%Y %H:%M") if src.get("finished") else "",
            "new": f.get("new", False)})
    return {"host": host, "created": datetime.now().strftime("%d.%m.%Y %H:%M"), "score": state.get("score"),
            "counts": state.get("counts", {}), "items": items, "lynis": lynis}


def export_markdown(c):
    L = ["# ubusec – Empfehlungen%s" % (" für " + c["host"] if c["host"] else ""), "",
         "Erstellt am %s mit ubusec %s · Sicherheitswert %s von 100" % (c["created"], VERSION, c["score"]), "",
         " · ".join("%s %d" % (SEV_NAME[s], c["counts"].get(s, 0)) for s in SEVERITIES if s != "INFO"), ""]
    for s in SEVERITIES[:-1]:
        group = [i for i in c["items"] if i["severity"] == s]
        if not group:
            continue
        L += ["## %s (%d)" % (GROUP_TITLE[s], len(group)), ""]
        for n, i in enumerate(group, 1):
            L += ["### %d. %s%s" % (n, i["message"], " (neu)" if i["new"] else ""), "",
                  "*%s · %s · geprüft %s%s*" % (SEV_NAME[s], i["module"], i["checked"],
                                                  " · Aufwand: " + i["effort"] if i["effort"] else ""), ""]
            L += ["- %s" % d for d in i["details"]] + (["- … und %d weitere" % i["more"]] if i.get("more") else []) \
                + ([""] if i["details"] else [])
            if i["why"]:
                L += ["**Warum:** " + i["why"], ""]
            if i["steps"]:
                L += ["**So behebst du es:**", ""]
                for txt, cmd in i["steps"]:
                    L += ["```bash", txt, "```"] if cmd else ["- " + txt]
                L += [""]
    if c["lynis"]:
        L += ["## Härtungsvorschläge von Lynis (%d)" % len(c["lynis"]), "",
              "Details: `sudo lynis show details TEST-ID`", ""] + ["- " + x for x in c["lynis"]] + [""]
    return "\n".join(L)


def _xml(t):
    t = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", str(t))
    return t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _col(n):
    s = ""
    while n:
        n, r = divmod(n - 1, 26)
        s = chr(65 + r) + s
    return s


def _sheet(rows, widths, styles, status_col=True, title_rows=0):
    """Ein Arbeitsblatt als XML. rows: Liste von Zeilen, jede Zelle (Text, Stilnummer)."""
    ncol = len(widths)
    hdr = title_rows + 1
    last = len(rows)
    out = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
           '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
           'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">',
           '<sheetPr><pageSetUpPr fitToPage="1"/></sheetPr>',
           '<dimension ref="A1:%s%d"/>' % (_col(ncol), max(last, 1)),
           '<sheetViews><sheetView workbookViewId="0"><pane ySplit="%d" topLeftCell="A%d" activePane="bottomLeft" '
           'state="frozen"/></sheetView></sheetViews>' % (hdr, hdr + 1),
           '<sheetFormatPr defaultRowHeight="15"/><cols>']
    out += ['<col min="%d" max="%d" width="%s" customWidth="1"/>' % (i, i, w) for i, w in enumerate(widths, 1)]
    out.append('</cols><sheetData>')
    for r, row in enumerate(rows, 1):
        cells = []
        for ci, (val, st) in enumerate(row, 1):
            if val == "" and not st:
                continue
            cells.append('<c r="%s%d" s="%d" t="inlineStr"><is><t xml:space="preserve">%s</t></is></c>'
                         % (_col(ci), r, st, _xml(val)))
        out.append('<row r="%d">%s</row>' % (r, "".join(cells)))
    out.append('</sheetData>')
    if last > hdr:
        out.append('<autoFilter ref="A%d:%s%d"/>' % (hdr, _col(ncol), last))
        if status_col:
            out.append('<conditionalFormatting sqref="A%d:%s%d"><cfRule type="expression" dxfId="0" priority="1">'
                       '<formula>$A%d="erledigt"</formula></cfRule><cfRule type="expression" dxfId="1" priority="2">'
                       '<formula>$A%d="ignoriert"</formula></cfRule></conditionalFormatting>'
                       % (hdr + 1, _col(ncol), last, hdr + 1, hdr + 1))
            out.append('<dataValidations count="1"><dataValidation type="list" allowBlank="1" showErrorMessage="1" '
                       'sqref="A%d:A%d"><formula1>"offen,in Arbeit,erledigt,ignoriert"</formula1></dataValidation>'
                       '</dataValidations>' % (hdr + 1, last + 200))
    out.append('<pageMargins left="0.4" right="0.4" top="0.5" bottom="0.5" header="0.3" footer="0.3"/>'
               '<pageSetup paperSize="9" orientation="landscape" fitToWidth="1" fitToHeight="0"/></worksheet>')
    return "".join(out)


XLSX_STYLES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
    '<fonts count="4"><font><sz val="10"/><name val="Calibri"/></font>'
    '<font><b/><sz val="10"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font>'
    '<font><b/><sz val="10"/><name val="Calibri"/></font>'
    '<font><b/><sz val="14"/><name val="Calibri"/></font></fonts>'
    '<fills count="8"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill>'
    '<fill><patternFill patternType="solid"><fgColor rgb="FF2F3E4E"/></patternFill></fill>'
    '<fill><patternFill patternType="solid"><fgColor rgb="FFF4C7C3"/></patternFill></fill>'
    '<fill><patternFill patternType="solid"><fgColor rgb="FFFAD9C1"/></patternFill></fill>'
    '<fill><patternFill patternType="solid"><fgColor rgb="FFFFF0B3"/></patternFill></fill>'
    '<fill><patternFill patternType="solid"><fgColor rgb="FFDCE8F3"/></patternFill></fill>'
    '<fill><patternFill patternType="solid"><fgColor rgb="FFF2F2F2"/></patternFill></fill></fills>'
    '<borders count="2"><border/><border><left/><right/><top/><bottom style="thin"><color rgb="FFD0D0D0"/></bottom>'
    '<diagonal/></border></borders>'
    '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
    '<cellXfs count="10">'
    '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'                                   # 0
    '<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1" applyAlignment="1">'
    '<alignment vertical="center" wrapText="1"/></xf>'                                                  # 1 Kopf
    '<xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1">'
    '<alignment vertical="top" wrapText="1"/></xf>'                                                     # 2 Text
    '<xf numFmtId="0" fontId="2" fillId="3" borderId="1" xfId="0" applyFont="1" applyFill="1" applyAlignment="1">'
    '<alignment vertical="top"/></xf>'                                                                  # 3 Kritisch
    '<xf numFmtId="0" fontId="2" fillId="4" borderId="1" xfId="0" applyFont="1" applyFill="1" applyAlignment="1">'
    '<alignment vertical="top"/></xf>'                                                                  # 4 Hoch
    '<xf numFmtId="0" fontId="2" fillId="5" borderId="1" xfId="0" applyFont="1" applyFill="1" applyAlignment="1">'
    '<alignment vertical="top"/></xf>'                                                                  # 5 Mittel
    '<xf numFmtId="0" fontId="2" fillId="6" borderId="1" xfId="0" applyFont="1" applyFill="1" applyAlignment="1">'
    '<alignment vertical="top"/></xf>'                                                                  # 6 Niedrig
    '<xf numFmtId="0" fontId="2" fillId="0" borderId="1" xfId="0" applyFont="1" applyBorder="1" applyAlignment="1">'
    '<alignment vertical="top" wrapText="1"/></xf>'                                                     # 7 fett
    '<xf numFmtId="0" fontId="3" fillId="0" borderId="0" xfId="0" applyFont="1"/>'                       # 8 Titel
    '<xf numFmtId="0" fontId="0" fillId="7" borderId="1" xfId="0" applyFill="1" applyBorder="1" applyAlignment="1">'
    '<alignment vertical="top"/></xf>'                                                                  # 9 Status
    '</cellXfs><cellStyles count="1"><cellStyle name="Standard" xfId="0" builtinId="0"/></cellStyles>'
    '<dxfs count="2"><dxf><font><strike/><color rgb="FF7F7F7F"/></font><fill><patternFill patternType="solid">'
    '<bgColor rgb="FFE2EFDA"/></patternFill></fill></dxf>'
    '<dxf><font><color rgb="FF9F9F9F"/></font></dxf></dxfs></styleSheet>')


def export_xlsx(c):
    """Excel-Datei (Office Open XML) ohne Zusatzbibliotheken: Kopfzeile fixiert, Filter, Farben je Schwere,
    Spalte „Status“ mit Auswahlliste – „erledigt“ färbt die Zeile grün und streicht sie durch."""
    import io
    import zipfile
    sev_style = {"KRITISCH": 3, "HOCH": 4, "MITTEL": 5, "NIEDRIG": 6}
    title = "ubusec – Empfehlungen%s" % (" für " + c["host"] if c["host"] else "")
    sub = "Erstellt am %s mit ubusec %s · Sicherheitswert %s von 100 · %s" % (
        c["created"], VERSION, c["score"],
        " · ".join("%s %d" % (SEV_NAME[s], c["counts"].get(s, 0)) for s in SEVERITIES if s != "INFO"))
    head = ["Status", "Schwere", "Bereich", "Befund", "Details", "Warum wichtig", "So behebst du es", "Aufwand",
            "Neu", "Geprüft", "Notiz"]
    rows = [[(title, 8)], [(sub, 0)], [(h, 1) for h in head]]
    order = {s: n for n, s in enumerate(SEVERITIES)}
    for i in sorted(c["items"], key=lambda x: order.get(x["severity"], 9)):
        steps = "\n".join(("$ " + t) if cmd else ("• " + t) for t, cmd in i["steps"])
        more = max(0, len(i["details"]) - 15) + i.get("more", 0)
        det = i["details"][:15] + (["… und %d weitere" % more] if more else [])
        rows.append([("offen", 9), (SEV_NAME[i["severity"]], sev_style.get(i["severity"], 2)), (i["module"], 2),
                     (i["message"], 7), ("\n".join(det), 2), (i["why"], 2), (steps, 2), (i["effort"], 2),
                     ("neu" if i["new"] else "", 2), (i["checked"], 2), ("", 2)])
    sheets = [("Empfehlungen", _sheet(rows, [11, 10, 16, 42, 50, 45, 60, 12, 6, 15, 30], None, True, 2))]
    if c["lynis"]:
        lr = [[("Härtungsvorschläge von Lynis", 8)], [("Details je Vorschlag: sudo lynis show details TEST-ID", 0)],
              [(h, 1) for h in ("Status", "Vorschlag", "Befehl für Details", "Notiz")]]
        for x in c["lynis"]:
            tid = x.rsplit("[", 1)[-1].rstrip("]") if "[" in x else ""
            lr.append([("offen", 9), (x, 2), ("sudo lynis show details " + tid if tid else "", 2), ("", 2)])
        sheets.append(("Lynis", _sheet(lr, [11, 90, 38, 30], None, True, 2)))
    ct = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
          '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
          '<Default Extension="xml" ContentType="application/xml"/>'
          '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
          '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>']
    ct += ['<Override PartName="/xl/worksheets/sheet%d.xml" ContentType="application/vnd.openxmlformats-officedocument.'
           'spreadsheetml.worksheet+xml"/>' % n for n in range(1, len(sheets) + 1)]
    ct.append('</Types>')
    wb = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
          '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
          'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>']
    wb += ['<sheet name="%s" sheetId="%d" r:id="rId%d"/>' % (nm, n, n) for n, (nm, _) in enumerate(sheets, 1)]
    wb.append('</sheets><definedNames>')
    for n, (nm, xml) in enumerate(sheets):
        m = re.search(r'<autoFilter ref="([A-Z]+)(\d+):([A-Z]+)(\d+)"', xml)
        if m:
            wb.append('<definedName name="_xlnm._FilterDatabase" localSheetId="%d" hidden="1">%s!$%s$%s:$%s$%s'
                      '</definedName>' % (n, nm, m.group(1), m.group(2), m.group(3), m.group(4)))
        wb.append('<definedName name="_xlnm.Print_Titles" localSheetId="%d">%s!$3:$3</definedName>' % (n, nm))
    wb.append('</definedNames></workbook>')
    rel = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
           '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">']
    rel += ['<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/'
            'worksheet" Target="worksheets/sheet%d.xml"/>' % (n, n) for n in range(1, len(sheets) + 1)]
    rel.append('<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/'
               'styles" Target="styles.xml"/></Relationships>' % (len(sheets) + 1))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", "".join(ct))
        z.writestr("_rels/.rels", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/'
                   'officeDocument" Target="xl/workbook.xml"/></Relationships>')
        z.writestr("xl/workbook.xml", "".join(wb))
        z.writestr("xl/_rels/workbook.xml.rels", "".join(rel))
        z.writestr("xl/styles.xml", XLSX_STYLES)
        for n, (_, xml) in enumerate(sheets, 1):
            z.writestr("xl/worksheets/sheet%d.xml" % n, xml)
    return buf.getvalue()


def export_html(c):
    from html import escape as e
    color = {"KRITISCH": "#a3191e", "HOCH": "#cc4a17", "MITTEL": "#9c6c00", "NIEDRIG": "#48708f"}
    H = ['<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">',
         "<title>ubusec – Empfehlungen %s</title><style>" % e(c["host"]),
         "body{font:15px/1.5 system-ui,sans-serif;color:#15233c;max-width:860px;margin:2rem auto;padding:0 16px}"
         "h1{font-size:1.6rem;margin:0}h2{margin-top:2rem;border-bottom:2px solid #c8d1db;padding-bottom:.2rem}"
         "h3{font-size:1.05rem;margin:1.4rem 0 .2rem}.meta{color:#56627a;font-size:.9rem}"
         "pre{background:#eef2f6;padding:.5rem .7rem;border-radius:4px;white-space:pre-wrap;word-break:break-all;font-size:.88rem}"
         ".it{border-left:4px solid var(--c);padding-left:.8rem;break-inside:avoid}ul{padding-left:1.2rem}"
         "@media print{body{margin:0;font-size:12px}h2{break-after:avoid}}</style></head><body>",
         "<h1>ubusec – Empfehlungen%s</h1>" % (" für " + e(c["host"]) if c["host"] else ""),
         '<p class="meta">Erstellt am %s mit ubusec %s · Sicherheitswert %s von 100 · %s</p>' % (
             e(c["created"]), e(VERSION), e(str(c["score"])),
             " · ".join("%s %d" % (SEV_NAME[s], c["counts"].get(s, 0)) for s in SEVERITIES if s != "INFO"))]
    for s in SEVERITIES[:-1]:
        group = [i for i in c["items"] if i["severity"] == s]
        if not group:
            continue
        H.append('<h2 style="color:%s">%s (%d)</h2>' % (color[s], GROUP_TITLE[s], len(group)))
        for n, i in enumerate(group, 1):
            H.append('<div class="it" style="--c:%s"><h3>%d. %s%s</h3><p class="meta">%s · %s · geprüft %s%s</p>' % (
                color[s], n, e(i["message"]), " (neu)" if i["new"] else "", SEV_NAME[s], e(i["module"]), e(i["checked"]),
                " · Aufwand: " + e(i["effort"]) if i["effort"] else ""))
            if i["details"]:
                H.append("<ul>" + "".join("<li>%s</li>" % e(d) for d in i["details"])
                         + ("<li>… und %d weitere</li>" % i["more"] if i.get("more") else "") + "</ul>")
            if i["why"]:
                H.append("<p><b>Warum:</b> %s</p>" % e(i["why"]))
            if i["steps"]:
                H.append("<p><b>So behebst du es:</b></p>")
                for txt, cmd in i["steps"]:
                    H.append("<pre>%s</pre>" % e(txt) if cmd else "<p>%s</p>" % e(txt))
            H.append("</div>")
    if c["lynis"]:
        H.append("<h2>Härtungsvorschläge von Lynis (%d)</h2><p class=\"meta\">Details: sudo lynis show details TEST-ID</p><ul>%s</ul>"
                 % (len(c["lynis"]), "".join("<li>%s</li>" % e(x) for x in c["lynis"])))
    H.append("</body></html>")
    return "\n".join(H)


# ------------------------------------------------------------ KI-Export (anonymisiert) ---
KEEP_LABELS = {"www", "mail", "webmail", "smtp", "imap", "pop", "autoconfig", "autodiscover", "cloud", "nextcloud",
               "admin", "ftp", "shop", "blog", "api", "dev", "test", "demo", "staging", "office", "collabora"}
PUBLIC_IP = re.compile(r"(?<![\w.:-])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\w.-]*\d)")
IPV6 = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{1,4}(?![\w:])")
LONGHEX = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{20,}(?![0-9a-fA-F])")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,}")
URLHOST = re.compile(r"https?://([A-Za-z0-9.-]+)")
HOSTLINE = re.compile(r"^([a-z0-9-]+(?:\.[a-z0-9-]+)*\.([a-z]{2,24}))(?:$|\s|:|\s–)", re.I)
FILE_EXT = {"php", "ini", "conf", "cnf", "log", "sql", "txt", "lock", "json", "js", "css", "html", "htm", "xml", "py", "sh",
            "gz", "zip", "tar", "bak", "old", "orig", "pem", "key", "crt", "dat", "md", "so", "service", "timer", "options"}


class Anonymizer:
    """Ersetzt eigene Domains, Benutzer, öffentliche IPs, E-Mail-Adressen und Prüfsummen durch Platzhalter."""

    def __init__(self, items, host):
        self.map = {}          # Original → Platzhalter (für die Zuordnungsliste)
        self.n = {"domain": 0, "benutzer": 0, "ip": 0, "postfach": 0}
        hosts = set()
        if host:
            hosts.add(host.lower())
        for i in items:
            for t in [i["message"]] + i["details"]:
                hosts.update(h.lower() for h in URLHOST.findall(t))
                m = HOSTLINE.match(t.strip())
                if m and i.get("raw_module") in ("sites", "apps") and m.group(2).lower() not in FILE_EXT:
                    hosts.add(m.group(1).lower())
        hosts = {h.strip(".") for h in hosts if "." in h and not re.fullmatch(r"[\d.]+", h)}
        self.apexes = {}
        for h in sorted(hosts, key=lambda x: (x.count("."), x)):
            parts = h.split(".")
            apex = ".".join(parts[-3:]) if len(parts) > 2 and parts[-2] in ("co", "com", "or", "ac", "gv") else ".".join(parts[-2:])
            if apex not in self.apexes:
                self.n["domain"] += 1
                self.apexes[apex] = "domain-%d.example" % self.n["domain"]
                self.map[apex] = self.apexes[apex]
        # Rechner-Benutzer (Virtualmin: ein Benutzer je Kunde/Domain) – aus /etc/passwd und /home
        users = set()
        try:
            for line in open("/etc/passwd", encoding="utf-8", errors="replace"):
                f = line.split(":")
                if len(f) > 5 and f[2].isdigit() and (1000 <= int(f[2]) < 65534 or f[5].startswith("/home/")):
                    users.add(f[0])
        except OSError:
            pass
        try:   # die Weboberfläche läuft mit ProtectHome=yes – /home ist dann nicht lesbar
            users.update(d for d in os.listdir("/home") if os.path.isdir(os.path.join("/home", d)))
        except OSError:
            pass
        # Virtualmin legt Benutzer mit Heimatordner unter /home an – die stehen auch in /etc/passwd
        self.users = {}                     # Platzhalter werden erst bei Verwendung vergeben
        users = sorted((u for u in users if len(u) >= 3), key=len, reverse=True)
        self.ips = {}
        self.mails = {}
        self.labels = {}
        if self.apexes:
            alt = "|".join(re.escape(a) for a in sorted(self.apexes, key=len, reverse=True))
            self.dom_rx = re.compile(r"(?<![\w-])((?:[a-z0-9-]+\.)*)(%s)(?![\w-])" % alt, re.I)
        else:
            self.dom_rx = None
        if users:
            alt = "|".join(re.escape(u) for u in users)
            # nicht ersetzen, wenn der Name Teil eines Domainnamens ist (Benutzer „ubuntu“ ↔ ubuntu.com/pro)
            self.user_rx = re.compile(r"(?<![\w.-])(%s)(?![\w-])(?!\.[A-Za-z]{2,})" % alt)
        else:
            self.user_rx = None

    def _dom(self, m):
        subs = [x.lower() for x in m.group(1).rstrip(".").split(".") if x]
        keep = []
        for x in subs:
            if x in KEEP_LABELS:
                keep.append(x)
            else:
                if x not in self.labels:
                    self.labels[x] = "sub%d" % (len(self.labels) + 1)
                    self.map[x + ".…"] = self.labels[x] + ".…"
                keep.append(self.labels[x])
        return ".".join(keep + [self.apexes[m.group(2).lower()]])

    def _user(self, m):
        u = m.group(1)
        if u not in self.users:
            self.n["benutzer"] += 1
            self.users[u] = "benutzer-%d" % self.n["benutzer"]
            self.map[u] = self.users[u]
        return self.users[u]

    def _ip(self, m):
        before = m.string[max(0, m.start() - 12):m.start()].lower()
        if re.search(r"(→|->|version|\bv)\s*$", before):   # Versionsnummern wie „6.1.6 → 6.2.4.1“
            return m.group(0)
        a = [int(x) for x in m.groups()]
        if any(x > 255 for x in a) or a[0] in (0, 10, 127) or (a[0] == 192 and a[1] == 168) or (a[0] == 172 and 16 <= a[1] < 32):
            return m.group(0)
        ip = m.group(0)
        if ip not in self.ips:
            self.n["ip"] += 1
            self.ips[ip] = "IP-%d" % self.n["ip"]
            self.map[ip] = self.ips[ip]
        return self.ips[ip]

    def _mail(self, m):
        addr = m.group(0)
        if addr not in self.mails:
            self.n["postfach"] += 1
            dom = addr.split("@", 1)[1]
            self.mails[addr] = "postfach-%d@%s" % (self.n["postfach"], self.dom_rx.sub(self._dom, dom) if self.dom_rx else "domain.example")
            self.map[addr] = self.mails[addr]
        return self.mails[addr]

    def __call__(self, t):
        t = EMAIL.sub(self._mail, t)
        # private Dateinamen in Nextcloud-Datenordnern und Benutzerablagen nicht weitergeben
        t = re.sub(r"(/data/)[^/\s]+(/files/)\S.*", r"\1<nextcloud-benutzer>\2…", t)
        if self.dom_rx:
            t = self.dom_rx.sub(self._dom, t)
        if self.user_rx:
            t = self.user_rx.sub(self._user, t)
        t = PUBLIC_IP.sub(self._ip, t)
        t = IPV6.sub("IPv6-Adresse", t)
        t = LONGHEX.sub("<prüfsumme>", t)
        return t


def export_ai(c, os_name=""):
    """Markdown für eine KI: anonymisiert, kompakt, mit Arbeitsauftrag."""
    an = Anonymizer(c["items"], c["host"])
    L = ["# Sicherheitsbefunde eines Linux-Servers – bitte bei der Behebung helfen", "",
         "## Kontext", "",
         "- Server: %s mit Virtualmin/Webmin (Apache, PHP-FPM, Postfix, Dovecot, MariaDB), Webanwendungen u. a. "
         "WordPress, Nextcloud und Roundcube" % (os_name or "Ubuntu"),
         "- Die Befunde stammen aus ubusec (fasst Lynis, rkhunter, chkrootkit, ClamAV, OpenSCAP und eigene Prüfungen zusammen).",
         "- Anonymisiert: Domains heißen domain-N.example (Subdomains subN), Systembenutzer benutzer-N, öffentliche "
         "IP-Adressen IP-N, Postfächer postfach-N@…, Prüfsummen <prüfsumme>. Bitte diese Platzhalter in Befehlen beibehalten.",
         "",
         "## Bitte",
         "",
         "1. Ordne die Punkte nach tatsächlichem Risiko für diesen Server und nenne mögliche Fehlalarme.",
         "2. Fasse zusammengehörige Punkte zusammen.",
         "3. Gib für jeden Punkt konkrete Schritte für Ubuntu/Virtualmin an – mit Befehlen und dem Hinweis, wie man die "
         "Änderung prüft und rückgängig macht.",
         "4. Warne ausdrücklich, wenn eine Änderung den Zugang zum Server (SSH, Webmin) oder Websites unterbrechen kann.",
         "",
         "## Befunde (%s)" % ", ".join("%d %s" % (c["counts"].get(s, 0), SEV_NAME[s]) for s in SEVERITIES if s != "INFO"), ""]
    n = 0
    for s in SEVERITIES[:-1]:
        for i in (x for x in c["items"] if x["severity"] == s):
            n += 1
            L.append("### %d. [%s] %s" % (n, SEV_NAME[s], an(i["message"])))
            L.append("Bereich: %s" % i["module"])
            det = list(dict.fromkeys(an(d) for d in i["details"][:8]))
            L += ["- " + d for d in det]
            more = max(0, len(i["details"]) - 8) + i.get("more", 0)
            if more:
                L.append("- … und %d weitere gleichartige Einträge" % more)
            if i["steps"]:
                L.append("Vorschlag von ubusec: " + " | ".join(an(t) for t, _ in i["steps"]))
            L.append("")
    if c["lynis"]:
        L += ["## Härtungsvorschläge von Lynis", ""] + ["- " + an(x) for x in c["lynis"]] + [""]
    return "\n".join(L), an.map


def lynis_suggestions(state):
    src = state["sources"].get("config")
    if not src:
        return []
    p = os.path.join(src.get("raw_dir", ""), "lynis-suggestions.txt")
    try:
        with open(p, encoding="utf-8", errors="replace") as f:
            return [l.strip() for l in f if l.strip()][:40]
    except OSError:
        return []


def read_json(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def ignore_entries():
    out, note = [], ""
    try:
        for line in open(IGNORE_FILE, encoding="utf-8"):
            line = line.rstrip("\n")
            if line.startswith("#"):
                note = line.lstrip("# ").strip()
            elif line.strip():
                out.append({"pattern": line, "note": note if note.startswith("per Weboberfl") else ""})
                note = ""
            else:
                note = ""
    except OSError:
        return None
    return out


def audit_tail(n=40):
    try:
        with open(os.path.join(LOG_DIR, "web-audit.log"), encoding="utf-8", errors="replace") as f:
            return list(reversed([l.rstrip() for l in f.readlines()[-n:]]))
    except OSError:
        return []


def record_login(user, ip, ok, agent):
    data = read_json(LOGINS_FILE, [])
    data.insert(0, {"t": int(time.time()), "user": user[:32], "ip": ip, "ok": ok, "agent": (agent or "")[:80]})
    try:
        tmp = LOGINS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data[:50], f)
        os.replace(tmp, LOGINS_FILE)
    except OSError:
        pass


def enqueue_ctl(fields):
    enqueue(fields, "ctl")


def enqueue(fields, ext="req"):
    os.makedirs(QUEUE_DIR, exist_ok=True)
    name = "%d-%s" % (time.time(), secrets.token_hex(4))
    tmp = os.path.join(QUEUE_DIR, name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        for k, v in fields.items():
            f.write("%s=%s\n" % (k, str(v).replace("\n", " ")))
    os.chmod(tmp, 0o640)
    os.replace(tmp, os.path.join(QUEUE_DIR, name + "." + ext))


# =============================================================================
#  Web-App
# =============================================================================
def create_app():
    from flask import (Flask, Response, abort, flash, g, jsonify, redirect, render_template,
                       request, send_file, session, url_for)

    conf = read_conf()
    app = Flask(__name__)
    try:
        app.secret_key = open(os.path.join(CONF_DIR, "web-secret"), encoding="utf-8").read().strip()
    except OSError:
        sys.exit("Fehlt: %s/web-secret (sudo ubusec --install --with-web)" % CONF_DIR)
    idle = int(conf.get("SESSION_MINUTES", "30")) * 60
    app.config.update(
        SESSION_COOKIE_NAME="ubusec",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=conf.get("SECURE_COOKIES") == "1",
        PERMANENT_SESSION_LIFETIME=12 * 3600,
        MAX_CONTENT_LENGTH=16 * 1024,
    )
    if conf.get("TRUST_PROXY") == "1":
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    fails = {}            # IP -> [Zeitstempel]
    totp_used = {}        # Benutzer -> letzter TOTP-Zähler
    lock = threading.Lock()

    # ---------------------------------------------------------- Filter -------
    @app.template_filter("dt")
    def f_dt(ts, fmt="%d.%m.%Y %H:%M"):
        try:
            return datetime.fromtimestamp(int(ts)).strftime(fmt)
        except (TypeError, ValueError):
            return "–"

    @app.template_filter("dur")
    def f_dur(sec):
        sec = int(sec or 0)
        if sec < 60:
            return "%d s" % sec
        if sec < 3600:
            return "%d min %02d s" % (sec // 60, sec % 60)
        return "%d h %02d min" % (sec // 3600, sec % 3600 // 60)

    @app.template_filter("ago")
    def f_ago(ts):
        d = int(time.time() - int(ts or 0))
        if d < 90:
            return "gerade eben"
        if d < 3600:
            return "vor %d Minuten" % (d // 60)
        if d < 86400 * 2:
            return "vor %d Stunden" % (d // 3600) if d >= 7200 else "vor einer Stunde"
        return "vor %d Tagen" % (d // 86400)

    @app.template_filter("titles")
    def f_titles(mods):
        return ", ".join(MOD_TITLE.get(m, m) for m in mods)

    @app.template_global("recs_reset_time")
    def g_recs_reset_time():
        return recs_reset_time()

    @app.template_global("fix_result")
    def g_fix_result(fid):
        return fix_result(fid)

    @app.template_global("verify_result")
    def g_verify_result(vid):
        return verify_result(vid)

    @app.template_filter("effort_group")
    def f_effort_group(e):
        return effort_group(e)

    @app.template_filter("effort_rank")
    def f_effort_rank(e):
        return effort_rank(e)

    @app.template_filter("detail")
    def f_detail(d, r):
        from markupsafe import Markup, escape
        raw = (r or {}).get("raw_dir", "")
        if d.startswith("Befehl: "):     # konkreter Befehl zum Kopieren
            c = d[8:]
            return Markup('<span class="cmdline"><code>%s</code><button type="button" class="copy" data-copy="%s">Kopieren</button></span>') % (c, c)
        if not raw or raw not in d:
            return escape(d)
        parts = re.split(re.escape(raw) + r"/([A-Za-z0-9._-]+)", d)
        out = Markup("")
        for i, part in enumerate(parts):
            if i % 2:
                out += Markup('<a href="%s">%s</a>') % (url_for("raw_file", rid=r["id"], name=part), part)
            else:
                out += escape(part)
        return out

    def update_info():
        t = read_json(os.path.join(STATE_DIR, "tools.json"), {}) or {}
        me = t.get("ubusec") or {}
        try:
            newer = bool(me.get("latest")) and tuple(map(int, re.findall(r"\d+", me["latest"])[:4])) > \
                tuple(map(int, re.findall(r"\d+", VERSION)[:4]))
        except ValueError:
            newer = False
        return me.get("latest") if newer else None

    @app.context_processor
    def ctx():
        return dict(NEW_VERSION=update_info() if session.get("user") else None,MODULES=MODULES, MOD_TITLE=MOD_TITLE, SEVERITIES=SEVERITIES, SEV_NAME=SEV_NAME,
                    QUICK=QUICK, csrf=session.get("csrf", ""), user=session.get("user"),
                    host=os.uname().nodename, INCIDENT=INCIDENT, VERSION=VERSION)

    # -------------------------------------------------- Sicherheit -----------
    @app.before_request
    def guard():
        if request.endpoint in ("login", "static"):
            return None
        users = load_users()
        u = users.get(session.get("user", ""))
        if not u or session.get("pwv") != pw_version(u):
            session.clear()
            return redirect(url_for("login", next=request.path if request.method == "GET" else None))
        now = time.time()
        if now - session.get("seen", 0) > idle:
            session.clear()
            flash("Du wurdest nach %d Minuten ohne Aktivität abgemeldet." % (idle // 60), "info")
            return redirect(url_for("login"))
        if request.path != "/api/status":       # Status-Abfragen verlängern die Sitzung nicht
            session["seen"] = now
        if request.method == "POST":
            tok = request.form.get("csrf") or request.headers.get("X-CSRF-Token", "")
            if not tok or not hmac.compare_digest(tok, session.get("csrf", "")):
                abort(400, "Ungültiges Formular-Token. Seite neu laden und erneut versuchen.")
        return None

    @app.after_request
    def headers(resp):
        if not resp.headers.get("Content-Security-Policy"):
            resp.headers["Content-Security-Policy"] = (
                "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
                "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if app.config["SESSION_COOKIE_SECURE"]:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000"
        return resp

    # ------------------------------------------------------- Login -----------
    @app.route("/login", methods=["GET", "POST"])
    def login():
        users = load_users()
        if not users:
            return render_template("login.html", no_users=True)
        ip = request.remote_addr or "?"
        if request.method == "POST":
            now = time.time()
            with lock:
                lst = [t for t in fails.get(ip, []) if now - t < 900]
                fails[ip] = lst
            if len(lst) >= 5:
                wait = int((900 - (now - lst[0])) // 60) + 1
                flash("Zu viele Fehlversuche. Bitte in %d Minuten erneut versuchen." % wait, "error")
                return render_template("login.html"), 429
            name = request.form.get("username", "")
            pw = request.form.get("password", "")
            u = users.get(name)
            ok = check_pw(pw, u["hash"] if u else DUMMY_HASH) and u is not None
            if ok and u["totp"]:
                c = totp_check(u["totp"], request.form.get("code", ""), totp_used.get(name, -1))
                ok = c is not None
                if ok:
                    totp_used[name] = c
            if ok:
                with lock:
                    fails.pop(ip, None)
                session.clear()
                session.permanent = True
                session.update(user=name, csrf=secrets.token_urlsafe(32), seen=time.time(), pwv=pw_version(u))
                record_login(name, ip, True, request.headers.get("User-Agent"))
                nxt = request.args.get("next") or ""
                return redirect(nxt if re.fullmatch(r"/(?!/)[A-Za-z0-9/_-]*", nxt) else url_for("dashboard"))
            with lock:
                fails.setdefault(ip, []).append(now)
            record_login(name, ip, False, request.headers.get("User-Agent"))
            time.sleep(0.5)
            flash("Anmeldung fehlgeschlagen. Benutzername, Passwort oder Code stimmen nicht.", "error")
        return render_template("login.html", needs_code=any(u["totp"] for u in users.values()))

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        flash("Abgemeldet.", "info")
        return redirect(url_for("login"))

    # ---------------------------------------------------------- Seiten -------
    @app.route("/")
    def dashboard():
        reports = all_reports(60)
        state = current_state(reports)
        # nur vollständige Scans sind untereinander vergleichbar (keine "--only"-Teilscans)
        history = list(reversed([r for r in reports if "(nur" not in r.get("label", "")][:30]))
        return render_template("dashboard.html", reports=reports[:6], state=state, chart=chart(history),
                               verdict=verdict(state, os.uname().nodename),
                               status=read_status(), timers=timer_info(), last=reports[0] if reports else None)

    @app.route("/scan", methods=["GET", "POST"])
    def scan():
        status = read_status()
        if request.method == "POST":
            if status.get("running") or status.get("queued"):
                flash("Es läuft bereits ein Scan. Warte, bis er fertig ist.", "error")
                return redirect(url_for("scan"))
            kind = request.form.get("kind", "quick")
            fields = {"action": "scan", "user": session["user"]}
            if kind == "full":
                fields["mode"] = "full"
            elif kind == "custom":
                sel = [m for m, _, _ in MODULES if request.form.get("m_" + m)]
                if not sel:
                    flash("Wähle mindestens einen Bereich aus.", "error")
                    return redirect(url_for("scan"))
                fields["mode"] = "full" if request.form.get("deep") else "quick"
                fields["only"] = ",".join(sel)
            else:
                fields["mode"] = "quick"
            enqueue(fields)
            flash("Scan gestartet. Du kannst diese Seite verlassen – der Scan läuft im Hintergrund weiter.", "ok")
            return redirect(url_for("scan"))
        return render_template("scan.html", status=status, last=(all_reports(1) or [None])[0])

    @app.route("/scan/modul/<mod>", methods=["POST"])
    def scan_module(mod):
        if mod not in MOD_TITLE:
            abort(404)
        st = read_status()
        if st.get("running") or st.get("queued"):
            flash("Es läuft bereits ein Scan.", "error")
        else:
            enqueue({"action": "scan", "mode": "quick", "only": mod, "user": session["user"]})
            flash("„%s“ wird erneut geprüft." % MOD_TITLE[mod], "ok")
        return redirect(url_for("scan"))

    @app.route("/wpscan/jetzt", methods=["POST"])
    def wpscan_now():
        st = read_status()
        if st.get("running") or st.get("queued"):
            flash("Es läuft bereits ein Scan.", "error")
            return redirect(url_for("settings") + "#scan")
        enqueue({"action": "scan", "mode": "quick", "only": "apps", "wpscan": "1", "user": session["user"]})
        flash("WordPress-Plugins werden jetzt bei WPScan abgefragt (im Rahmen des Tageskontingents).", "ok")
        return redirect(url_for("scan"))

    @app.route("/scan/abbrechen", methods=["POST"])
    def scan_cancel():
        st = read_status()
        if not (st.get("running") or st.get("queued")):
            flash("Es läuft gerade kein Scan.", "info")
            return redirect(url_for("scan"))
        # noch nicht gestartete Aufträge einfach entfernen
        try:
            for n in os.listdir(QUEUE_DIR):
                if n.endswith(".req"):
                    os.remove(os.path.join(QUEUE_DIR, n))
        except OSError:
            pass
        if st.get("running"):
            enqueue_ctl({"action": "cancel", "user": session["user"]})
        flash("Der Scan wird abgebrochen. Ein unvollständiger Scan erzeugt keinen Bericht.", "ok")
        return redirect(url_for("scan"))

    @app.route("/api/status")
    def api_status():
        return jsonify(read_status())

    @app.route("/pruefen", methods=["POST"])
    def verify_start():
        r = get_report(request.form.get("report", ""))
        try:
            f = r["findings"][int(request.form.get("idx", "-1"))]
        except (TypeError, ValueError, IndexError, KeyError):
            abort(400)
        spec = f.get("verify")
        if not spec:
            abort(400)
        os.makedirs(VERIFY_PENDING, exist_ok=True)
        with open(os.path.join(VERIFY_PENDING, spec["id"]), "w") as fh:
            fh.write(str(int(time.time())))
        enqueue_ctl({"action": "verify", "kind": spec["kind"], "id": spec["id"], "args": " ".join(spec["args"]),
                     "user": session["user"]})
        return redirect((request.referrer or url_for("recommendations")).split("#")[0] + "#f-%s-%s" % (r["id"], f["idx"]))

    @app.route("/aendern", methods=["POST"])
    def fix_start():
        r = get_report(request.form.get("report", ""))
        try:
            f = r["findings"][int(request.form.get("idx", "-1"))]
            spec = f["fixes"][int(request.form.get("n", "-1"))]
        except (TypeError, ValueError, IndexError, KeyError):
            abort(400)
        op = request.form.get("op")
        if op not in ("apply", "undo"):
            abort(400)
        os.makedirs(FIX_PENDING, exist_ok=True)
        with open(os.path.join(FIX_PENDING, spec["id"]), "w") as fh:
            fh.write(str(int(time.time())))
        enqueue_ctl({"action": "fix", "op": op, "kind": spec["kind"], "target": spec["target"], "domain": spec["domain"],
                     "id": spec["id"], "user": session["user"]})
        return redirect((request.referrer or url_for("recommendations")).split("#")[0] + "#f-%s-%s" % (r["id"], f["idx"]))

    @app.route("/api/aenderung/<fid>")
    def fix_status(fid):
        if not re.fullmatch(r"[a-f0-9]{16}", fid):
            abort(404)
        res, pending = fix_result(fid)
        return jsonify({"pending": pending, "done": bool(res)})

    @app.route("/api/pruefung/<vid>")
    def verify_status(vid):
        if not re.fullmatch(r"[a-f0-9]{16}", vid):
            abort(404)
        res, pending = verify_result(vid)
        return jsonify({"pending": pending, "done": bool(res), "time": (res or {}).get("time", 0)})

    @app.route("/berichte")
    def reports():
        return render_template("reports.html", reports=all_reports(), status=read_status())

    def wait_gone(paths, present=False, secs=6):
        """Kurz warten, bis root den Auftrag erledigt hat (die Steuer-Warteschlange reagiert sofort)."""
        end = time.time() + secs
        while time.time() < end:
            if all(os.path.exists(p) == present for p in paths):
                return True
            time.sleep(0.3)
        return False

    @app.route("/berichte/<rid>/loeschen", methods=["POST"])
    def report_delete(rid):
        if not get_report(rid):
            abort(404)
        if read_status().get("running"):
            flash("Während ein Scan läuft, werden keine Berichte gelöscht.", "error")
            return redirect(url_for("reports"))
        enqueue_ctl({"action": "delreport", "rid": rid, "user": session["user"]})
        done = wait_gone([os.path.join(LOG_DIR, "report-%s.json" % rid)])
        flash("Bericht gelöscht." if done else "Bericht wird gelöscht …", "ok")
        return redirect(url_for("reports"))

    @app.route("/berichte/alle-loeschen", methods=["POST"])
    def reports_delete_all():
        if request.form.get("confirm") != "ja":
            flash("Bitte bestätige, dass alle Berichte gelöscht werden sollen.", "error")
            return redirect(url_for("reports"))
        if read_status().get("running"):
            flash("Während ein Scan läuft, werden keine Berichte gelöscht.", "error")
            return redirect(url_for("reports"))
        paths = report_paths()
        enqueue_ctl({"action": "delreports", "user": session["user"]})
        done = wait_gone(paths)
        flash("Alle Berichte gelöscht. Der nächste Scan baut Übersicht und Empfehlungen neu auf." if done
              else "Berichte werden gelöscht …", "ok")
        return redirect(url_for("reports"))

    @app.route("/empfehlungen/zuruecksetzen", methods=["POST"])
    def recs_reset():
        if read_status().get("running"):
            flash("Während ein Scan läuft, lässt sich das nicht zurücksetzen.", "error")
            return redirect(url_for("recommendations"))
        before = recs_reset_time()
        enqueue_ctl({"action": "resetrecs", "user": session["user"]})
        end = time.time() + 6
        while time.time() < end and recs_reset_time() <= before:
            time.sleep(0.3)
        flash("Empfehlungen zurückgesetzt. Ein Vollscan baut sie jetzt komplett neu auf – die alten Berichte bleiben "
              "unter „Berichte“ erhalten.", "ok")
        return redirect(url_for("recommendations"))

    @app.route("/berichte/<rid>")
    def report(rid):
        r = get_report(rid)
        if not r:
            abort(404)
        mods = [m for m, _, _ in MODULES if m in r.get("modules", {})]
        return render_template("report.html", r=r, mods=mods, raw_files=raw_files(r))

    @app.route("/berichte/<rid>/<fmt>")
    def report_file(rid, fmt):
        r = get_report(rid)
        if not r or fmt not in ("txt", "html", "json"):
            abort(404)
        path = os.path.join(LOG_DIR, "report-%s.%s" % (rid, fmt))
        if not os.path.isfile(path):
            abort(404)
        resp = send_file(path, mimetype={"txt": "text/plain", "html": "text/html", "json": "application/json"}[fmt],
                         as_attachment=fmt != "html", download_name="ubusec-%s.%s" % (rid, fmt))
        if fmt == "html":   # eigener HTML-Bericht nutzt Inline-CSS, darf aber nichts nachladen
            resp.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; sandbox"
        return resp

    @app.route("/berichte/<rid>/roh/<name>")
    def raw_file(rid, name):
        r = get_report(rid)
        if not r or not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", name):
            abort(404)
        base = os.path.realpath(r.get("raw_dir", "/nonexistent"))
        path = os.path.realpath(os.path.join(base, name))
        if not path.startswith(base + os.sep) or not os.path.isfile(path) \
                or not base.startswith(os.path.realpath(LOG_DIR) + os.sep):
            abort(404)
        if request.args.get("download") == "1" or os.path.getsize(path) > 5 * 1024 * 1024:
            dl = "%s-%s" % (r["id"], name)    # Bericht im Dateinamen, damit Downloads verschiedener Scans nicht kollidieren
            return send_file(path, as_attachment=True, download_name=dl,
                             mimetype="text/plain" if not name.endswith((".json", ".html")) else None)
        if name.endswith(".html"):
            resp = send_file(path, mimetype="text/html")
            resp.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; sandbox"
            return resp
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read()
        return render_template("raw.html", r=r, name=name, text=text)

    @app.route("/empfehlungen")
    def recommendations():
        state = current_state(all_reports(60))
        todo = [f for f in state["findings"] if f["severity"] != "INFO"]
        return render_template("recommendations.html", state=state, todo=todo,
                               lynis=lynis_suggestions(state))

    @app.route("/empfehlungen/export.<fmt>")
    def recommendations_export(fmt):
        if fmt == "csv":   # frühere Tabelle – jetzt als Excel-Datei
            return redirect(url_for("recommendations_export", fmt="xlsx"))
        if fmt not in ("md", "xlsx", "html", "ki", "ki-zuordnung"):
            abort(404)
        state = current_state(all_reports(60))
        todo = [f for f in state["findings"] if f["severity"] != "INFO"]
        c = export_context(state, todo, lynis_suggestions(state))
        stamp = datetime.now().strftime("%Y%m%d")
        if fmt in ("ki", "ki-zuordnung"):
            os_name = next((r.get("os") for r in state["sources"].values() if r.get("os")), "")
            body, mapping = export_ai(c, ("Ubuntu " + os_name) if os_name and not os_name.lower().startswith("ubuntu") else os_name)
            if fmt == "ki-zuordnung":
                body = "ubusec – Zuordnung der Platzhalter im KI-Export vom %s\nNur für dich – nicht an die KI weitergeben.\n\n" % c["created"] \
                    + "\n".join("%-28s %s" % (v, k) for k, v in sorted(mapping.items(), key=lambda kv: kv[1])) + "\n"
                mime, name = "text/plain", "ubusec-ki-zuordnung-%s.txt" % stamp
            else:
                mime, name = "text/markdown", "ubusec-fuer-ki-%s.md" % stamp   # ohne Servernamen im Dateinamen
            resp = Response(body, mimetype=mime + "; charset=utf-8")
            resp.headers["Content-Disposition"] = 'attachment; filename="%s"' % name
            return resp
        name = "ubusec-empfehlungen-%s-%s.%s" % (re.sub(r"[^A-Za-z0-9.-]", "_", c["host"] or "server"), stamp, fmt)
        if fmt == "xlsx":
            resp = Response(export_xlsx(c), mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
            resp.headers["Content-Disposition"] = 'attachment; filename="%s"' % name
            return resp
        body = {"md": export_markdown, "html": export_html}[fmt](c)
        mime = {"md": "text/markdown", "html": "text/html"}[fmt]
        resp = Response(body, mimetype=mime + "; charset=utf-8")
        resp.headers["Content-Disposition"] = 'attachment; filename="%s"' % name
        return resp

    @app.route("/baseline", methods=["POST"])
    def accept_baseline():
        if request.form.get("confirm") != "ja":
            flash("Bitte bestätige, dass du die Änderungen geprüft hast.", "error")
            return redirect(request.referrer or url_for("recommendations"))
        enqueue_ctl({"action": "accept", "user": session["user"]})
        # gleich danach den Bereich „Baseline“ neu prüfen, damit die Meldungen sofort verschwinden
        st = read_status()
        if not st.get("running") and not st.get("queued"):
            flash("Der aktuelle Zustand wird als neue Baseline übernommen; der Bereich „Baseline“ wird gleich neu geprüft – "
                  "danach verschwinden die Meldungen.", "ok")
        else:
            flash("Der aktuelle Zustand wird als neue Baseline übernommen. Beim nächsten Scan entfallen die "
                  "Baseline-Meldungen.", "ok")
        return redirect(request.referrer or url_for("recommendations"))

    @app.route("/ignorieren", methods=["POST"])
    def ignore():
        r = get_report(request.form.get("report", ""))
        try:
            f = r["findings"][int(request.form.get("idx", "-1"))]
        except (TypeError, ValueError, IndexError, KeyError):
            abort(400)
        # Zahlen in der Meldung durch Platzhalter ersetzen, damit das Muster auch bei
        # wechselnden Anzahlen greift
        msg = re.sub(r"\d+", "\x00", f["message"])
        pat = "^" + re.escape(f["module"]) + r"\|" + re.escape(msg).replace("\x00", "[0-9]+") + r"\|"
        enqueue_ctl({"action": "ignore", "pattern": pat, "user": session["user"]})
        flash("„%s“ wird künftig ausgeblendet (Eintrag in /etc/ubusec/ignore.list)." % f["message"], "ok")
        return redirect(request.referrer or url_for("recommendations"))

    # ------------------------------------------------------ Einstellungen -------
    def back(anchor=""):
        return redirect(url_for("settings") + (("#" + anchor) if anchor else ""))

    def need_pw(name):
        u = load_users().get(session["user"])
        return u and check_pw(request.form.get(name, ""), u["hash"])

    # -------------------------------------------------- SSH-Schlüssel -------
    SSH_JSON = os.path.join(STATE_DIR, "ssh-keys.json")
    SSH_FIX_ID = hashlib.sha256(b"ssh-root-keyonly|sshd").hexdigest()[:16]
    SSH_ASKED = os.path.join(WEB_STATE, "ssh-asked")

    def ssh_pending():
        try:
            asked = os.path.getmtime(SSH_ASKED)
        except OSError:
            return False
        st = read_json(SSH_JSON, {}) or {}
        return time.time() - asked < 120 and st.get("time", 0) < asked - 1

    def ssh_ask(fields):
        os.makedirs(WEB_STATE, exist_ok=True)
        with open(SSH_ASKED, "w") as fh:
            fh.write(str(int(time.time())))
        fields.update(action="sshkey", user=session["user"])
        enqueue_ctl(fields)

    def ssh_wait(secs=8):
        end = time.time() + secs
        while time.time() < end and ssh_pending():
            time.sleep(0.4)

    @app.route("/ssh")
    def ssh_page():
        st = read_json(SSH_JSON, None)
        if (not st or time.time() - st.get("time", 0) > 300) and not ssh_pending():
            ssh_ask({"op": "status"})
        port = str(((st or {}).get("sshd") or {}).get("port", "22"))
        try:
            fqdn = socket.getfqdn()
        except OSError:
            fqdn = os.uname().nodename
        res, fpend = fix_result(SSH_FIX_ID)
        return render_template("ssh.html", st=st or {}, pending=ssh_pending(), fqdn=fqdn,
                               pp="" if port == "22" else " -p " + port, fix=res, fix_pending=fpend, fix_id=SSH_FIX_ID)

    @app.route("/api/ssh")
    def ssh_status():
        return jsonify({"pending": ssh_pending()})

    @app.route("/ssh/eintragen", methods=["POST"])
    def ssh_add():
        key = request.form.get("key", "").strip()
        if "PRIVATE KEY" in key or "PuTTY-User-Key-File" in key:
            flash("Das war ein PRIVATER Schlüssel – er wurde nicht gespeichert und nicht übertragen. Bitte nur den "
                  "öffentlichen Teil (Datei mit der Endung .pub) einfügen. Tipp: Den privaten Schlüssel nirgends sonst "
                  "einfügen; im Zweifel auf dem Gerät einen neuen erzeugen.", "error")
            return redirect(url_for("ssh_page") + "#eintragen")
        if not 20 <= len(key) <= 2900:
            flash("Bitte einen öffentlichen SSH-Schlüssel einfügen (eine Zeile, beginnt mit ssh-ed25519 …).", "error")
            return redirect(url_for("ssh_page") + "#eintragen")
        b64 = base64.urlsafe_b64encode(key.encode("utf-8")).decode().rstrip("=")
        ssh_ask({"op": "add", "key": b64})
        ssh_wait()
        last = (read_json(SSH_JSON, {}) or {}).get("last") or {}
        if not ssh_pending() and last.get("op") == "add":
            flash(last.get("message", ""), "ok" if last.get("ok") else "error")
        return redirect(url_for("ssh_page") + "#eintragen")

    @app.route("/ssh/entfernen", methods=["POST"])
    def ssh_del():
        fp = request.form.get("fp", "")
        if not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", fp):
            abort(400)
        ssh_ask({"op": "del", "fp": fp})
        ssh_wait()
        last = (read_json(SSH_JSON, {}) or {}).get("last") or {}
        if not ssh_pending() and last.get("op") == "del":
            flash(last.get("message", ""), "ok" if last.get("ok") else "error")
        return redirect(url_for("ssh_page") + "#schluessel")

    @app.route("/ssh/aktualisieren", methods=["POST"])
    def ssh_refresh():
        ssh_ask({"op": "status"})
        ssh_wait()
        return redirect(url_for("ssh_page") + "#anmeldungen")

    @app.route("/ssh/umstellen", methods=["POST"])
    def ssh_switch():
        op = request.form.get("op")
        if op not in ("apply", "undo"):
            abort(400)
        os.makedirs(FIX_PENDING, exist_ok=True)
        with open(os.path.join(FIX_PENDING, SSH_FIX_ID), "w") as fh:
            fh.write(str(int(time.time())))
        enqueue_ctl({"action": "fix", "op": op, "kind": "ssh-root-keyonly", "target": "sshd", "domain": "",
                     "id": SSH_FIX_ID, "user": session["user"]})
        # danach die Anzeige (Einstellung, Schlüssel) auffrischen
        ssh_ask({"op": "status"})
        return redirect(url_for("ssh_page") + "#umstellen")

    @app.route("/einstellungen")
    def settings():
        users = load_users()
        me = users.get(session["user"], {})
        conf = read_json(os.path.join(STATE_DIR, "settings.json"), {}) or {}
        wpb = read_json(os.path.join(STATE_DIR, "wpscan-budget.json"), {}) or {}
        if wpb.get("day") != time.strftime("%Y-%m-%d"):
            wpb = {"used": 0}
        return render_template("settings.html", wpb=wpb, users=sorted(users), me=me, conf=conf, DAYS=DAYS,
                               ignores=ignore_entries(), audit=audit_tail(), logins=read_json(LOGINS_FILE, [])[:15],
                               test=read_json(os.path.join(STATE_DIR, "notify-test.json")), status=read_status())

    @app.route("/einstellungen/passwort", methods=["POST"])
    def change_pw():
        if not need_pw("current"):
            flash("Das aktuelle Passwort stimmt nicht.", "error")
        elif len(request.form.get("new", "")) < 12:
            flash("Das neue Passwort braucht mindestens 12 Zeichen.", "error")
        elif request.form.get("new") != request.form.get("new2"):
            flash("Die beiden neuen Passwörter stimmen nicht überein.", "error")
        else:
            users = load_users()
            users[session["user"]]["hash"] = hash_pw(request.form["new"])
            save_users(users)
            session["pwv"] = pw_version(users[session["user"]])
            flash("Passwort geändert. Andere Sitzungen mit diesem Konto wurden abgemeldet.", "ok")
        return back("konto")

    @app.route("/einstellungen/2fa/start", methods=["POST"])
    def totp_start():
        if not need_pw("current"):
            flash("Das Passwort stimmt nicht.", "error")
            return back("konto")
        session["totp_pending"] = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
        return redirect(url_for("totp_setup"))

    def totp_uri(secret):
        return "otpauth://totp/ubusec:%s@%s?secret=%s&issuer=ubusec" % (session["user"], os.uname().nodename, secret)

    @app.route("/einstellungen/2fa")
    def totp_setup():
        sec = session.get("totp_pending")
        if not sec:
            return back("konto")
        return render_template("totp.html", secret=" ".join(sec[i:i + 4] for i in range(0, len(sec), 4)),
                               has_qr=bool(shutil.which("qrencode")))

    @app.route("/einstellungen/2fa/qr.svg")
    def totp_qr():
        sec = session.get("totp_pending")
        if not sec or not shutil.which("qrencode"):
            abort(404)
        r = subprocess.run(["qrencode", "-t", "SVG", "-m", "2", "-s", "6", "-o", "-", totp_uri(sec)],
                           capture_output=True, timeout=10)
        resp = Response(r.stdout, mimetype="image/svg+xml")
        resp.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'"
        return resp

    @app.route("/einstellungen/2fa/bestaetigen", methods=["POST"])
    def totp_confirm():
        sec = session.get("totp_pending")
        if not sec:
            return back("konto")
        c = totp_check(sec, request.form.get("code", ""))
        if c is None:
            flash("Der Code passt nicht. Prüfe, ob die Uhrzeit am Handy stimmt, und versuche es mit dem nächsten Code.", "error")
            return redirect(url_for("totp_setup"))
        users = load_users()
        users[session["user"]]["totp"] = sec
        save_users(users)
        totp_used[session["user"]] = c
        session.pop("totp_pending", None)
        flash("Zwei-Faktor-Anmeldung ist aktiv. Ab der nächsten Anmeldung brauchst du den Code aus der App.", "ok")
        return back("konto")

    @app.route("/einstellungen/2fa/aus", methods=["POST"])
    def totp_off():
        users = load_users()
        u = users[session["user"]]
        if not need_pw("current") or (u["totp"] and totp_check(u["totp"], request.form.get("code", "")) is None):
            flash("Passwort oder Code stimmen nicht – Zwei-Faktor bleibt aktiv.", "error")
            return back("konto")
        u["totp"] = ""
        save_users(users)
        flash("Zwei-Faktor-Anmeldung ist ausgeschaltet. Empfehlung: bald wieder einrichten.", "info")
        return back("konto")

    @app.route("/einstellungen/benutzer/neu", methods=["POST"])
    def user_add():
        name = request.form.get("name", "").strip()
        users = load_users()
        if not USERNAME.match(name):
            flash("Benutzername: 1–32 Zeichen aus Buchstaben, Ziffern, Punkt, Unterstrich, Bindestrich.", "error")
        elif name in users:
            flash("Den Benutzer %s gibt es schon." % name, "error")
        elif len(request.form.get("password", "")) < 12:
            flash("Das Startpasswort braucht mindestens 12 Zeichen.", "error")
        elif not need_pw("current"):
            flash("Zur Bestätigung dein eigenes Passwort eingeben.", "error")
        else:
            users[name] = {"hash": hash_pw(request.form["password"]), "totp": ""}
            save_users(users)
            flash("Benutzer %s angelegt. Nach der ersten Anmeldung bitte das Passwort ändern und Zwei-Faktor einrichten." % name, "ok")
        return back("benutzer")

    @app.route("/einstellungen/benutzer/<name>/loeschen", methods=["POST"])
    def user_del(name):
        users = load_users()
        if name == session["user"]:
            flash("Du kannst dich nicht selbst löschen.", "error")
        elif name not in users:
            abort(404)
        elif not need_pw("current"):
            flash("Zur Bestätigung dein eigenes Passwort eingeben.", "error")
        else:
            users.pop(name)
            save_users(users)
            flash("Benutzer %s gelöscht." % name, "ok")
        return back("benutzer")

    def validated(keys):
        vals, errors = {}, []
        for k in keys:
            v = request.form.get(k, "").strip()
            if k in CHECKBOX_KEYS:
                v = "1" if request.form.get(k) else "0"
            if k in PATH_KEYS:
                v = " ".join(x.rstrip("/") or "/" for x in v.replace(",", " ").split())
            if not re.fullmatch(SETTING_RX[k], v):
                errors.append(SETTING_LABEL.get(k, k))
            vals[k] = v
        return vals, errors

    @app.route("/einstellungen/benachrichtigung", methods=["POST"])
    def save_notify():
        vals, errors = validated(["MAIL_TO", "NTFY_URL", "NOTIFY_MIN", "NOTIFY_ONLY_NEW"])
        if errors:
            flash("Bitte prüfen: " + ", ".join(errors) + ".", "error")
        else:
            enqueue_ctl(dict(vals, action="settings", user=session["user"]))
            flash("Benachrichtigungen werden gespeichert …", "ok")
        return back("benachrichtigung")

    @app.route("/einstellungen/test", methods=["POST"])
    def test_notify():
        enqueue_ctl({"action": "testnotify", "user": session["user"]})
        flash("Testnachricht wird gesendet …", "ok")
        return back("benachrichtigung")

    @app.route("/einstellungen/scan", methods=["POST"])
    def save_scan():
        keys = ["KEEP_DAYS", "CLAM_PATHS_QUICK", "CLAM_MAX_FILESIZE", "WEB_PATHS", "SITES_EXCLUDE", "SITES_EXTRA", "SITES_TESTSSL",
                "CLAM_ENGINE", "CLAM_PARALLEL", "CLAM_QUICK_CHANGED", "CLAM_EXCLUDE_DB", "CLAM_EXCLUDE_BACKUPS", "CLAM_EXCLUDE_LOGS", "CLAM_EXCLUDE_MAIL",
                "CLAM_EXCLUDE_NEXTCLOUD", "CLAM_EXCLUDE_CUSTOM", "UPDATE_CHECK"]
        tok = request.form.get("WPSCAN_API_TOKEN", "").strip()
        if tok or request.form.get("token_remove"):
            keys.append("WPSCAN_API_TOKEN")
        vals, errors = validated(keys)
        if request.form.get("token_remove"):
            vals["WPSCAN_API_TOKEN"] = ""
        if errors:
            flash("Bitte prüfen: " + ", ".join(errors) + ".", "error")
        else:
            enqueue_ctl(dict(vals, action="settings", user=session["user"]))
            flash("Scan-Einstellungen werden gespeichert …", "ok")
        return back("scan")

    @app.route("/einstellungen/zeitplan", methods=["POST"])
    def save_schedule():
        f = {"action": "schedule", "user": session["user"]}
        for t in ("QUICK", "FULL"):
            days = [d for d, _ in DAYS if request.form.get("%s_%s" % (t, d))]
            tm = request.form.get(t + "_TIME", "")
            if not days or not re.fullmatch(r"([01][0-9]|2[0-3]):[0-5][0-9]", tm):
                flash("Bitte für jeden Scan mindestens einen Tag und eine gültige Uhrzeit wählen.", "error")
                return back("zeitplan")
            f.update({t + "_ON": "1" if request.form.get(t + "_ON") else "0", t + "_DAYS": ",".join(days), t + "_TIME": tm})
        overlap = set(f["QUICK_DAYS"].split(",")) & set(f["FULL_DAYS"].split(","))
        enqueue_ctl(f)
        msg = "Zeitplan wird übernommen …"
        if overlap and f["QUICK_ON"] == "1" and f["FULL_ON"] == "1":
            msg += " Hinweis: An %s laufen beide Scans; der zweite wartet, bis der erste fertig ist." % \
                   ", ".join(n for d, n in DAYS if d in overlap)
        flash(msg, "ok")
        return back("zeitplan")

    @app.route("/einstellungen/fehlalarm/entfernen", methods=["POST"])
    def unignore():
        pat = request.form.get("pattern", "")
        if pat not in [e["pattern"] for e in (ignore_entries() or [])]:
            abort(400)
        enqueue_ctl({"action": "unignore", "pattern": pat, "user": session["user"]})
        flash("Die Meldung wird ab dem nächsten Scan wieder angezeigt.", "ok")
        return back("fehlalarme")

    # ------------------------------------------------------------ Werkzeuge ------
    @app.route("/werkzeuge")
    def tools():
        data = read_json(os.path.join(STATE_DIR, "tools.json"), {}) or {}
        state = read_json(os.path.join(STATE_DIR, "tools-update.state"), {}) or {}
        if state.get("running") and time.time() - state.get("time", 0) > 3600:
            state["running"] = False
        try:
            with open(os.path.join(STATE_DIR, "tools-update.log"), encoding="utf-8", errors="replace") as f:
                log = f.read()[-12000:]
        except OSError:
            log = ""
        conf = read_json(os.path.join(STATE_DIR, "settings.json"), {}) or {}
        # Ergebnis der letzten Aktion nur einen Tag lang hervorheben
        if state.get("running") or time.time() - state.get("time", 0) > 86400:
            state["result"] = ""
        # AIDE-Datenbank: Fortschritt live (nicht erst nach der nächsten Werkzeugprüfung)
        aide = read_json(os.path.join(STATE_DIR, "aide-init.json"), None) or {}
        if aide.get("state") == "running":
            alive = False
            try:
                pid = int(open(os.path.join(STATE_DIR, "aide-init.running")).read().strip())
                os.kill(pid, 0)
                alive = True
            except PermissionError:      # Prozess gehört root – er läuft also
                alive = True
            except (OSError, ValueError):
                alive = False
            if not alive:
                aide["state"] = "aborted"
            aide["minutes"] = int((time.time() - aide.get("started", time.time())) / 60)
        elif aide.get("finished"):
            aide["minutes"] = max(1, int((aide["finished"] - aide.get("started", aide["finished"])) / 60))
            if time.time() - aide["finished"] > 7 * 86400 and aide.get("state") == "ok":
                aide = {}
        if aide.get("state") in ("failed", "aborted"):
            try:
                with open(os.path.join(LOG_DIR, "aide-init.log"), encoding="utf-8", errors="replace") as f:
                    aide["log"] = f.read()[-3000:]
            except OSError:
                aide["log"] = ""
        return render_template("tools.html", data=data, tools=data.get("tools", []), me=data.get("ubusec", {}),
                               upd=state, log=log, status=read_status(), conf=conf, aide=aide)

    @app.route("/werkzeuge/<aktion>", methods=["POST"])
    def tools_action(aktion):
        actions = {"pruefen": ("toolscheck", "Die Werkzeuge werden geprüft …"),
                   "aktualisieren": ("toolsupdate", "Die Werkzeuge werden aktualisiert. Das kann einige Minuten dauern …"),
                   "lynis": ("lynisrepo", "Die Paketquelle des Herstellers wird eingerichtet und Lynis aktualisiert …"),
                   "aide-installieren": ("toolinstall", "AIDE wird installiert; danach wird die Datenbank im Hintergrund angelegt …"),
                   "maldet-installieren": ("toolinstall", "Linux Malware Detect wird heruntergeladen und installiert …"),
                   "aide-einrichten": ("aideinit", "Die AIDE-Datenbank wird im Hintergrund angelegt – das kann bis zu einer Stunde dauern …"),
                   "aide-entfernen": ("tooluninstall", "AIDE wird entfernt …"),
                   "maldet-entfernen": ("tooluninstall", "Linux Malware Detect wird entfernt …")}
        if aktion not in actions:
            abort(404)
        st = read_status()
        if aktion != "pruefen" and st.get("running"):
            flash("Während ein Scan läuft, werden keine Werkzeuge aktualisiert. Bitte warten oder den Scan abbrechen.", "error")
            return redirect(url_for("tools"))
        req = {"action": actions[aktion][0], "user": session["user"]}
        if aktion.endswith(("-installieren", "-entfernen")):
            req["tool"] = aktion.split("-")[0]
        enqueue_ctl(req)
        flash(actions[aktion][1], "ok")
        return redirect(url_for("tools"))

    @app.errorhandler(400)
    @app.errorhandler(404)
    def err(e):
        return render_template("error.html", code=e.code, text=getattr(e, "description", "")), e.code

    return app


# =============================================================================
#  Kommandozeile
# =============================================================================
def cmd_useradd(name, totp):
    if not USERNAME.match(name):
        sys.exit("Ungültiger Benutzername.")
    users = load_users()
    while True:
        pw = getpass.getpass("Passwort für %s (mind. 12 Zeichen): " % name)
        if len(pw) < 12:
            print("Zu kurz.")
            continue
        if pw != getpass.getpass("Wiederholen: "):
            print("Stimmt nicht überein.")
            continue
        break
    secret = ""
    if totp:
        secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
        uri = "otpauth://totp/ubusec:%s@%s?secret=%s&issuer=ubusec" % (name, os.uname().nodename, secret)
        print("\nZwei-Faktor-Anmeldung einrichten – in der Authenticator-App (z. B. Aegis, Google/Microsoft "
              "Authenticator) diesen Code scannen oder den Schlüssel eintippen:\n")
        if shutil.which("qrencode"):
            subprocess.run(["qrencode", "-t", "ANSIUTF8", uri])
        print("Schlüssel: %s\n" % " ".join(secret[i:i + 4] for i in range(0, len(secret), 4)))
        for _ in range(3):
            if totp_check(secret, input("Zur Bestätigung den 6-stelligen Code aus der App eingeben: ")) is not None:
                break
            print("Code passt nicht – Uhrzeit von Server und Handy prüfen.")
        else:
            sys.exit("Abgebrochen, nichts gespeichert.")
    users[name] = {"hash": hash_pw(pw), "totp": secret}
    save_users(users)
    print("✔ Benutzer %s gespeichert%s." % (name, " (mit Zwei-Faktor)" if secret else ""))


def cmd_userdel(name):
    users = load_users()
    if users.pop(name, None) is None:
        sys.exit("Benutzer %s nicht gefunden." % name)
    save_users(users)
    print("✔ Benutzer %s gelöscht." % name)


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return
    if args[0] == "serve":
        conf = read_conf()
        app = create_app()
        host, port = conf["BIND"], int(conf["PORT"])
        try:
            from waitress import serve
            print("ubusec-Weboberfläche %s auf http://%s:%d" % (VERSION, host, port), flush=True)
            serve(app, host=host, port=port, threads=4, ident="ubusec")
        except ImportError:
            print("waitress fehlt – Entwicklungsserver wird verwendet", flush=True)
            app.run(host=host, port=port)
    elif args[0] == "useradd" and len(args) >= 2:
        cmd_useradd(args[1], "--totp" in args[2:])
    elif args[0] == "userdel" and len(args) == 2:
        cmd_userdel(args[1])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
