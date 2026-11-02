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
    "UPDATE_CHECK": r"[01]",
    "CLAM_EXCLUDE_DB": r"[01]", "CLAM_EXCLUDE_BACKUPS": r"[01]", "CLAM_EXCLUDE_LOGS": r"[01]",
    "CLAM_EXCLUDE_MAIL": r"[01]", "CLAM_EXCLUDE_NEXTCLOUD": r"[01]",
    "CLAM_EXCLUDE_CUSTOM": r"(/[A-Za-z0-9._/-]*( /[A-Za-z0-9._/-]*){0,29})?",
}
CHECKBOX_KEYS = {"UPDATE_CHECK", "NOTIFY_ONLY_NEW", "SITES_TESTSSL", "CLAM_EXCLUDE_DB", "CLAM_EXCLUDE_BACKUPS", "CLAM_EXCLUDE_LOGS",
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
    elif mod == "rootkit" and re.search(r"temporären|/dev/shm|versteckte|Hidden|aus gelöschten", text):
        kind = "fileinfo"
        args = [m.rstrip(":") for m in _PATH_TOKEN.findall(text)]
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


def current_state(reports):
    """Aktueller Gesamtstand: je Modul die Meldungen aus dem jüngsten Scan, der es geprüft hat."""
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
            L += ["- %s" % d for d in i["details"]] + ([""] if i["details"] else [])
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


def export_csv(c):
    import csv
    import io
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";", quoting=csv.QUOTE_MINIMAL)
    w.writerow(["Schweregrad", "Bereich", "Meldung", "Details", "Warum", "Behebung", "Aufwand", "Geprüft", "Neu", "Erledigt"])
    for i in c["items"]:
        w.writerow([SEV_NAME[i["severity"]], i["module"], i["message"], "\n".join(i["details"]), i["why"],
                    "\n".join(t for t, _ in i["steps"]), i["effort"], i["checked"], "ja" if i["new"] else "", ""])
    for x in c["lynis"]:
        w.writerow(["Lynis", "Konfiguration & Härtung", x, "", "", "sudo lynis show details " + x.rsplit("[", 1)[-1].rstrip("]"),
                    "", "", "", ""])
    return "﻿" + buf.getvalue()   # BOM, damit Excel die Umlaute richtig liest


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
                H.append("<ul>" + "".join("<li>%s</li>" % e(d) for d in i["details"]) + "</ul>")
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
                if len(f) > 3 and f[2].isdigit() and 1000 <= int(f[2]) < 65534:
                    users.add(f[0])
        except OSError:
            pass
        users.update(d for d in os.listdir("/home") if os.path.isdir(os.path.join("/home", d))) if os.path.isdir("/home") else None
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
            self.user_rx = re.compile(r"(?<![\w.-])(%s)(?![\w-])" % alt)
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
            if len(i["details"]) > 8:
                L.append("- … und %d weitere gleichartige Einträge" % (len(i["details"]) - 8))
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

    @app.route("/api/pruefung/<vid>")
    def verify_status(vid):
        if not re.fullmatch(r"[a-f0-9]{16}", vid):
            abort(404)
        res, pending = verify_result(vid)
        return jsonify({"pending": pending, "done": bool(res), "time": (res or {}).get("time", 0)})

    @app.route("/berichte")
    def reports():
        return render_template("reports.html", reports=all_reports())

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
        if os.path.getsize(path) > 5 * 1024 * 1024:
            return send_file(path, as_attachment=True, download_name=name)
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
        if fmt not in ("md", "csv", "html", "ki", "ki-zuordnung"):
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
        body = {"md": export_markdown, "csv": export_csv, "html": export_html}[fmt](c)
        mime = {"md": "text/markdown", "csv": "text/csv", "html": "text/html"}[fmt]
        name = "ubusec-empfehlungen-%s-%s.%s" % (re.sub(r"[^A-Za-z0-9.-]", "_", c["host"] or "server"), stamp, fmt)
        resp = Response(body, mimetype=mime + "; charset=utf-8")
        resp.headers["Content-Disposition"] = 'attachment; filename="%s"' % name
        return resp

    @app.route("/baseline", methods=["POST"])
    def accept_baseline():
        if request.form.get("confirm") != "ja":
            flash("Bitte bestätige, dass du die Änderungen geprüft hast.", "error")
            return redirect(request.referrer or url_for("recommendations"))
        enqueue_ctl({"action": "accept", "user": session["user"]})
        flash("Der aktuelle Zustand wird als neue Baseline übernommen. Beim nächsten Scan entfallen die "
              "Baseline-Meldungen.", "ok")
        return redirect(url_for("recommendations"))

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

    @app.route("/einstellungen")
    def settings():
        users = load_users()
        me = users.get(session["user"], {})
        conf = read_json(os.path.join(STATE_DIR, "settings.json"), {}) or {}
        return render_template("settings.html", users=sorted(users), me=me, conf=conf, DAYS=DAYS,
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
                "CLAM_ENGINE", "CLAM_PARALLEL", "CLAM_EXCLUDE_DB", "CLAM_EXCLUDE_BACKUPS", "CLAM_EXCLUDE_LOGS", "CLAM_EXCLUDE_MAIL",
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
        return render_template("tools.html", data=data, tools=data.get("tools", []), me=data.get("ubusec", {}),
                               upd=state, log=log, status=read_status(), conf=conf)

    @app.route("/werkzeuge/<aktion>", methods=["POST"])
    def tools_action(aktion):
        actions = {"pruefen": ("toolscheck", "Die Werkzeuge werden geprüft …"),
                   "aktualisieren": ("toolsupdate", "Die Werkzeuge werden aktualisiert. Das kann einige Minuten dauern …"),
                   "lynis": ("lynisrepo", "Die Paketquelle des Herstellers wird eingerichtet und Lynis aktualisiert …")}
        if aktion not in actions:
            abort(404)
        st = read_status()
        if aktion != "pruefen" and st.get("running"):
            flash("Während ein Scan läuft, werden keine Werkzeuge aktualisiert. Bitte warten oder den Scan abbrechen.", "error")
            return redirect(url_for("tools"))
        enqueue_ctl({"action": actions[aktion][0], "user": session["user"]})
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
