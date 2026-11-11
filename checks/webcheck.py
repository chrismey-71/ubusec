#!/usr/bin/env python3
"""ubusec – Prüfungen für Websites, Domains und Webanwendungen.

Wird von ubusec (als root) aufgerufen:
    webcheck.py sites  --raw DIR --mode quick|full
    webcheck.py apps   --raw DIR --mode quick|full
    webcheck.py tools  --raw DIR --mode quick|full   (Aktualität der Werkzeuge, JSON nach $TOOLS_JSON)
    webcheck.py mail   --raw DIR --mode quick|full   (Postfix/Dovecot, Spamschutz, Ruf der Server-IP)
    webcheck.py nc-datadirs        (Datenordner der Nextcloud-Installationen)

Ausgabe: eine Zeile pro Befund  SCHWERE<TAB>MELDUNG<TAB>DETAIL1\\x1fDETAIL2…

Grundsätze:
  * Es wird nichts verändert und kein Code der Webseiten als root ausgeführt.
    Versionen werden aus Dateien gelesen; wo ein Werkzeug der Anwendung nötig ist
    (Nextcloud occ), läuft es unter dem Besitzer der Installation.
  * HTTP-Prüfungen gehen an die IP, an die der Apache-VirtualHost gebunden ist,
    mit dem richtigen Hostnamen (SNI) – also an genau diesen Server.
"""
import concurrent.futures as cf
import datetime
import fnmatch
import glob
import http.client
import ipaddress
import json
import os
import pwd
import random
import re
import socket
import ssl
import string
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)

UA = "ubusec-webcheck/1.2 (+lokale Sicherheitsprüfung)"
CACHE = "/var/lib/ubusec/cache"
TIMEOUT = float(os.environ.get("SITES_TIMEOUT", "8"))
TODAY = datetime.date.today().isoformat()
OUT = []
AGG = {}
NET_FAIL = set()   # externe Datenquellen, die nicht erreichbar waren


# =============================================================================
#  Ausgabe
# =============================================================================
def add(sev, msg, *details):
    OUT.append((sev, msg, [str(d) for d in details if d]))


def agg(sev, msg, item):
    """Gleichartige Befunde über mehrere Domains/Installationen zusammenfassen."""
    AGG.setdefault((sev, msg), []).append(str(item))


def plural(n, one, many):
    return "%d %s" % (n, one if n == 1 else many)


def flush_agg():
    for (sev, msg), items in AGG.items():
        items = sorted(set(items))
        n = len(items)
        text = msg.replace("{n}", str(n)).replace("{domains}", plural(n, "Domain", "Domains")) \
                  .replace("{inst}", plural(n, "Installation", "Installationen"))
        shown = items[:15] + (["… und %d weitere" % (n - 15)] if n > 15 else [])
        add(sev, text, *shown)


def emit():
    flush_agg()
    for sev, msg, det in OUT:
        clean = lambda s: s.replace("\t", " ").replace("\n", " ").replace("\x1f", " ")  # noqa: E731
        print("%s\t%s\t%s" % (sev, clean(msg), "\x1f".join(clean(d) for d in det)))


# =============================================================================
#  Hilfsfunktionen
# =============================================================================
def run(cmd, timeout=60, user=None, cwd=None):
    if user:
        cmd = ["runuser", "-u", user, "--"] + cmd
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        return r.returncode, r.stdout, r.stderr
    except Exception as e:  # noqa: BLE001
        return 127, "", str(e)


def vt(s):
    return tuple(int(x) for x in re.findall(r"\d+", s or "")[:4])


def read(path, limit=2_000_000):
    try:
        with open(path, "rb") as f:
            return f.read(limit).decode("utf-8", "replace")
    except OSError:
        return ""


def owner(path):
    try:
        return pwd.getpwuid(os.stat(path).st_uid).pw_name
    except (OSError, KeyError):
        return None


def world_readable(path):
    try:
        return bool(os.stat(path).st_mode & 0o004)
    except OSError:
        return False


def get_json(url, cache_key=None, max_age=86400, headers=None):
    """Externe API mit Tages-Cache (endoflife.date, wordpress.org, GitHub)."""
    if cache_key:
        os.makedirs(CACHE, mode=0o700, exist_ok=True)
        cp = os.path.join(CACHE, re.sub(r"[^A-Za-z0-9._-]", "_", cache_key) + ".json")
        try:
            if time.time() - os.path.getmtime(cp) < max_age:
                with open(cp, encoding="utf-8") as f:
                    return json.load(f)
        except (OSError, ValueError):
            pass
    try:
        req = urllib.request.Request(url, headers=dict({"User-Agent": UA, "Accept": "application/json"}, **(headers or {})))
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"_not_found": True}
        NET_FAIL.add(urllib.parse.urlsplit(url).hostname)
        return None
    except Exception:  # noqa: BLE001
        NET_FAIL.add(urllib.parse.urlsplit(url).hostname)
        return None
    if cache_key:
        try:
            with open(cp, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except OSError:
            pass
    return data


def eol_info(product, version, parts):
    """Support-Status einer Versionslinie laut endoflife.date."""
    cyc = ".".join(str(x) for x in vt(version)[:parts])
    data = get_json("https://endoflife.date/api/%s.json" % product, "eol-" + product)
    if not isinstance(data, list):
        return None
    for c in data:
        if str(c.get("cycle")) == cyc:
            eol = c.get("eol")
            past = eol is True or (isinstance(eol, str) and eol <= TODAY)
            return {"cycle": cyc, "eol": eol, "past": past, "latest": c.get("latest")}
    return {"cycle": cyc, "eol": None, "past": None, "latest": None, "unknown": True}


def pkg_from_ubuntu(pkg):
    """True, wenn das installierte Paket aus dem Ubuntu-Archiv stammt (Canonical patcht es)."""
    rc, out, _ = run(["apt-cache", "policy", pkg], timeout=30)
    if rc != 0 or "***" not in out:
        return None
    after = out.split("***", 1)[1].splitlines()[1:6]
    for line in after:
        if re.match(r"^\s+\d+\s+(http|https|file|/)", line):
            return "ubuntu.com" in line or "canonical.com" in line
        if re.match(r"^\s+\S+\s+\d+$", line):  # nächste Version
            break
    return None


# =============================================================================
#  Domains und VirtualHosts
# =============================================================================
def apache_vhosts():
    """Hostname -> {docroot, ip, ssl} aus der Apache-Konfiguration."""
    hosts = {}
    files = glob.glob("/etc/apache2/sites-enabled/*")
    for f in files:
        txt = read(f)
        for m in re.finditer(r"<VirtualHost\s+([^>]*)>(.*?)</VirtualHost>", txt, re.S | re.I):
            addr, body = m.group(1), m.group(2)
            names = []
            for line in re.findall(r"^\s*Server(?:Name|Alias)\s+(.+)$", body, re.M | re.I):
                names += [n.lower().split(":")[0] for n in line.split()]
            dr = re.search(r'^\s*DocumentRoot\s+"?([^"\s]+)"?', body, re.M | re.I)
            is_ssl = bool(re.search(r"^\s*SSLEngine\s+on", body, re.M | re.I)) or ":443" in addr
            ip = None
            am = re.match(r"\[?([0-9a-fA-F.:]+?)\]?:\d+", addr.split()[0]) if addr.split() else None
            if am and am.group(1) not in ("*", "_default_"):
                ip = am.group(1)
            for n in names:
                h = hosts.setdefault(n, {"docroot": None, "ip": None, "ssl": False, "ssl_ip": None})
                if dr and not h["docroot"]:
                    h["docroot"] = dr.group(1)
                if is_ssl:
                    h["ssl"] = True
                    h["ssl_ip"] = h["ssl_ip"] or ip
                h["ip"] = h["ip"] or ip
    return hosts


def virtualmin_domains():
    if not shutil_which("virtualmin"):
        return None
    for args in (["--name-only", "--with-feature", "web"], ["--name-only"]):
        rc, out, _ = run(["virtualmin", "list-domains"] + args, timeout=90)
        if rc == 0 and out.strip():
            return [l.strip().lower() for l in out.splitlines() if l.strip()]
    return None


def shutil_which(cmd):
    from shutil import which
    return which(cmd)


def domain_list(vh):
    src = "Virtualmin"
    doms = virtualmin_domains()
    if doms is None:
        src = "Apache-Konfiguration"
        doms = [n for n in vh if "." in n and not n.startswith(("www.", "mail.", "autoconfig.", "autodiscover.", "webmail.", "admin."))
                and not re.match(r"^[0-9.]+$", n) and "*" not in n]
    doms += os.environ.get("SITES_EXTRA", "").split()
    excl = os.environ.get("SITES_EXCLUDE", "").split()
    doms = [d for d in dict.fromkeys(doms) if not any(fnmatch.fnmatch(d, e) for e in excl)]
    return sorted(doms), src


def target_ip(domain, vh, port):
    h = vh.get(domain) or vh.get("www." + domain)
    if h:
        ip = h["ssl_ip"] if port == 443 else h["ip"]
        return ip or "127.0.0.1"
    try:
        return socket.getaddrinfo(domain, port, proto=socket.IPPROTO_TCP)[0][4][0]
    except OSError:
        return None


# =============================================================================
#  HTTP
# =============================================================================
class Resp:
    def __init__(self, status, headers, body):
        self.status, self.headers, self.body = status, headers, body

    def h(self, name):
        return self.headers.get(name.lower(), "")


class _SNIConn(http.client.HTTPSConnection):
    def __init__(self, sni, *a, **k):
        self._sni = sni
        super().__init__(*a, **k)

    def connect(self):
        sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self._sni)


FETCH_ERR = [""]   # Grund des letzten Fehlschlags von fetch() (für verständliche Meldungen)


def fetch(domain, ip, path="/", scheme="https", method="GET", body=None, limit=65536, ctype=None, timeout=None):
    FETCH_ERR[0] = ""
    try:
        if scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            c = _SNIConn(domain, ip, 443, timeout=timeout or TIMEOUT, context=ctx)
        else:
            c = http.client.HTTPConnection(ip, 80, timeout=timeout or TIMEOUT)
        hdr = {"Host": domain, "User-Agent": UA, "Accept": "*/*"}
        if ctype:
            hdr["Content-Type"] = ctype
        c.request(method, path, body=body, headers=hdr)
        r = c.getresponse()
        headers = {}
        for k, v in r.getheaders():
            k = k.lower()
            headers[k] = (headers[k] + ", " + v) if k in headers else v
        data = r.read(limit) if method != "HEAD" else b""
        c.close()
        return Resp(r.status, headers, data)
    except Exception as e:  # noqa: BLE001
        FETCH_ERR[0] = "Zeitüberschreitung" if isinstance(e, (socket.timeout, TimeoutError)) else \
            "Verbindung abgelehnt" if isinstance(e, ConnectionRefusedError) else \
            "Verbindung abgebrochen" if isinstance(e, (ConnectionResetError, http.client.RemoteDisconnected)) else \
            type(e).__name__
        return None


def is_html(r):
    return "text/html" in r.h("content-type") or r.body[:200].lstrip().lower().startswith((b"<!doctype", b"<html"))


# =============================================================================
#  Modul: sites
# =============================================================================
def sev_for_days(days):
    return "HOCH" if days < 7 else "MITTEL"


PROBES = [
    # Pfad, Prüfung des Inhalts, Schwere, Meldung
    ("/.git/HEAD", lambda r: r.body.startswith(b"ref:") or re.match(rb"^[0-9a-f]{40}\s*$", r.body), "HOCH",
     "Git-Repository öffentlich abrufbar (Quellcode und Verlauf)"),
    ("/.env", lambda r: not is_html(r) and re.search(rb"^[A-Z][A-Z0-9_]{2,}=", r.body, re.M), "KRITISCH",
     ".env-Datei mit Zugangsdaten öffentlich abrufbar"),
    ("/.svn/entries", lambda r: not is_html(r) and len(r.body) > 0 and r.body[:3].isdigit(), "HOCH",
     "SVN-Daten öffentlich abrufbar"),
    ("/wp-config.php.bak", lambda r: b"DB_PASSWORD" in r.body, "KRITISCH", "Sicherungskopie der WordPress-Konfiguration öffentlich"),
    ("/wp-config.php.old", lambda r: b"DB_PASSWORD" in r.body, "KRITISCH", "Sicherungskopie der WordPress-Konfiguration öffentlich"),
    ("/wp-config.php~", lambda r: b"DB_PASSWORD" in r.body, "KRITISCH", "Sicherungskopie der WordPress-Konfiguration öffentlich"),
    ("/wp-config.php.save", lambda r: b"DB_PASSWORD" in r.body, "KRITISCH", "Sicherungskopie der WordPress-Konfiguration öffentlich"),
    ("/wp-config.php.orig", lambda r: b"DB_PASSWORD" in r.body, "KRITISCH", "Sicherungskopie der WordPress-Konfiguration öffentlich"),
    ("/config.php.bak", lambda r: b"<?php" in r.body, "HOCH", "Sicherungskopie einer PHP-Konfiguration öffentlich"),
    ("/backup.sql", lambda r: re.search(rb"CREATE TABLE|INSERT INTO|-- (MySQL|MariaDB) dump", r.body), "KRITISCH", "Datenbank-Dump öffentlich abrufbar"),
    ("/dump.sql", lambda r: re.search(rb"CREATE TABLE|INSERT INTO|-- (MySQL|MariaDB) dump", r.body), "KRITISCH", "Datenbank-Dump öffentlich abrufbar"),
    ("/db.sql", lambda r: re.search(rb"CREATE TABLE|INSERT INTO|-- (MySQL|MariaDB) dump", r.body), "KRITISCH", "Datenbank-Dump öffentlich abrufbar"),
    ("/database.sql", lambda r: re.search(rb"CREATE TABLE|INSERT INTO|-- (MySQL|MariaDB) dump", r.body), "KRITISCH", "Datenbank-Dump öffentlich abrufbar"),
    ("/backup.zip", lambda r: r.body[:4] == b"PK\x03\x04", "HOCH", "Backup-Archiv öffentlich abrufbar"),
    ("/backup.tar.gz", lambda r: r.body[:2] == b"\x1f\x8b", "HOCH", "Backup-Archiv öffentlich abrufbar"),
    ("/phpinfo.php", lambda r: b"PHP Version" in r.body and b"phpinfo" in r.body.lower(), "MITTEL", "phpinfo()-Seite öffentlich (verrät Serverdetails)"),
    ("/info.php", lambda r: b"PHP Version" in r.body and b"phpinfo" in r.body.lower(), "MITTEL", "phpinfo()-Seite öffentlich (verrät Serverdetails)"),
    ("/test.php", lambda r: b"PHP Version" in r.body and b"phpinfo" in r.body.lower(), "MITTEL", "phpinfo()-Seite öffentlich (verrät Serverdetails)"),
    ("/server-status", lambda r: b"Apache Server Status" in r.body, "MITTEL", "Apache-Statusseite öffentlich (zeigt aufgerufene Adressen und Besucher)"),
    ("/server-info", lambda r: b"Apache Server Information" in r.body, "MITTEL", "Apache-Infoseite öffentlich"),
    ("/.DS_Store", lambda r: r.body[:8] == b"\x00\x00\x00\x01Bud1", "NIEDRIG", ".DS_Store-Datei öffentlich (verrät Dateinamen)"),
    ("/wp-content/debug.log", lambda r: not is_html(r) and re.search(rb"PHP (Notice|Warning|Fatal|Deprecated)", r.body), "HOCH",
     "WordPress-Fehlerprotokoll öffentlich abrufbar"),
    ("/adminer.php", lambda r: b"Adminer" in r.body, "HOCH", "Adminer (Datenbank-Verwaltung) öffentlich erreichbar"),
    ("/composer.lock", lambda r: not is_html(r) and b'"packages"' in r.body, "NIEDRIG", "composer.lock öffentlich (verrät Bibliotheksversionen)"),
    ("/error_log", lambda r: not is_html(r) and re.search(rb"PHP (Notice|Warning|Fatal)", r.body), "MITTEL", "PHP-Fehlerprotokoll öffentlich abrufbar"),
]
PROBE_PATHS = {p for p, _, _, _ in PROBES}
LISTING_DIRS = ["/", "/wp-content/uploads/", "/uploads/", "/files/", "/backup/", "/images/", "/includes/"]


def check_domain(domain, vh, full):
    res = {"domain": domain, "notes": []}
    ip = target_ip(domain, vh, 443)
    ip80 = target_ip(domain, vh, 80)
    res["ip"] = ip
    if not ip:
        agg("NIEDRIG", "Domain nicht auflösbar oder nicht auf diesem Server ({domains})", domain)
        return res

    # --- Zertifikat -----------------------------------------------------------
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((ip, 443), TIMEOUT) as s, ctx.wrap_socket(s, server_hostname=domain) as t:
            cert = t.getpeercert()
            days = (ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) / 86400
            res["cert_days"] = round(days, 1)
            if days < 21:
                agg(sev_for_days(days), "TLS-Zertifikat läuft bald ab ({domains})", "%s (noch %d Tage)" % (domain, days))
    except ssl.SSLCertVerificationError as e:
        msg = getattr(e, "verify_message", "") or str(e)
        if "expired" in msg:
            agg("KRITISCH", "TLS-Zertifikat abgelaufen ({domains})", domain)
        else:
            agg("HOCH", "TLS-Zertifikat ungültig (Name, Aussteller oder Kette) ({domains})", "%s – %s" % (domain, msg))
        res["cert_error"] = msg
    except (OSError, ssl.SSLError) as e:
        agg("HOCH", "HTTPS nicht erreichbar ({domains})", "%s (%s)" % (domain, type(e).__name__))
        res["https"] = False
        return res

    # --- veraltete TLS-Versionen -----------------------------------------------
    try:
        old = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        old.check_hostname = False
        old.verify_mode = ssl.CERT_NONE
        old.minimum_version = ssl.TLSVersion.TLSv1
        old.maximum_version = ssl.TLSVersion.TLSv1_1
        old.set_ciphers("DEFAULT:@SECLEVEL=0")
        with socket.create_connection((ip, 443), TIMEOUT) as s, old.wrap_socket(s, server_hostname=domain) as t:
            agg("MITTEL", "Veraltete TLS-Versionen (1.0/1.1) aktiv ({domains})", "%s (%s)" % (domain, t.version()))
    except (OSError, ssl.SSLError, ValueError):
        pass

    # --- HTTP → HTTPS -------------------------------------------------------------
    r80 = fetch(domain, ip80 or ip, "/", "http")
    if r80 is not None:
        loc = r80.h("location")
        if not (r80.status in (301, 302, 307, 308) and loc.startswith("https://")):
            agg("MITTEL", "HTTP leitet nicht auf HTTPS um ({domains})", "%s (HTTP %d)" % (domain, r80.status))

    # --- Startseite und Header (einer Weiterleitung auf dieselbe Domain folgen) ---
    r = fetch(domain, ip, "/")
    path, host_used = "/", domain
    for _ in range(3):
        if r is None or r.status not in (301, 302, 307, 308):
            break
        loc = r.h("location")
        m = re.match(r"https://([^/]+)(/.*)?$", loc)
        if not m or m.group(1).lower().split(":")[0] not in (domain, "www." + domain, domain.replace("www.", "", 1)):
            break
        path, host_used = m.group(2) or "/", m.group(1).lower()
        r = fetch(host_used, ip, path)
    if r is None:
        # TLS klappt (siehe oben), nur die Seite antwortet nicht rechtzeitig – oft eine langsame Startseite
        # (großes WordPress, Cache leer). Einmal mit viel Zeit wiederholen, bevor etwas gemeldet wird.
        t0 = time.time()
        r = fetch(host_used, ip, path, timeout=45)
        took = time.time() - t0
        if r is None:
            agg("MITTEL", "Startseite antwortet über HTTPS nicht ({domains})",
                "%s – %s%s (verschlüsselte Verbindung selbst klappt)" % (
                    domain, FETCH_ERR[0] or "keine Antwort", " nach %d s" % took if FETCH_ERR[0] == "Zeitüberschreitung" else ""))
            return res
        agg("NIEDRIG", "Startseite antwortet sehr langsam ({domains})", "%s – %.0f s bis zur Antwort" % (domain, took))
    res["status"] = r.status
    if r.status < 500:
        hsts = r.h("strict-transport-security")
        if not hsts:
            agg("MITTEL", "HSTS-Header (Strict-Transport-Security) fehlt ({domains})", domain)
        else:
            m = re.search(r"max-age=(\d+)", hsts)
            if not m or int(m.group(1)) < 15552000:
                agg("NIEDRIG", "HSTS gilt zu kurz (unter 6 Monaten) ({domains})", domain)
        csp = r.h("content-security-policy")
        if not csp:
            if r.h("content-security-policy-report-only"):
                agg("INFO", "Content-Security-Policy nur im Testmodus (Report-Only) ({domains})", domain)
            else:
                agg("NIEDRIG", "Content-Security-Policy fehlt ({domains})", domain)
        if "nosniff" not in r.h("x-content-type-options").lower():
            agg("NIEDRIG", "X-Content-Type-Options fehlt ({domains})", domain)
        if not r.h("x-frame-options") and "frame-ancestors" not in csp:
            agg("NIEDRIG", "Schutz vor Einbettung in fremde Seiten fehlt (X-Frame-Options) ({domains})", domain)
        if not r.h("referrer-policy"):
            agg("NIEDRIG", "Referrer-Policy fehlt ({domains})", domain)
        if not r.h("permissions-policy"):
            agg("INFO", "Permissions-Policy fehlt ({domains})", domain)
        leaks = []
        if re.search(r"\d", r.h("server")):
            leaks.append("Server: " + r.h("server"))
        if re.search(r"\d", r.h("x-powered-by")):
            leaks.append("X-Powered-By: " + r.h("x-powered-by"))
        if leaks:
            agg("NIEDRIG", "Softwareversionen im HTTP-Header sichtbar ({domains})", "%s – %s" % (domain, "; ".join(leaks)))
        res["headers"] = r.headers

        # Source-Maps der eingebundenen Skripte
        if is_html(r):
            srcs = re.findall(rb'<script[^>]+src=["\']([^"\']+\.js)(?:\?[^"\']*)?["\']', r.body)
            checked = 0
            for s in srcs:
                s = s.decode("utf-8", "replace")
                if s.startswith("//") or (s.startswith("http") and domain not in s.split("/")[2]):
                    continue
                p = re.sub(r"^https?://[^/]+", "", s)
                if not p.startswith("/"):
                    p = "/" + p
                checked += 1
                m = fetch(domain, ip, p + ".map", limit=2048)
                if m and m.status == 200 and m.body.lstrip().startswith(b"{") and b'"sources"' in m.body:
                    agg("NIEDRIG", "Source-Maps öffentlich (unkompilierter JavaScript-Quellcode) ({domains})",
                        "https://%s%s.map" % (domain, p))
                    break
                if checked >= 6:
                    break

    # --- offene Dateien und Verzeichnislisten -------------------------------------
    for p, test, sev, label in PROBES:
        x = fetch(domain, ip, p, limit=8192)
        if x and x.status == 200 and x.body:
            try:
                if test(x):
                    if p in ("/server-status", "/server-info") and apache_location_local_only(p):
                        # „Require local“ erlaubt auch Anfragen vom Server selbst – ubusec prüft von hier aus
                        agg("INFO", "Apache-Status-/Infoseite nur lokal freigegeben (Require local) – von außen gesperrt", "https://%s%s" % (domain, p))
                        continue
                    agg(sev, label, "https://%s%s" % (domain, p))
                    # zugehörige Datei nennen (für die Korrektur auf Knopfdruck)
                    dr = (vh.get(domain) or {}).get("docroot")
                    if p in ("/phpinfo.php", "/info.php", "/test.php", "/.DS_Store") and dr and os.path.isfile(dr + p):
                        agg(sev, label, "Datei: " + os.path.realpath(dr + p))
            except Exception:  # noqa: BLE001
                pass
    for d in LISTING_DIRS:
        x = fetch(domain, ip, d, limit=16384)
        if x and x.status == 200 and re.search(rb"<title>Index of ", x.body):
            agg("MITTEL", "Verzeichnisauflistung aktiv (Dateien eines Ordners sichtbar)", "https://%s%s" % (domain, d))

    # --- gründliche TLS-Prüfung (nur Vollscan, optional) ---------------------------
    if full and os.environ.get("SITES_TESTSSL") == "1" and shutil_which("testssl.sh"):
        out = os.path.join(os.environ.get("RAW", "/tmp"), "testssl-%s.json" % re.sub(r"[^a-z0-9.-]", "_", domain))
        run(["testssl.sh", "--quiet", "--warnings", "off", "--color", "0", "--severity", "MEDIUM",
             "--jsonfile", out, "--ip", ip, domain], timeout=900)
        try:
            for f in json.load(open(out, encoding="utf-8")):
                sv = f.get("severity", "")
                if sv in ("CRITICAL", "HIGH", "MEDIUM"):
                    s = {"CRITICAL": "HOCH", "HIGH": "HOCH", "MEDIUM": "MITTEL"}[sv]
                    agg(s, "testssl.sh: Schwächen in der TLS-Konfiguration", "%s – %s: %s" % (domain, f.get("id"), f.get("finding", "")[:120]))
        except (OSError, ValueError, TypeError):
            pass
    return res


# --- DNS / E-Mail ---------------------------------------------------------------
def dig(name, rtype):
    rc, out, _ = run(["dig", "+short", "+time=3", "+tries=2", rtype, name], timeout=20)
    if rc != 0:
        return []
    lines = [l.strip() for l in out.splitlines() if l.strip() and not l.startswith(";")]
    if rtype == "TXT":
        return ["".join(re.findall(r'"((?:[^"\\]|\\.)*)"', l)) or l for l in lines]
    return lines


def dig_status(name, rtype, server=None, cd=False):
    """(Status, Antworten) einer DNS-Abfrage, z. B. ("NOERROR", [...]) oder ("SERVFAIL", [])."""
    cmd = ["dig", "+time=3", "+tries=2", "+noall", "+comments", "+answer", rtype, name]
    if server:
        cmd.insert(1, "@" + server)
    if cd:
        cmd.insert(1, "+cd")
    rc, out, _ = run(cmd, timeout=25)
    m = re.search(r"status: (\w+)", out)
    ans = [l for l in out.splitlines() if l.strip() and not l.startswith(";")]
    return (m.group(1) if m else ("TIMEOUT" if rc else "?")), ans


def check_public_resolution(apex):
    """Ist die Zone über öffentliche Resolver auflösbar? Erkennt kaputtes DNSSEC (DS beim Registry passt nicht)."""
    for srv in ("1.1.1.1", "8.8.8.8"):
        st, _ = dig_status(apex, "SOA", srv)
        if st == "NOERROR":
            return
        if st == "SERVFAIL":
            st_cd, ans_cd = dig_status(apex, "SOA", srv, cd=True)
            if st_cd == "NOERROR" and ans_cd:
                ds = dig(apex, "DS")
                agg("HOCH", "DNSSEC-Fehler – Domain ist für viele Besucher und Mailserver nicht erreichbar ({domains})",
                    "%s – %s meldet SERVFAIL, ohne DNSSEC-Prüfung (+cd) kommt eine Antwort%s"
                    % (apex, srv, "; DS bei der Registry: " + ds[0][:60] if ds else ""))
            else:
                agg("HOCH", "Domain über öffentliche DNS-Resolver nicht auflösbar ({domains})", "%s – %s meldet %s" % (apex, srv, st))
            return
    # Zeitüberschreitung bei beiden: Netz des Servers blockiert vermutlich ausgehendes DNS – nichts melden


def zone_apex(name):
    parts = name.split(".")
    for i in range(len(parts) - 1):
        cand = ".".join(parts[i:])
        if dig(cand, "SOA"):
            return cand
    return ".".join(parts[-2:])


_LOC_CACHE = {}


def apache_location_local_only(loc):
    """True, wenn jede Apache-Freigabe für /server-status bzw. /server-info nur lokal oder für feste IPs gilt."""
    if loc in _LOC_CACHE:
        return _LOC_CACHE[loc]
    files = []
    for g in ("/etc/apache2/mods-enabled/*.conf", "/etc/apache2/conf-enabled/*.conf", "/etc/apache2/sites-enabled/*",
              "/etc/apache2/apache2.conf"):
        files += glob.glob(g)
    blocks = []
    for f in files:
        txt = read(f)
        for m in re.finditer(r"<Location\s+\"?%s\"?\s*>(.*?)</Location>" % re.escape(loc), txt, re.S | re.I):
            body = "\n".join(l for l in m.group(1).splitlines() if not l.strip().startswith("#"))
            blocks.append(body)
    ok = bool(blocks) and all(re.search(r"Require\s+(local|ip\s|host\s)", b, re.I) and not re.search(r"Require\s+all\s+granted", b, re.I)
                              for b in blocks)
    _LOC_CACHE[loc] = ok
    return ok


# Hostnamen-Domains von Server-Anbietern: Deren DNS (SPF, DMARC, CAA) verwaltet der Anbieter, nicht du
PROVIDER_ZONES = {"ultrasrv.de", "netcup.net", "contaboserver.net", "your-server.de", "vps.ovh.net", "vps.ovh.ca",
                  "ip-ionos.de", "stratoserver.net", "members.linode.com", "ip.linodeusercontent.com", "vultrusercontent.com",
                  "hostingersite.com", "1blu.de", "server4you.de", "dogado.net", "hosteurope.de", "kasserver.com"}


def check_dns(domains):
    if not shutil_which("dig"):
        add("NIEDRIG", "DNS-/E-Mail-Prüfung übersprungen: dig fehlt", "Installieren: apt install bind9-dnsutils")
        return {}
    info = {}
    apexes = {}
    for d in domains:
        a = zone_apex(d)
        apexes.setdefault(a, []).append(d)
    for apex in sorted(apexes):
        if apex in PROVIDER_ZONES:
            agg("INFO", "DNS-Prüfung übersprungen für Hostnamen des Server-Anbieters ({domains})",
                "%s – SPF, DMARC und CAA verwaltet der Anbieter" % ", ".join(apexes[apex]))
            continue
        check_public_resolution(apex)
        mx = dig(apex, "MX")
        txt = dig(apex, "TXT")
        spf = [t for t in txt if t.lower().startswith("v=spf1")]
        dm = [t for t in dig("_dmarc." + apex, "TXT") if t.lower().startswith("v=dmarc1")]
        pol = None
        if dm:
            m = re.search(r"\bp=(\w+)", dm[0], re.I)
            pol = m.group(1).lower() if m else None
        info[apex] = {"mx": mx, "spf": spf, "dmarc": dm}
        sends_mail = bool(mx or spf)
        if sends_mail:
            if not spf:
                agg("MITTEL", "Kein SPF-Eintrag ({domains})", apex)
            elif len(spf) > 1:
                agg("HOCH", "Mehrere SPF-Einträge (dadurch ungültig) ({domains})", apex)
            else:
                m = re.search(r"(^|\s)([+~?-]?)all\b", spf[0])
                q = m.group(2) if m else None
                if m is None or q == "?":
                    agg("MITTEL", "SPF ohne verbindlichen Abschluss (fehlendes oder ?all) ({domains})", "%s: %s" % (apex, spf[0]))
                elif q in ("+", ""):
                    agg("HOCH", "SPF erlaubt jedem Server das Senden (+all) ({domains})", apex)
                elif q == "~" and pol not in ("quarantine", "reject"):
                    agg("NIEDRIG", "SPF nur mit ~all und ohne strenge DMARC-Richtlinie ({domains})", "%s: %s" % (apex, spf[0]))
            if not dm:
                agg("MITTEL", "Kein DMARC-Eintrag ({domains})", apex)
            elif pol == "none":
                agg("NIEDRIG", "DMARC nur im Beobachtungsmodus (p=none) ({domains})", apex)
        # CAA gilt für die Domain und alle Subdomains (Zertifizierungsstellen suchen nach oben) – je Zone einmal melden
        missing = []
        for d in apexes[apex]:
            parts = d.split(".")
            if not any(dig(".".join(parts[i:]), "CAA") for i in range(len(parts) - 1)):
                missing.append(d)
        if missing:
            subs = [d for d in missing if d != apex]
            agg("NIEDRIG", "Kein CAA-Eintrag (beliebige Zertifizierungsstellen dürfen Zertifikate ausstellen) ({domains})",
                apex + (" – gilt auch für %d Subdomain%s" % (len(subs), "s" if len(subs) != 1 else "") if subs else ""))
    return info


def check_apache():
    if not os.path.isdir("/etc/apache2"):
        return
    files = ["/etc/apache2/apache2.conf"] + sorted(glob.glob("/etc/apache2/conf-enabled/*.conf"))
    tokens = sig = trace = None
    for f in files:
        for line in read(f).splitlines():
            line = line.split("#", 1)[0].strip()
            m = re.match(r"(?i)^(ServerTokens|ServerSignature|TraceEnable)\s+(\S+)", line)
            if m:
                k, v = m.group(1).lower(), m.group(2).lower()
                if k == "servertokens":
                    tokens = v
                elif k == "serversignature":
                    sig = v
                else:
                    trace = v
    issues = []
    if tokens not in ("prod", "productonly"):
        issues.append("ServerTokens %s (empfohlen: Prod)" % (tokens or "nicht gesetzt = Full"))
    if sig not in ("off",):
        issues.append("ServerSignature %s (empfohlen: Off)" % (sig or "nicht gesetzt"))
    if issues:
        add("NIEDRIG", "Apache verrät Versionsdetails", *issues)
    if trace not in ("off",):
        add("NIEDRIG", "Apache: HTTP-Methode TRACE nicht abgeschaltet", "TraceEnable %s (empfohlen: Off)" % (trace or "nicht gesetzt"))


def mod_sites(raw, full):
    vh = apache_vhosts()
    domains, src = domain_list(vh)
    if not domains:
        add("INFO", "Keine Domains gefunden (weder Virtualmin noch Apache-VirtualHosts)",
            "Domains können unter Einstellungen → Scan-Einstellungen ergänzt werden")
        return
    results = []
    with cf.ThreadPoolExecutor(max_workers=6) as ex:
        for r in ex.map(lambda d: check_domain(d, vh, full), domains):
            results.append(r)
    dns = check_dns(domains)
    check_apache()
    add("INFO", "%s geprüft (Quelle: %s)" % (plural(len(domains), "Domain", "Domains"), src), *domains[:30])
    try:
        with open(os.path.join(raw, "sites.json"), "w", encoding="utf-8") as f:
            json.dump({"domains": results, "dns": dns}, f, indent=1, default=str)
    except OSError:
        pass


# =============================================================================
#  Modul: apps
# =============================================================================
SKIP_DIRS = {"node_modules", "vendor", ".git", "cache", "tmp", "temp", "logs", "uploads", "data",
             "awstats", "cgi-bin", "stats", "Maildir", ".cache", ".trash", "backup", "backups"}


def web_roots(vh):
    roots = set()
    for h in vh.values():
        if h.get("docroot") and os.path.isdir(h["docroot"]):
            roots.add(os.path.realpath(h["docroot"]))
    for pat in ("/home/*/public_html", "/home/*/domains/*/public_html", "/var/www/*"):
        for p in glob.glob(pat):
            if os.path.isdir(p):
                roots.add(os.path.realpath(p))
    for p in os.environ.get("WEB_PATHS", "").split():
        if os.path.isdir(p) and p not in ("/home", "/var/www"):
            roots.add(os.path.realpath(p))
    return sorted(roots)


def url_for(path, vh):
    """Passende https-URL zu einem Dateipfad (über DocumentRoot der VirtualHosts)."""
    best = None
    rp = os.path.realpath(path)
    for name, h in vh.items():
        dr = h.get("docroot")
        if not dr or name.startswith("www.") and name[4:] in vh:
            continue
        dr = os.path.realpath(dr)
        if rp == dr or rp.startswith(dr + os.sep):
            if not best or len(dr) > len(best[1]):
                best = (name, dr, h)
    if not best:
        return None
    name, dr, h = best
    rel = rp[len(dr):].replace(os.sep, "/") or "/"
    return name, h.get("ssl_ip") or h.get("ip") or "127.0.0.1", rel


def find_apps(roots):
    apps = {"wordpress": [], "nextcloud": [], "mautic": [], "roundcube": [], "custom": []}
    seen = set()
    for root in roots:
        known_here = False
        for dirpath, dirs, files in os.walk(root):
            depth = dirpath[len(root):].count(os.sep)
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")] if depth < 3 else []
            fs = set(files)
            if dirpath in seen:
                continue
            if os.path.isfile(os.path.join(dirpath, "wp-includes", "version.php")):
                apps["wordpress"].append(dirpath); seen.add(dirpath); known_here = True; dirs[:] = []
            elif "occ" in fs and "version.php" in fs and os.path.isdir(os.path.join(dirpath, "lib")):
                apps["nextcloud"].append(dirpath); seen.add(dirpath); known_here = True; dirs[:] = []
            elif os.path.isfile(os.path.join(dirpath, "app", "release_metadata.json")) or \
                    os.path.isfile(os.path.join(dirpath, "..", "app", "release_metadata.json")) and os.path.basename(dirpath) == "docroot":
                apps["mautic"].append(dirpath); seen.add(dirpath); known_here = True; dirs[:] = []
            elif os.path.isfile(os.path.join(dirpath, "program", "include", "iniset.php")):
                apps["roundcube"].append(dirpath); seen.add(dirpath); known_here = True; dirs[:] = []
        # eigene Anwendungen: Ordner mit PHP-Dateien außerhalb erkannter Anwendungen
        if not known_here and glob.glob(os.path.join(root, "*.php")):
            apps["custom"].append(root)
        elif known_here:
            for sub in sorted(glob.glob(os.path.join(root, "*", ""))):
                sub = sub.rstrip("/")
                if sub not in seen and not any(sub.startswith(k + os.sep) or k.startswith(sub + os.sep) for k in seen) \
                        and glob.glob(os.path.join(sub, "*.php")):
                    apps["custom"].append(sub)
    return apps


def ver_wordpress(path):
    m = re.search(r"\$wp_version\s*=\s*'([^']+)'", read(os.path.join(path, "wp-includes", "version.php")))
    return m.group(1) if m else None


def plugin_headers(path, kind):
    """Plugins/Themes mit Slug und Version aus den Dateiköpfen."""
    out = []
    if kind == "plugin":
        for d in sorted(glob.glob(os.path.join(path, "wp-content", "plugins", "*", ""))):
            slug = os.path.basename(d.rstrip("/"))
            for php in sorted(glob.glob(os.path.join(d, "*.php")))[:30]:
                head = read(php, 8192)
                if re.search(r"(?im)^[ \t/*#@]*Plugin Name:", head):
                    v = re.search(r"(?im)^[ \t/*#@]*Version:\s*([^\s*]+)", head)
                    out.append((slug, v.group(1) if v else ""))
                    break
    else:
        for css in sorted(glob.glob(os.path.join(path, "wp-content", "themes", "*", "style.css"))):
            head = read(css, 8192)
            v = re.search(r"(?im)^[ \t/*#@]*Version:\s*([^\s*]+)", head)
            out.append((os.path.basename(os.path.dirname(css)), v.group(1) if v else ""))
    return out


def wp_latest(kind, slug):
    if kind == "plugin":
        url = ("https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=%s"
               "&request[fields][sections]=0&request[fields][versions]=0" % slug)
    else:
        url = "https://api.wordpress.org/themes/info/1.2/?action=theme_information&request[slug]=%s" % slug
    d = get_json(url, "wp-%s-%s" % (kind, slug))
    if d is None:
        return None                     # Verzeichnis nicht erreichbar
    return d.get("version") if isinstance(d, dict) and d.get("version") else "unbekannt"


WPSCAN_DAILY = 22          # kostenloser Plan: 25 Abfragen am Tag – etwas Reserve für eigene Abfragen lassen
WPSCAN_SKIPPED = set()
WPSCAN_BUDGET = os.path.join(os.environ.get("STATE_DIR", "/var/lib/ubusec"), "wpscan-budget.json")


def _wpscan_budget():
    day = time.strftime("%Y-%m-%d")
    try:
        b = json.load(open(WPSCAN_BUDGET))
        if b.get("day") == day:
            return b
    except (OSError, ValueError):
        pass
    return {"day": day, "used": 0, "blocked": "", "limit": WPSCAN_DAILY}


def _wpscan_save(b):
    try:
        tmp = WPSCAN_BUDGET + ".tmp"
        with open(tmp, "w") as f:
            json.dump(b, f)
        try:     # die Weboberfläche zeigt den Tagesverbrauch an
            import grp
            os.chown(tmp, -1, grp.getgrnam("ubusec").gr_gid)
            os.chmod(tmp, 0o640)
        except (KeyError, OSError):
            pass
        os.replace(tmp, WPSCAN_BUDGET)
    except OSError:
        pass


def _wpscan_cache(slug):
    return os.path.join(CACHE, "wpscan-%s.json" % re.sub(r"[^a-z0-9_-]", "_", slug))


def _wpscan_age(slug):
    try:
        return time.time() - os.path.getmtime(_wpscan_cache(slug))
    except OSError:
        return None


def wpscan_prefetch(slugs):
    """Vor der WordPress-Prüfung: Plugins bei WPScan abfragen – nie geprüfte zuerst, dann die ältesten.
    Jedes Plugin höchstens einmal am Tag, über alle Scans eines Tages höchstens WPSCAN_DAILY Abfragen.
    So kommen bei vielen Plugins alle reihum dran, auch wenn das Kontingent nicht für alle an einem Tag reicht."""
    tok = os.environ.get("WPSCAN_API_TOKEN", "")
    if not tok or not slugs:
        return
    os.makedirs(CACHE, mode=0o700, exist_ok=True)
    force = os.environ.get("UBUSEC_WPSCAN_FORCE") == "1"
    due = []
    for slug in sorted(set(slugs)):
        age = _wpscan_age(slug)
        if age is None or age >= 86400 or (force and age >= 3600):
            due.append((0 if age is None else 1, -(age or 0), slug))
    b = _wpscan_budget()
    for _, _, slug in sorted(due):
        if b.get("blocked") or b.get("used", 0) >= WPSCAN_DAILY:
            break
        b["used"] = b.get("used", 0) + 1
        cp = _wpscan_cache(slug)
        try:
            req = urllib.request.Request("https://wpscan.com/api/v3/plugins/%s" % slug, headers={
                "User-Agent": UA, "Accept": "application/json", "Authorization": "Token token=%s" % tok})
            with urllib.request.urlopen(req, timeout=15) as r:
                d = json.loads(r.read().decode("utf-8", "replace"))
            with open(cp, "w", encoding="utf-8") as f:
                json.dump(d, f)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                with open(cp, "w", encoding="utf-8") as f:
                    json.dump({}, f)
            elif e.code == 429:
                b["blocked"] = "limit"       # Kontingent bei WPScan erschöpft – heute nicht mehr fragen
            elif e.code in (401, 403):
                b["blocked"] = "token"
            else:
                NET_FAIL.add("wpscan.com")
        except Exception:  # noqa: BLE001
            NET_FAIL.add("wpscan.com")
    _wpscan_save(b)


def wpscan_vulns(slug, version):
    """Bekannte Lücken eines Plugins aus dem gespeicherten WPScan-Ergebnis (höchstens 14 Tage alt)."""
    if not os.environ.get("WPSCAN_API_TOKEN", ""):
        return []
    age = _wpscan_age(slug)
    d = None
    if age is not None and age < 14 * 86400:
        try:
            d = json.load(open(_wpscan_cache(slug), encoding="utf-8"))
        except (OSError, ValueError):
            d = None
    if d is None:
        WPSCAN_SKIPPED.add(slug)
        return []
    if not isinstance(d, dict) or slug not in d:
        return []
    out = []
    for v in (d[slug] or {}).get("vulnerabilities", []) or []:
        fixed = v.get("fixed_in")
        title = v.get("title", "?")
        if fixed:
            if version and vt(version) >= vt(fixed):
                continue
        elif version:
            # Ohne „fixed_in“ steht der betroffene Bereich meist nur im Titel („Plugin <= 3.3.3 - …“).
            # Liegt die installierte Version darüber, ist sie nicht betroffen.
            m = re.search(r"(<=|<)\s*v?(\d+(?:\.\d+)*)", title)
            if m and (vt(version) > vt(m.group(2)) if m.group(1) == "<=" else vt(version) >= vt(m.group(2))):
                continue
        out.append("%s%s" % (title[:110], " (behoben in %s)" % fixed if fixed else " (noch kein Fix)"))
    return out


def check_wordpress(path, vh):
    site = url_for(path, vh)
    label = site[0] + (site[2] if site[2] != "/" else "") if site else path
    try:
        owner = pwd.getpwuid(os.stat(path).st_uid).pw_name
    except (OSError, KeyError):
        owner = "<benutzer>"
    wpcli = shutil_which("wp")
    ver = ver_wordpress(path)
    if ver:
        sc = get_json("https://api.wordpress.org/core/stable-check/1.0/", "wp-stable-check")
        st = sc.get(ver) if isinstance(sc, dict) else None
        if st == "insecure":
            agg("HOCH", "WordPress-Version mit bekannten Sicherheitslücken", "%s – WordPress %s" % (label, ver))
        elif st == "outdated":
            agg("MITTEL", "WordPress nicht aktuell", "%s – WordPress %s" % (label, ver))
    for kind in ("plugin", "theme"):
        for slug, v in plugin_headers(path, kind):
            latest = wp_latest(kind, slug)
            if latest is None:
                continue
            if latest == "unbekannt":
                if kind == "plugin":
                    agg("INFO", "Plugins ohne Eintrag im WordPress-Verzeichnis (Updates selbst prüfen)", "%s – %s" % (label, slug))
                continue
            if v and vt(v) < vt(latest):
                if kind == "plugin":
                    agg("MITTEL", "WordPress-Plugins mit verfügbaren Updates", "%s – %s %s → %s" % (label, slug, v, latest))
                    if wpcli:
                        agg("MITTEL", "WordPress-Plugins mit verfügbaren Updates",
                            "Befehl: sudo -u %s wp plugin update %s --path=%s" % (owner, slug, path))
                else:
                    agg("NIEDRIG", "WordPress-Themes mit verfügbaren Updates", "%s – %s %s → %s" % (label, slug, v, latest))
            if kind == "plugin":
                for t in wpscan_vulns(slug, v):
                    agg("HOCH", "WordPress-Plugins mit bekannten Sicherheitslücken (WPScan)", "%s – %s %s: %s" % (label, slug, v, t))
    cfg = os.path.join(path, "wp-config.php")
    if not os.path.isfile(cfg):
        cfg = os.path.join(os.path.dirname(path), "wp-config.php")
    c = read(cfg)
    if re.search(r"define\(\s*['\"]WP_DEBUG['\"]\s*,\s*true", c, re.I) and \
            not re.search(r"define\(\s*['\"]WP_DEBUG_DISPLAY['\"]\s*,\s*false", c, re.I):
        agg("MITTEL", "WordPress: Debug-Modus zeigt Fehler öffentlich an", label)
    if c and not re.search(r"define\(\s*['\"]DISALLOW_FILE_EDIT['\"]\s*,\s*true", c, re.I):
        agg("NIEDRIG", "WordPress: Datei-Editor im Backend aktiv", label)
        agg("NIEDRIG", "WordPress: Datei-Editor im Backend aktiv",
            "%s: in %s vor der Zeile „/* That's all, stop editing! …“ einfügen: define('DISALLOW_FILE_EDIT', true);" % (label, cfg))
    if c and world_readable(cfg):
        agg("MITTEL", "WordPress: wp-config.php für alle Benutzer des Servers lesbar", cfg)
        agg("MITTEL", "WordPress: wp-config.php für alle Benutzer des Servers lesbar", "Befehl: sudo chmod 640 %s" % cfg)
    up = os.path.join(path, "wp-content", "uploads")
    if os.path.isdir(up) and not re.search(r"(?i)(php_flag\s+engine\s+off|Require all denied|Deny from all|SetHandler\s+none)",
                                         read(os.path.join(up, ".htaccess"))):
        agg("NIEDRIG", "WordPress: PHP-Ausführung im Upload-Ordner nicht gesperrt", label)
        agg("NIEDRIG", "WordPress: PHP-Ausführung im Upload-Ordner nicht gesperrt",
            "Befehl: printf '<FilesMatch \"\\\\.(php|phtml|php[0-9])$\">\\n  Require all denied\\n</FilesMatch>\\n' | sudo -u %s tee -a %s/.htaccess"
            % (owner, up))
    if site:
        dom, ip, rel = site
        base = rel.rstrip("/")
        x = fetch(dom, ip, base + "/xmlrpc.php", "https", "POST",
                  b"<?xml version='1.0'?><methodCall><methodName>system.listMethods</methodName></methodCall>", ctype="text/xml")
        if x and x.status == 200 and b"<methodResponse>" in x.body and b"wp." in x.body:
            agg("NIEDRIG", "WordPress: xmlrpc.php öffentlich aktiv (Angriffsfläche für Passwort-Raten)", label)
            agg("NIEDRIG", "WordPress: xmlrpc.php öffentlich aktiv (Angriffsfläche für Passwort-Raten)",
                "%s: in %s/.htaccess oberhalb von „# BEGIN WordPress“ einfügen: <Files xmlrpc.php> Require all denied </Files>"
                % (label, path))
        u = fetch(dom, ip, base + "/wp-json/wp/v2/users", limit=8192)
        if u and u.status == 200 and u.body.lstrip().startswith(b"[{") and b'"slug"' in u.body:
            agg("NIEDRIG", "WordPress: Benutzernamen öffentlich auslesbar", label + " (über /wp-json/wp/v2/users)")
    return {"path": path, "version": ver}


def check_nextcloud(path, vh):
    site = url_for(path, vh)
    label = site[0] + (site[2] if site[2] != "/" else "") if site else path
    vm = re.search(r"\$OC_VersionString\s*=\s*'([^']+)'", read(os.path.join(path, "version.php")))
    ver = vm.group(1) if vm else None
    if ver:
        e = eol_info("nextcloud", ver, 1)
        if e and e.get("past"):
            agg("HOCH", "Nextcloud-Version erhält keine Sicherheitsupdates mehr", "%s – Nextcloud %s (Support endete %s)" % (label, ver, e["eol"]))
        elif e and e.get("latest") and vt(ver) < vt(e["latest"]):
            agg("MITTEL", "Nextcloud-Wartungsupdate verfügbar", "%s – %s → %s" % (label, ver, e["latest"]))
    cfg = read(os.path.join(path, "config", "config.php"))
    if re.search(r"'debug'\s*=>\s*true", cfg):
        agg("MITTEL", "Nextcloud: Debug-Modus aktiv", label)
    if world_readable(os.path.join(path, "config", "config.php")):
        agg("MITTEL", "Nextcloud: config.php für alle Benutzer des Servers lesbar", os.path.join(path, "config", "config.php"))
    dm = re.search(r"'datadirectory'\s*=>\s*'([^']+)'", cfg)
    if dm and site and os.path.realpath(dm.group(1)).startswith(os.path.realpath(path)):
        rel = os.path.relpath(dm.group(1), path).replace(os.sep, "/")
        x = fetch(site[0], site[1], site[2].rstrip("/") + "/" + rel + "/.ocdata", limit=1024)
        if x and x.status == 200:
            agg("KRITISCH", "Nextcloud: Datenverzeichnis öffentlich erreichbar", label)
    usr = owner(os.path.join(path, "occ"))
    if usr and usr != "root" and shutil_which("php"):
        rc, out, err = run(["php", "occ", "update:check"], timeout=180, user=usr, cwd=path)
        if rc == 0:
            apps = [l.strip() for l in out.splitlines() if re.search(r"Update for .* is available", l)]
            core = [l.strip() for l in out.splitlines() if re.search(r"Nextcloud .* is available", l)]
            for l in core:
                agg("MITTEL", "Nextcloud-Update verfügbar", "%s – %s" % (label, l))
            for l in apps:
                agg("NIEDRIG", "Nextcloud-App-Updates verfügbar", "%s – %s" % (label, l))
        else:
            agg("INFO", "Nextcloud: Update-Prüfung mit occ nicht möglich", "%s – %s" % (label, (err or out).strip()[:150]))
    return {"path": path, "version": ver}


def gh_latest(repo):
    d = get_json("https://api.github.com/repos/%s/releases?per_page=40" % repo, "gh-" + repo.replace("/", "-"))
    if not isinstance(d, list):
        return []
    return [r.get("tag_name", "").lstrip("v") for r in d if not r.get("prerelease") and not r.get("draft")]


def check_mautic(path, vh):
    site = url_for(path, vh)
    label = site[0] if site else path
    meta = None
    for cand in (os.path.join(path, "app", "release_metadata.json"), os.path.join(path, "..", "app", "release_metadata.json")):
        try:
            meta = json.load(open(cand, encoding="utf-8"))
            break
        except (OSError, ValueError):
            continue
    ver = (meta or {}).get("version")
    rel = gh_latest("mautic/mautic")
    if ver and rel:
        latest = max(rel, key=vt)
        same = [r for r in rel if vt(r)[:1] == vt(ver)[:1]]
        if vt(ver)[0] < vt(latest)[0]:
            agg("HOCH", "Mautic-Hauptversion veraltet", "%s – Mautic %s, aktuell %s" % (label, ver, latest))
        elif same and vt(ver) < vt(max(same, key=vt)):
            agg("MITTEL", "Mautic-Update verfügbar", "%s – %s → %s" % (label, ver, max(same, key=vt)))
    if site:
        for d in ("/app/", "/var/logs/", "/var/", "/app/config/"):
            x = fetch(site[0], site[1], site[2].rstrip("/") + d, limit=8192)
            if x and x.status == 200 and re.search(rb"<title>Index of ", x.body):
                agg("HOCH", "Mautic: interne Verzeichnisse öffentlich einsehbar", "https://%s%s" % (site[0], site[2].rstrip("/") + d))
    lp = os.path.join(path, "app", "config", "local.php")
    if os.path.isfile(lp) and world_readable(lp):
        agg("MITTEL", "Mautic: local.php (Zugangsdaten) für alle Benutzer des Servers lesbar", lp)
    return {"path": path, "version": ver}


def check_roundcube(path, vh):
    site = url_for(path, vh)
    label = site[0] + (site[2] if site[2] != "/" else "") if site else path
    m = re.search(r"RCMAIL_VERSION'\s*,\s*'([^']+)'", read(os.path.join(path, "program", "include", "iniset.php")))
    ver = m.group(1) if m else None
    if ver and not path.startswith(("/usr/share/roundcube", "/var/lib/roundcube")):
        rel = [r for r in gh_latest("roundcube/roundcubemail") if re.fullmatch(r"\d+\.\d+\.\d+", r)]
        same = [r for r in rel if vt(r)[:2] == vt(ver)[:2]]
        if same and vt(ver) < vt(max(same, key=vt)):
            agg("HOCH", "Roundcube-Sicherheitsupdate verfügbar", "%s – %s → %s" % (label, ver, max(same, key=vt)))
        elif rel and vt(max(rel, key=vt))[:2] > vt(ver)[:2]:
            e = eol_info("roundcube", ver, 2)
            if e and e.get("past"):
                agg("HOCH", "Roundcube-Version erhält keine Sicherheitsupdates mehr", "%s – %s" % (label, ver))
            else:
                agg("NIEDRIG", "Neuere Roundcube-Versionslinie verfügbar", "%s – %s, aktuell %s" % (label, ver, max(rel, key=vt)))
    if os.path.isdir(os.path.join(path, "installer")):
        reach = False
        if site:
            x = fetch(site[0], site[1], site[2].rstrip("/") + "/installer/", limit=8192)
            reach = bool(x and x.status == 200 and b"Installer" in x.body)
        agg("HOCH" if reach else "MITTEL",
            "Roundcube: Installer öffentlich erreichbar" if reach else "Roundcube: Installer-Verzeichnis noch vorhanden", label)
        agg("HOCH" if reach else "MITTEL",
            "Roundcube: Installer öffentlich erreichbar" if reach else "Roundcube: Installer-Verzeichnis noch vorhanden",
            "Ordner: " + os.path.join(path, "installer"))
    cfg = read(os.path.join(path, "config", "config.inc.php"))
    if re.search(r"\$config\['enable_installer'\]\s*=\s*true", cfg):
        agg("HOCH", "Roundcube: Installer in der Konfiguration aktiviert", label)
    if site:
        x = fetch(site[0], site[1], site[2].rstrip("/") + "/logs/errors.log", limit=2048)
        if x and x.status == 200 and not is_html(x) and x.body:
            agg("HOCH", "Roundcube: Protokolldateien öffentlich abrufbar", label + "/logs/")
    return {"path": path, "version": ver}


def read_bytes(p, limit):
    try:
        with open(p, "rb") as f:
            return f.read(limit)
    except OSError:
        return b""


SENSITIVE = [
    (re.compile(r"\.(sql|sql\.gz|sql\.zip|sql\.bz2|dump)$", re.I), "KRITISCH", "db"),
    (re.compile(r"(^|/)(\.env|id_rsa|id_ed25519)$|\.(pem|key|p12|pfx)$", re.I), "KRITISCH", "secret"),
    (re.compile(r"\.(bak|old|orig|save|swp|backup)$|~$", re.I), "HOCH", "backup"),
    (re.compile(r"\.(zip|tar|tar\.gz|tgz|7z|rar)$", re.I), "HOCH", "archive"),
]
SQLI = re.compile(r"(mysqli_query|mysql_query|->query|->exec|->prepare)\s*\([^;]{0,200}\$_(GET|POST|REQUEST|COOKIE)\s*\[")
XSS = re.compile(r"\b(echo|print)\b[^;]{0,40}\$_(GET|POST|REQUEST|COOKIE)\s*\[")
DBROOT = re.compile(r"(mysqli_connect|new\s+mysqli|new\s+PDO)\s*\([^)]{0,200}['\"]root['\"]|define\(\s*['\"]DB_USER['\"]\s*,\s*['\"]root['\"]", re.I)


def scan_files(root, vh, known, budget):
    """Sensible Dateien im Webverzeichnis; bei eigenen Apps zusätzlich Code-Hinweise."""
    count = 0
    for dirpath, dirs, files in os.walk(root):
        depth = dirpath[len(root):].count(os.sep)
        dirs[:] = [d for d in dirs if d not in {"node_modules", "vendor", "cache", ".cache"}] if depth < 5 else []
        if ".git" in dirs and depth == 0:
            pass  # wird über HTTP-Probe /.git/HEAD gemeldet
        dirs[:] = [d for d in dirs if d != ".git"]
        for fn in files:
            count += 1
            if count > 60000 or time.time() > budget:
                return
            p = os.path.join(dirpath, fn)
            for rx, sev, kind in SENSITIVE:
                if rx.search(fn):
                    # .pem-Dateien sind meist öffentliche Zertifikate (z. B. die CA-Liste cacert.pem in Plugins) –
                    # gefährlich ist nur ein privater Schlüssel darin
                    if kind == "secret" and fn.lower().endswith(".pem") and b"PRIVATE KEY" not in read_bytes(p, 262144):
                        break
                    # Roundcube liefert seine Datenbank-Schemas unter SQL/ mit (per .htaccess gesperrt)
                    if kind == "db" and "/SQL/" in p and os.path.isfile(os.path.join(p.split("/SQL/")[0], "program/include/iniset.php")):
                        break
                    if kind == "archive":
                        try:
                            if os.path.getsize(p) < 512 * 1024:
                                break
                        except OSError:
                            break
                    site = url_for(p, vh)
                    if site and site[2] in PROBE_PATHS:
                        break            # meldet bereits das Modul „Websites & Domains“
                    reach = False
                    if site:
                        x = fetch(site[0], site[1], site[2], method="GET", limit=256)
                        reach = bool(x and x.status == 200 and not is_html(x))
                    if reach and kind == "archive" and re.search(r"/wp-content/(plugins|themes)/[^/]+/|/(apps|custom_apps|apps-extra)/[^/]+/", p):
                        # Teil eines Plugins/einer App (z. B. mitgelieferte Programme) – keine Sicherung mit Zugangsdaten
                        agg("NIEDRIG", "Archive in Plugin-/App-Ordnern öffentlich abrufbar (meist mitgeliefert)",
                            "https://%s%s" % (site[0], site[2]))
                        if "/wp-content/" in p:
                            agg("NIEDRIG", "Archive in Plugin-/App-Ordnern öffentlich abrufbar (meist mitgeliefert)", "Datei: " + p)
                    elif reach:
                        agg(sev, {"db": "Datenbank-Dumps öffentlich abrufbar", "secret": "Schlüssel- oder Zugangsdateien öffentlich abrufbar",
                                  "backup": "Sicherungskopien öffentlich abrufbar (Quellcode, Zugangsdaten)",
                                  "archive": "Archive/Backups im Webverzeichnis öffentlich abrufbar"}[kind],
                            "https://%s%s" % (site[0], site[2]))
                    else:
                        agg("NIEDRIG", "Sensible Dateien im Webverzeichnis (gesperrt, aber dort fehl am Platz)", p)
                    break
            custom = not any(p == k or p.startswith(k + os.sep) for k in known)
            if custom and fn.endswith(".php"):
                try:
                    if os.path.getsize(p) > 512 * 1024:
                        continue
                except OSError:
                    continue
                txt = read(p)
                if "phpinfo(" in txt and len(txt) < 400:
                    site = url_for(p, vh)
                    agg("MITTEL", "phpinfo()-Dateien im Webverzeichnis", "https://%s%s" % (site[0], site[2]) if site else p)
                if DBROOT.search(txt):
                    agg("MITTEL", "PHP-Anwendung verbindet sich als MySQL-root", p)
                for i, line in enumerate(txt.splitlines(), 1):
                    if SQLI.search(line):
                        agg("MITTEL", "Möglicher SQL-Injection-Code: Benutzereingaben direkt im SQL-Befehl", "%s:%d" % (p, i))
                    elif XSS.search(line) and "htmlspecialchars" not in line and "htmlentities" not in line \
                            and "intval" not in line and "(int)" not in line:
                        agg("NIEDRIG", "Ungefilterte Ausgabe von Benutzereingaben (mögliches XSS)", "%s:%d" % (p, i))


def check_php():
    versions = sorted({os.path.basename(p)[3:] for p in glob.glob("/usr/bin/php[0-9].[0-9]*") if re.fullmatch(r"php\d+\.\d+", os.path.basename(p))}, key=vt)
    found = []
    for v in versions:
        found.append(v)
        ub = pkg_from_ubuntu("php%s-common" % v)
        if ub is False:
            e = eol_info("php", v, 2)
            if e and e.get("past"):
                active = run(["systemctl", "is-active", "php%s-fpm" % v], timeout=10)[1].strip() == "active"
                agg("HOCH" if active else "MITTEL", "PHP-Version ohne Sicherheitsupdates installiert",
                    "PHP %s (Support endete %s%s)" % (v, e["eol"], ", FPM-Dienst läuft" if active else ""))
    inis = glob.glob("/etc/php/*/fpm/php.ini") + glob.glob("/etc/php/*/cgi/php.ini") + glob.glob("/etc/php/*/apache2/php.ini") \
        + glob.glob("/home/*/etc/php*/php.ini") + glob.glob("/home/*/domains/*/etc/php*/php.ini")
    # Welche PHP-Versionen sind wirklich installiert? (CLI, CGI oder FPM)
    have = set(versions)
    for pat in ("/usr/bin/php-cgi[0-9]*", "/usr/sbin/php-fpm[0-9]*", "/usr/lib/cgi-bin/php[0-9]*"):
        for b in glob.glob(pat):
            m = re.search(r"(\d+\.\d+)$", b)
            if m:
                have.add(m.group(1))
    stale = []
    for ini in inis:
        m = re.search(r"/etc/php/(\d+\.\d+)/|/etc/php(\d+\.\d+)/php\.ini$", ini)
        v = m and (m.group(1) or m.group(2))
        if v and have and v not in have:
            # Überbleibsel einer entfernten PHP-Version (Virtualmin lässt etc/phpX.Y je Domain stehen,
            # apt remove lässt /etc/php/X.Y stehen) – wird nicht benutzt, Einstellungen darin sind egal
            stale.append((v, os.path.dirname(ini) if "/etc/php/" not in ini else "/etc/php/" + v))
            continue
        vals = {}
        for line in read(ini).splitlines():
            m = re.match(r"^\s*([A-Za-z_.]+)\s*=\s*([^;]*)", line)
            if m:
                vals[m.group(1).lower()] = m.group(2).strip().strip('"').lower()
        on = lambda k: vals.get(k) in ("on", "1", "true", "yes", "stdout", "stderr")  # noqa: E731
        if on("display_errors"):
            agg("MITTEL", "PHP: display_errors aktiv (Fehlermeldungen öffentlich sichtbar)", ini)
        if on("allow_url_include"):
            agg("HOCH", "PHP: allow_url_include aktiv", ini)
        if on("expose_php"):
            agg("NIEDRIG", "PHP: expose_php aktiv (Version im Header)", ini)
        if "session.cookie_httponly" in vals and not on("session.cookie_httponly"):
            agg("NIEDRIG", "PHP: Session-Cookies ohne HttpOnly", ini)
    if stale:
        agg("NIEDRIG", "PHP: Einstellungen für nicht mehr installierte PHP-Versionen (Überbleibsel)",
            "Installiert: PHP " + ", ".join(sorted(have, key=vt)))
        for v, d in sorted(set(stale), key=lambda x: x[1]):
            agg("NIEDRIG", "PHP: Einstellungen für nicht mehr installierte PHP-Versionen (Überbleibsel)",
                "Ordner: %s (PHP %s)" % (d, v))
    return found


def check_mysql():
    if not shutil_which("mysql"):
        return
    base = ["mysql", "-N", "-B"]
    rc, out, _ = run(base + ["-e", "SELECT user,host,IFNULL(plugin,''),IFNULL(authentication_string,'') FROM mysql.user"], timeout=30)
    if rc != 0 and os.path.exists("/etc/mysql/debian.cnf"):
        base = ["mysql", "--defaults-file=/etc/mysql/debian.cnf", "-N", "-B"]
        rc, out, _ = run(base + ["-e", "SELECT user,host,IFNULL(plugin,''),IFNULL(authentication_string,'') FROM mysql.user"], timeout=30)
    if rc != 0:
        add("INFO", "MySQL/MariaDB-Prüfung übersprungen (kein Zugriff als root über den Unix-Socket)")
        return
    local = ("localhost", "127.0.0.1", "::1")
    for line in out.splitlines():
        p = line.split("\t")
        if len(p) < 4:
            continue
        user, host, plugin, auth = p[:4]
        if user == "":
            agg("HOCH", "MySQL/MariaDB: anonyme Benutzer vorhanden", "''@'%s'" % host)
            continue
        if user == "root" and host not in local:
            agg("HOCH", "MySQL/MariaDB: root darf sich von außen anmelden", "root@'%s'" % host)
        elif host == "%":
            agg("MITTEL", "MySQL/MariaDB: Benutzer dürfen sich von beliebigen Rechnern anmelden (%)", "%s@'%%'" % user)
        if auth == "" and plugin not in ("unix_socket", "auth_socket", "invalid") and user not in ("mariadb.sys", "mysql.sys", "mysql.session", "mysql.infoschema", "PUBLIC"):
            agg("HOCH", "MySQL/MariaDB: Benutzer ohne Passwort", "%s@'%s'" % (user, host))
    rc, out, _ = run(base + ["-e", "SHOW DATABASES LIKE 'test'"], timeout=20)
    if rc == 0 and out.strip() == "test":
        add("NIEDRIG", "MySQL/MariaDB: Testdatenbank 'test' vorhanden")
    rc, out, _ = run(base + ["-e", "SELECT VERSION()"], timeout=20)
    if rc == 0 and out.strip():
        v = out.strip()
        prod = "mariadb" if "mariadb" in v.lower() else "mysql"
        pkg = "mariadb-server" if prod == "mariadb" else "mysql-server"
        if pkg_from_ubuntu(pkg) is False:
            e = eol_info(prod, v, 2)
            if e and e.get("past"):
                add("HOCH", "%s-Version erhält keine Sicherheitsupdates mehr" % ("MariaDB" if prod == "mariadb" else "MySQL"),
                    "%s (Support endete %s)" % (v.split("-")[0], e["eol"]))


def mod_apps(raw, full):
    vh = apache_vhosts()
    roots = web_roots(vh)
    apps = find_apps(roots)
    result = {k: [] for k in apps}
    wpscan_prefetch([slug for p in apps["wordpress"] for slug, _ in plugin_headers(p, "plugin")])
    for p in apps["wordpress"]:
        result["wordpress"].append(check_wordpress(p, vh))
    for p in apps["nextcloud"]:
        result["nextcloud"].append(check_nextcloud(p, vh))
    for p in apps["mautic"]:
        result["mautic"].append(check_mautic(p, vh))
    for p in apps["roundcube"]:
        result["roundcube"].append(check_roundcube(p, vh))
    # Roundcube aus dem Ubuntu-Paket wird über apt aktualisiert
    budget = time.time() + (1800 if full else 600)
    known = set(apps["wordpress"] + apps["nextcloud"] + apps["mautic"] + apps["roundcube"])
    for r in roots:
        scan_files(r, vh, known, budget=budget)
    php = check_php()
    check_mysql()
    names = {"wordpress": "WordPress", "nextcloud": "Nextcloud", "mautic": "Mautic", "roundcube": "Roundcube", "custom": "eigene PHP-Anwendungen"}
    summary = ["%s: %d" % (names[k], len(v)) for k, v in apps.items() if v]
    det = ["%s – %s%s" % (names[k], p, " (%s)" % i.get("version") if i.get("version") else "")
           for k in ("wordpress", "nextcloud", "mautic", "roundcube") for p, i in zip(apps[k], result[k])]
    det += ["eigene Anwendung – %s" % p for p in apps["custom"]]
    if php:
        det.append("PHP-Versionen: " + ", ".join(php))
    add("INFO", "Gefundene Webanwendungen: " + (", ".join(summary) if summary else "keine"), *det[:40])
    try:
        with open(os.path.join(raw, "apps.json"), "w", encoding="utf-8") as f:
            json.dump({"roots": roots, "apps": apps, "details": result}, f, indent=1)
    except OSError:
        pass


# =============================================================================
#  Modul: tools – Aktualität der Prüfwerkzeuge und von ubusec selbst
# =============================================================================
TOOLS = [
    # Anzeige, Pakete, Aufgabe, Programm, Pflicht
    ("ClamAV", ["clamav", "clamav-freshclam"], "Virenscan", "clamscan", True),
    ("rkhunter", ["rkhunter"], "Rootkit-Suche", "rkhunter", True),
    ("chkrootkit", ["chkrootkit"], "Rootkit-Suche", "chkrootkit", True),
    ("Lynis", ["lynis"], "Härtungsaudit", "lynis", True),
    ("OpenSCAP", ["openscap-scanner", "libopenscap8"], "CVE-Prüfung", "oscap", True),
    ("unhide", ["unhide"], "Versteckte Prozesse und Ports", "unhide-linux", True),
    ("needrestart", ["needrestart"], "Dienste mit alten Bibliotheken", "needrestart", True),
    ("dig", ["bind9-dnsutils"], "DNS- und E-Mail-Prüfung", "dig", True),
    ("testssl.sh", ["testssl.sh"], "Gründliche TLS-Prüfung", "testssl.sh", False),
    ("AIDE", ["aide"], "Dateiintegrität", "aide", False),
    ("Linux Malware Detect", [], "Web-Malware", "maldet", False),
    ("Flask / Waitress", ["python3-flask", "python3-waitress"], "Weboberfläche", None, False),
]


def apt_versions(pkgs):
    rc, out, _ = run(["apt-cache", "policy"] + pkgs, timeout=60)
    res, cur = {}, None
    for line in out.splitlines():
        m = re.match(r"^(\S+):$", line)
        if m:
            cur = m.group(1); res[cur] = {}
        elif cur and ":" in line and line.startswith("  ") and not line.startswith("    "):
            k, v = line.strip().split(":", 1)
            res[cur][k.strip()] = v.strip()
    return res


def newer(a, b):
    """True, wenn Debian-Version a neuer ist als b."""
    return run(["dpkg", "--compare-versions", a, "gt", b], timeout=10)[0] == 0


def age_days(paths):
    ts = [os.path.getmtime(p) for p in paths if os.path.exists(p)]
    return round((time.time() - max(ts)) / 86400, 1) if ts else None


def mod_tools(raw, full):
    allpkgs = sorted({p for t in TOOLS for p in t[1]})
    av = apt_versions(allpkgs)
    rows, upd = [], []
    for name, pkgs, task, binary, required in TOOLS:
        inst = [(p, av.get(p, {})) for p in pkgs if av.get(p, {}).get("Installed", "(none)") not in ("(none)", "")]
        version = inst[0][1]["Installed"] if inst else ""
        present = bool(inst) or (binary and shutil_which(binary))
        cand = ""
        for p, info in inst:
            c = info.get("Candidate", "")
            if c and c != "(none)" and newer(c, info["Installed"]):
                upd.append("%s %s → %s" % (p, info["Installed"], c)); cand = c
        if not version and binary and shutil_which(binary):
            version = "(nicht über apt)"
        rows.append({"name": name, "task": task, "packages": [p for p, _ in inst] or pkgs[:1], "installed": version,
                     "present": bool(present), "required": required, "update": cand, "data": "", "data_age": None,
                     "state": "fehlt" if not present else ("update" if cand else "ok"), "note": ""})
    row = {r["name"]: r for r in rows}
    if upd:
        add("NIEDRIG", "Updates für Prüfwerkzeuge verfügbar", *upd,
            "Einspielen: Weboberfläche → Werkzeuge → „Werkzeuge aktualisieren“ oder sudo ubusec --update-tools")

    # --- Signaturen und Prüfdaten ------------------------------------------------
    r = row["ClamAV"]
    if r["present"]:
        a = age_days(glob.glob("/var/lib/clamav/daily.c[lv]d") + glob.glob("/var/lib/clamav/main.c[lv]d"))
        r["data"], r["data_age"] = "Virensignaturen", a
        fresh_active = run(["systemctl", "is-active", "clamav-freshclam"], timeout=10)[1].strip() == "active"
        r["note"] = "Signaturen werden automatisch aktualisiert" if fresh_active else "Signatur-Dienst clamav-freshclam läuft nicht"
        if a is None or a > 3:
            r["state"] = "veraltet"
            add("MITTEL", "ClamAV-Virensignaturen veraltet" if a else "ClamAV-Virensignaturen fehlen",
                "Stand: vor %s Tagen" % a if a else "keine Signaturdateien in /var/lib/clamav",
                "Beheben: sudo systemctl enable --now clamav-freshclam")
        elif not fresh_active:
            add("NIEDRIG", "ClamAV-Signaturdienst (clamav-freshclam) läuft nicht",
                "Signaturen werden nur bei Scans aktualisiert", "Beheben: sudo systemctl enable --now clamav-freshclam")
    r = row["rkhunter"]
    if r["present"]:
        r["data"], r["data_age"] = "Rootkit-Datenbank", age_days(glob.glob("/var/lib/rkhunter/db/*.dat"))
        r["note"] = "Programm wird seit Jahren kaum weiterentwickelt; chkrootkit und eigene Prüfungen ergänzen es"
    r = row["OpenSCAP"]
    oval = glob.glob(os.path.join(os.environ.get("STATE_DIR", "/var/lib/ubusec"), "oval", "*.xml"))
    if r["present"]:
        a = age_days(oval)
        r["data"], r["data_age"] = "CVE-Daten von Canonical", a
        # läuft im selben Scan noch der CVE-Bereich, lädt er die Daten gleich neu – dann nicht als veraltet melden
        if a is not None and a > 2 and os.environ.get("UBUSEC_CVE_FOLLOWS") != "1":
            r["state"] = "veraltet"
            add("NIEDRIG", "CVE-Daten (Ubuntu OVAL) älter als 2 Tage",
                "Stand: vor %s Tagen – erreicht der Server security-metadata.canonical.com?" % a)

    # --- optionale Werkzeuge ---------------------------------------------------------
    sd = os.environ.get("STATE_DIR", "/var/lib/ubusec")
    r = row["AIDE"]
    r["benefit"] = ("Überwacht alle Systemdateien – auch Konfigurationen und Programme, die zu keinem Paket gehören – und "
                    "meldet jede Änderung seit der letzten Freigabe. Ergänzt die Paketprüfung (dpkg), die nur Paketdateien kennt.")
    r["cost"] = "Datenbank anlegen 10–60 Minuten einmalig; prüft beim Vollscan; nach Updates „Baseline übernehmen“."
    if r["present"]:
        db = "/var/lib/aide/aide.db"
        try:
            pid = int(open(os.path.join(sd, "aide-init.running")).read().strip())
            os.kill(pid, 0)
            r["aide_init"] = True
        except (OSError, ValueError):
            r["aide_init"] = False
        r["aide_db"] = os.path.isfile(db)
        r["data"], r["data_age"] = "Datenbank (Baseline)", age_days([db]) if os.path.isfile(db) else None
        if r["aide_init"]:
            r["note"] = "Datenbank wird gerade angelegt …"
        elif not r["aide_db"]:
            r["state"], r["note"] = "veraltet", "noch keine Datenbank – „AIDE einrichten“"
    r = row["Linux Malware Detect"]
    r["benefit"] = ("Eigene Signaturen für Web-Malware (PHP-Webshells, eingeschleustes JavaScript, Spam-Skripte), die ClamAV oft "
                    "nicht kennt. Nutzt den laufenden ClamAV-Dienst als Suchmaschine mit.")
    r["cost"] = "Wird von rfxn.com geladen (nicht aus den Ubuntu-Paketquellen) und aktualisiert sich selbst; prüft die Webordner."
    if shutil_which("maldet") or os.path.exists("/usr/local/maldetect/maldet"):
        r["present"], r["state"] = True, "ok"
        rc, out, _ = run(["/usr/local/maldetect/maldet"], timeout=20)
        m = re.search(r"v(\d+[\d.]*)", out)
        r["installed"] = m.group(1) if m else "installiert"
        r["data"], r["data_age"] = "Signaturen", age_days(glob.glob("/usr/local/maldetect/sigs/*"))

    # --- Lynis: Ubuntu-Paket oft weit hinter dem Hersteller ------------------------
    r = row["Lynis"]
    rel = get_json("https://api.github.com/repos/CISOfy/lynis/releases/latest", "gh-lynis-latest", 43200)
    latest = (rel or {}).get("tag_name", "").lstrip("v") if isinstance(rel, dict) else ""
    repo = any(os.path.exists(f) for f in ("/etc/apt/sources.list.d/cisofy-lynis.list", "/etc/apt/sources.list.d/cisofy-lynis.sources"))
    r["upstream"], r["upstream_repo"] = latest, repo
    if r["present"] and latest and r["installed"] and vt(r["installed"].split("-")[0]) < vt(latest):
        r["state"] = "veraltet"
        r["note"] = "Hersteller-Version %s verfügbar" % latest
        add("NIEDRIG", "Lynis veraltet – neuere Prüfregeln beim Hersteller verfügbar",
            "Installiert: %s, aktuell: %s" % (r["installed"], latest),
            "Beheben: Weboberfläche → Werkzeuge → „Lynis-Paketquelle des Herstellers einrichten“ oder sudo ubusec --lynis-upstream")

    # --- ubusec selbst ---------------------------------------------------------------
    me = {"installed": os.environ.get("UBUSEC_VERSION", ""), "repo": os.environ.get("UBUSEC_REPO", ""),
          "latest": "", "notes": "", "url": "", "checked": int(time.time()), "check": os.environ.get("UPDATE_CHECK", "1") == "1"}
    if me["check"] and me["repo"]:
        # „Jetzt prüfen“ fragt sofort nach; ein Cache-Stand älter als die installierte Version ist sicher veraltet
        force = os.environ.get("UBUSEC_FORCE_CHECK") == "1"
        rel = get_json("https://api.github.com/repos/%s/releases/latest" % me["repo"], "gh-ubusec-latest", 0 if force else 21600)
        if isinstance(rel, dict) and rel.get("tag_name") and vt(rel["tag_name"].lstrip("v")) < vt(me["installed"]):
            rel = get_json("https://api.github.com/repos/%s/releases/latest" % me["repo"], "gh-ubusec-latest", 0) or rel
        if isinstance(rel, dict) and rel.get("tag_name"):
            me.update(latest=rel["tag_name"].lstrip("v"), notes=(rel.get("body") or "")[:6000], url=rel.get("html_url", ""))
            if vt(me["latest"]) > vt(me["installed"]):
                add("NIEDRIG", "Neue ubusec-Version %s verfügbar" % me["latest"],
                    "Installiert: %s" % me["installed"], "Einspielen: sudo ubusec --update", me["url"])
    out = os.environ.get("TOOLS_JSON")
    if out:
        try:
            with open(out + ".tmp", "w", encoding="utf-8") as f:
                json.dump({"tools": rows, "ubusec": me, "updated": int(time.time())}, f, ensure_ascii=False, indent=1)
            os.replace(out + ".tmp", out)
        except OSError:
            pass


def nc_datadirs():
    """Datenordner aller gefundenen Nextcloud-Installationen (für Ausnahmen beim Virenscan)."""
    vh = apache_vhosts()
    out = set()
    for p in find_apps(web_roots(vh))["nextcloud"]:
        m = re.search(r"'datadirectory'\s*=>\s*'([^']+)'", read(os.path.join(p, "config", "config.php")))
        d = m.group(1) if m else os.path.join(p, "data")
        if os.path.isdir(d):
            out.add(os.path.realpath(d))
    for d in sorted(out):
        print(d)



# ======================================================================= Mail ===
# Prüft den Mailserver (Postfix, Dovecot, Spamfilter, Sperrlisten, Ruf des Servers). Nur lesend.
SPAMHAUS_BLOCKED = {"127.255.255.252", "127.255.255.254", "127.255.255.255"}


def postconf_all():
    rc, out, _ = run(["postconf"], timeout=30)
    conf = {}
    for l in out.splitlines():
        k, _, v = l.partition(" = ")
        conf[k.strip()] = v.strip()
    return conf if rc == 0 else None


def svc_active(*names):
    for n in names:
        if run(["systemctl", "is-active", "--quiet", n], timeout=10)[0] == 0:
            return n
    return ""


def restr(conf, key):
    return [x.strip() for x in re.split(r"[,\s]+", conf.get(key, "")) if x.strip()]


def public_ips():
    rc, out, _ = run(["hostname", "-I"], timeout=10)
    ips = []
    for ip in out.split():
        if ":" in ip:
            if ip.lower().startswith(("fe80", "fd", "fc", "::1")):
                continue
        elif re.match(r"^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)", ip):
            continue
        ips.append(ip)
    return ips


def dnsbl_lookup(ip, zone):
    """Einträge einer Sperrliste für eine IPv4-Adresse (leere Liste = nicht gelistet)."""
    rev = ".".join(reversed(ip.split(".")))
    return dig("%s.%s" % (rev, zone), "A")


def cert_days(path):
    rc, out, _ = run(["openssl", "x509", "-noout", "-enddate", "-in", path], timeout=10)
    m = re.search(r"notAfter=(.+)", out)
    if rc != 0 or not m:
        return None
    try:
        end = datetime.datetime.strptime(m.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
        return (end - datetime.datetime.utcnow()).days
    except ValueError:
        return None


_MAILDOM = []


def mail_domains():
    if not _MAILDOM:
        _MAILDOM.append(_mail_domains())
    return _MAILDOM[0]


def _mail_domains():
    """(Domains mit Mail, davon mit Spamfilter) laut Virtualmin – oder (None, None)."""
    if not shutil_which("virtualmin"):
        return None, None
    def names(*args):
        rc, out, _ = run(["virtualmin", "list-domains", "--name-only"] + list(args), timeout=90)
        return [l.strip().lower() for l in out.splitlines() if l.strip()] if rc == 0 else None
    return names("--with-feature", "mail"), names("--with-feature", "spam")


def check_open_relay(conf):
    rel = restr(conf, "smtpd_relay_restrictions")
    rcpt = restr(conf, "smtpd_recipient_restrictions")
    guard = {"reject_unauth_destination", "defer_unauth_destination"}

    def guarded(lst):
        for x in lst:
            if x in guard:
                return True
            if x in ("permit", "permit_auth_destination") or (x.startswith("permit") and x not in (
                    "permit_mynetworks", "permit_sasl_authenticated", "permit_tls_clientcerts", "permit_tls_all_clientcerts")):
                return False
        return False
    if not (guarded(rel) or guarded(rcpt)):
        add("KRITISCH", "Server könnte als offenes Relay missbraucht werden",
            "Weder smtpd_relay_restrictions noch smtpd_recipient_restrictions enthalten reject_unauth_destination",
            "smtpd_relay_restrictions = %s" % (conf.get("smtpd_relay_restrictions") or "(leer)"))
    nets = conf.get("mynetworks", "")
    wide = []
    for n in re.split(r"[,\s]+", nets):
        try:
            net = ipaddress.ip_network(n.strip("[]").replace("]/", "/"), strict=False)
        except ValueError:
            continue
        if net.prefixlen == 0 or (net.is_global and net.prefixlen < (24 if net.version == 4 else 56)):
            wide.append(n)
    if wide:
        add("HOCH", "mynetworks erlaubt sehr großen Netzen das Versenden ohne Anmeldung",
            "mynetworks = %s" % nets, "Üblich: 127.0.0.0/8 [::1]/128 (nur der Server selbst)")


def check_tls(conf):
    lvl = conf.get("smtpd_tls_security_level") or ("may" if conf.get("smtpd_use_tls") == "yes" else "")
    if lvl not in ("may", "encrypt"):
        add("MITTEL", "Empfang ohne Verschlüsselung (STARTTLS nicht angeboten)",
            "smtpd_tls_security_level = %s" % (lvl or "(nicht gesetzt)"))
    if conf.get("smtp_tls_security_level", "") not in ("may", "encrypt", "dane", "verify", "secure"):
        add("NIEDRIG", "Versand an andere Server unverschlüsselt (smtp_tls_security_level)",
            "smtp_tls_security_level = %s" % (conf.get("smtp_tls_security_level") or "(nicht gesetzt)"))
    if conf.get("smtpd_tls_auth_only", "no") != "yes":
        add("MITTEL", "Anmeldung (SMTP-AUTH) auch ohne Verschlüsselung erlaubt",
            "smtpd_tls_auth_only = %s" % conf.get("smtpd_tls_auth_only", "no"))
    cert = conf.get("smtpd_tls_cert_file") or ""
    if not cert:
        chain = conf.get("smtpd_tls_chain_files", "")
        cert = re.split(r"[,\s]+", chain)[-1] if chain else ""
    if cert and os.path.isfile(cert):
        d = cert_days(cert)
        if d is not None and d < 0:
            add("HOCH", "TLS-Zertifikat von Postfix ist abgelaufen", "%s (seit %d Tagen)" % (cert, -d))
        elif d is not None and d < 14:
            add("MITTEL", "TLS-Zertifikat von Postfix läuft bald ab", "%s (noch %d Tage)" % (cert, d))
        rc, out, _ = run(["openssl", "x509", "-noout", "-ext", "subjectAltName", "-subject", "-in", cert], timeout=10)
        host = conf.get("myhostname", "")
        names = set(re.findall(r"DNS:([^,\s]+)", out)) | set(re.findall(r"CN\s*=\s*([^,/\s]+)", out))
        if host and names and not any(n == host or (n.startswith("*.") and host.endswith(n[1:])) for n in names):
            add("NIEDRIG", "TLS-Zertifikat von Postfix passt nicht zum Servernamen",
                "myhostname = %s" % host, "Zertifikat gilt für: %s" % ", ".join(sorted(names)[:6]))
    if shutil_which("doveconf"):
        ssl_ = run(["doveconf", "-h", "ssl"], timeout=15)[1].strip()
        plain = run(["doveconf", "-h", "auth_allow_cleartext"], timeout=15)
        if plain[0] == 0 and plain[1].strip():
            clear_ok = plain[1].strip() == "yes"
        else:
            clear_ok = run(["doveconf", "-h", "disable_plaintext_auth"], timeout=15)[1].strip() == "no"
        if ssl_ == "no":
            add("HOCH", "Dovecot (IMAP/POP3) ohne Verschlüsselung", "ssl = no")
        elif clear_ok and ssl_ != "required":
            add("MITTEL", "Dovecot erlaubt Passwörter ohne Verschlüsselung",
                "auth_allow_cleartext = yes bzw. disable_plaintext_auth = no")


def check_spam(conf):
    filt = []
    if svc_active("spamd", "spamassassin"):
        filt.append("SpamAssassin")
    if svc_active("rspamd"):
        filt.append("Rspamd")
    if svc_active("amavis", "amavisd-new"):
        filt.append("Amavis")
    maild, spamd = mail_domains()
    if maild is not None:
        missing = sorted(set(maild) - set(spamd or []))
        if not filt and maild:
            add("MITTEL", "Kein Spamfilter aktiv", "Domains mit Mail: %s" % ", ".join(maild[:10]))
        elif missing:
            add("MITTEL", "Spamfilter nicht für alle Domains mit Postfächern eingeschaltet",
                *["%s – ohne Spamfilter" % d for d in missing[:15]])
    elif not filt:
        add("MITTEL", "Kein Spamfilter gefunden (SpamAssassin, Rspamd oder Amavis)")
    # Greylisting
    rcpt = restr(conf, "smtpd_recipient_restrictions")
    pol = [x for i, x in enumerate(rcpt) if x.startswith("inet:") and i and rcpt[i - 1] == "check_policy_service"]
    grey = svc_active("postgrey")
    if grey and not pol:
        port = re.search(r"--inet=(?:[\d.]+:)?(\d+)", read("/etc/default/postgrey") or "")
        add("NIEDRIG", "Greylisting (postgrey) läuft, ist aber nicht in Postfix eingebunden",
            "In smtpd_recipient_restrictions fehlt: check_policy_service inet:127.0.0.1:%s" % (port.group(1) if port else "10023"),
            "Virtualmin: Email Settings → Greylisting einschalten")
    elif not grey and not pol and not svc_active("rspamd"):
        add("INFO", "Kein Greylisting – fängt einen großen Teil des Massen-Spams ab",
            "Virtualmin: Email Settings → Greylisting; sonst: apt install postgrey")


def check_dnsbl(conf):
    rcpt = conf.get("smtpd_recipient_restrictions", "") + " " + conf.get("smtpd_client_restrictions", "")
    rbls = re.findall(r"reject_rbl_client\s+(\S+)", rcpt)
    ps = conf.get("postscreen_dnsbl_sites", "")
    if not rbls and not ps:
        add("NIEDRIG", "Keine Sperrliste (DNSBL) – bekannte Spam-Server werden nicht abgewiesen",
            "Empfehlung: reject_rbl_client zen.spamhaus.org=127.0.0.[2..11] in smtpd_recipient_restrictions",
            "Vorher prüfen, ob Spamhaus antwortet: dig +short 2.0.0.127.zen.spamhaus.org")
    probe = dig("2.0.0.127.zen.spamhaus.org", "A")
    blocked = bool(set(probe) & SPAMHAUS_BLOCKED)
    for r in rbls:
        if "=" not in r and not (blocked and "spamhaus" in r.lower()):
            add("MITTEL", "Sperrliste ohne Ergebnisfilter – Fehlerantworten würden als Treffer zählen",
                "reject_rbl_client %s" % r, "Besser: reject_rbl_client %s=127.0.0.[2..11]" % r)
    uses_sh = "spamhaus" in (rcpt + ps).lower()
    unfiltered = [r for r in rbls if "spamhaus" in r.lower() and "=" not in r]
    if blocked and unfiltered:
        add("KRITISCH", "Spamhaus antwortet mit Fehlercode und die Sperrliste hat keinen Filter – eingehende Mails werden abgelehnt",
            "dig 2.0.0.127.zen.spamhaus.org → %s" % ", ".join(probe),
            "Sofort: =127.0.0.[2..11] an reject_rbl_client %s anhängen oder die Zeile entfernen" % unfiltered[0])
    elif uses_sh and blocked:
        add("HOCH", "Spamhaus beantwortet keine Abfragen dieses Servers – Sperrliste wirkungslos",
            "dig 2.0.0.127.zen.spamhaus.org → %s (Abfrage über öffentlichen DNS-Resolver)" % ", ".join(probe),
            "Lösung: eigener Resolver (BIND/Unbound) für den Server, siehe Hinweis")
    return not blocked and bool(probe)


def check_reputation(conf, sh_ok):
    host = conf.get("myhostname", "")
    for ip in public_ips():
        if ":" in ip:
            continue
        ptr = [p.rstrip(".") for p in dig(".".join(reversed(ip.split("."))) + ".in-addr.arpa", "PTR")]
        if not ptr:
            add("MITTEL", "Kein Reverse-DNS-Eintrag (PTR) für die Server-IP – Mails landen oft im Spam",
                "%s hat keinen PTR-Eintrag" % ip, "Beim Server-Anbieter im Kundenbereich auf %s setzen" % (host or "den Servernamen"))
        else:
            fwd = dig(ptr[0], "A")
            if ip not in fwd:
                add("NIEDRIG", "Reverse-DNS passt nicht in beide Richtungen (PTR ↔ A)",
                    "%s → %s → %s" % (ip, ptr[0], ", ".join(fwd) or "keine Adresse"))
            elif host and ptr[0].lower() != host.lower():
                add("NIEDRIG", "Reverse-DNS und Servername von Postfix unterscheiden sich",
                    "PTR %s = %s, myhostname = %s" % (ip, ptr[0], host))
        listed = []
        if sh_ok:
            r = [x for x in dnsbl_lookup(ip, "zen.spamhaus.org") if x.startswith("127.0.0.")]
            if r:
                listed.append("Spamhaus ZEN (%s)" % ", ".join(r))
        for zone, name in (("bl.spamcop.net", "SpamCop"), ("psbl.surriel.com", "PSBL")):
            r = [x for x in dnsbl_lookup(ip, zone) if x.startswith("127.0.0.")]
            if r:
                listed.append(name)
        if listed:
            add("HOCH", "Server-IP steht auf Sperrlisten – andere Server lehnen Mails ab",
                "%s: %s" % (ip, ", ".join(listed)),
                "Ursache suchen (Warteschlange, gekaperte Postfächer, Kontaktformulare), dann bei der Liste austragen lassen")


def check_queue():
    rc, out, _ = run(["postqueue", "-j"], timeout=60)
    if rc != 0:
        return
    n, senders = 0, {}
    for l in out.splitlines():
        try:
            j = json.loads(l)
        except ValueError:
            continue
        n += 1
        s = j.get("sender") or "(leer)"
        senders[s] = senders.get(s, 0) + 1
    if n >= 100:
        top = sorted(senders.items(), key=lambda kv: -kv[1])[:5]
        add("HOCH" if n >= 1000 else "MITTEL",
            "%d Mails in der Warteschlange – möglicherweise Spam-Versand über ein gekapertes Postfach" % n,
            *["%s: %d" % kv for kv in top], "Ansehen: mailq | head -40")


def check_helo(conf):
    rcpt = restr(conf, "smtpd_recipient_restrictions") + restr(conf, "smtpd_helo_restrictions") + \
        restr(conf, "smtpd_sender_restrictions") + restr(conf, "smtpd_client_restrictions")
    want = ["reject_unknown_sender_domain", "reject_non_fqdn_sender", "reject_invalid_helo_hostname"]
    miss = [w for w in want if w not in rcpt]
    if len(miss) == len(want):
        add("NIEDRIG", "Keine Prüfung von Absenderdomain und HELO beim Empfang",
            "Fehlt: " + ", ".join(miss), "smtpd_helo_required = %s" % conf.get("smtpd_helo_required", "no"))


def check_dkim(conf, domains):
    milters = conf.get("smtpd_milters", "") + conf.get("non_smtpd_milters", "")
    if not milters.strip() and not svc_active("rspamd"):
        add("NIEDRIG", "Keine DKIM-Signatur für ausgehende Mails",
            "Virtualmin: Email Settings → DomainKeys Identified Mail einschalten")
        return
    oc = read("/etc/opendkim.conf") or ""
    sel = re.search(r"(?m)^\s*Selector\s+(\S+)", oc)
    if not sel or not domains:
        return
    sel = sel.group(1)
    dom = re.search(r"(?m)^\s*Domain\s+(\S+)", oc)
    signed = [d.strip().lower() for d in dom.group(1).split(",")] if dom else []
    if dom and dom.group(1).startswith("/"):
        signed = [l.split()[0].lower() for l in (read(dom.group(1)) or "").splitlines() if l.strip() and not l.startswith("#")]
    for d in sorted(set(domains)):
        if signed and d not in signed:
            continue
        if not any("v=dkim1" in t.lower() or "p=" in t for t in dig("%s._domainkey.%s" % (sel, d), "TXT")):
            agg("MITTEL", "DKIM-Schlüssel fehlt im DNS ({domains})",
                "%s – TXT-Eintrag %s._domainkey.%s anlegen (Wert: Virtualmin → Email Settings → DKIM)" % (d, sel, d))


def check_fail2ban_mail():
    if not shutil_which("fail2ban-client"):
        return
    rc, out, _ = run(["fail2ban-client", "status"], timeout=20)
    jails = out.lower()
    if rc == 0 and not any(j in jails for j in ("postfix-sasl", "postfix", "dovecot", "sasl")):
        add("NIEDRIG", "fail2ban schützt die Mail-Anmeldung nicht (keine postfix-sasl/dovecot-Jail)",
            "Rateversuche auf Postfach-Passwörter werden nicht gebremst")


def mod_mail(raw, full):
    conf = postconf_all() if shutil_which("postconf") else None
    if conf is None:
        add("INFO", "Kein Postfix gefunden – Mailprüfung übersprungen")
        return
    if not shutil_which("dig"):
        add("NIEDRIG", "dig fehlt – DNS-Teile der Mailprüfung übersprungen", "Installieren: apt install bind9-dnsutils")
    check_open_relay(conf)
    check_tls(conf)
    check_spam(conf)
    sh_ok = check_dnsbl(conf) if shutil_which("dig") else False
    check_helo(conf)
    maild, _ = mail_domains()
    if shutil_which("dig"):
        check_dkim(conf, maild or [])
        check_reputation(conf, sh_ok)
    check_queue()
    check_fail2ban_mail()


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "nc-datadirs":
        nc_datadirs()
        return
    if len(sys.argv) < 2 or sys.argv[1] not in ("sites", "apps", "tools", "mail"):
        sys.exit(__doc__)
    raw = "/tmp"
    full = False
    a = sys.argv[2:]
    for i, x in enumerate(a):
        if x == "--raw" and i + 1 < len(a):
            raw = a[i + 1]
        if x == "--mode" and i + 1 < len(a):
            full = a[i + 1] == "full"
    os.environ.setdefault("RAW", raw)
    socket.setdefaulttimeout(TIMEOUT + 2)
    try:
        {"sites": mod_sites, "apps": mod_apps, "tools": mod_tools, "mail": mod_mail}[sys.argv[1]](raw, full)
    except Exception as e:  # noqa: BLE001
        import traceback
        traceback.print_exc(file=sys.stderr)
        add("NIEDRIG", "Prüfung „%s“ mit Fehler abgebrochen" % sys.argv[1], "%s: %s" % (type(e).__name__, e))
    if sys.argv[1] == "apps" and os.environ.get("WPSCAN_API_TOKEN"):
        b = _wpscan_budget()
        if b.get("blocked") == "token":
            add("NIEDRIG", "WPScan-Token wird abgelehnt – Plugin-Lücken nicht geprüft",
                "Token unter Einstellungen → Scan prüfen bzw. neu eintragen (wpscan.com → Profil)")
        elif WPSCAN_SKIPPED:
            add("INFO", "WPScan: %d Plugin(s) heute noch nicht geprüft – Tageskontingent verbraucht" % len(WPSCAN_SKIPPED),
                "Heute %d von %d Abfragen genutzt; die übrigen Plugins kommen in den nächsten Tagen an die Reihe"
                % (b.get("used", 0), WPSCAN_DAILY))
    if NET_FAIL:
        add("INFO", "Externe Versionsdaten nicht erreichbar – Versionsvergleiche teilweise übersprungen", *sorted(NET_FAIL))
    emit()


if __name__ == "__main__":
    main()
