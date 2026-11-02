#!/usr/bin/env python3
"""ubusec – Korrekturen auf Knopfdruck (läuft als root).

Aufruf:  fix.py apply|undo ART ZIEL ERGEBNISDATEI [DOMAIN]
Arten (bewusst wenige, gut prüfbare Änderungen; SSH- und Firewall-Änderungen gibt es hier absichtlich nicht,
weil sie den Zugang zum Server kosten können):
  wp-chmod       wp-config.php auf 640 setzen (nur Besitzer und Gruppe dürfen lesen)
  wp-fileedit    define('DISALLOW_FILE_EDIT', true); in wp-config.php ergänzen
  wp-uploads     PHP-Ausführung im Upload-Ordner per .htaccess sperren
  wp-xmlrpc      xmlrpc.php per .htaccess sperren (ganz oben, außerhalb der Blöcke von WordPress/Wordfence)
  svc-rpcbind    rpcbind abschalten (nur wenn kein NFS genutzt wird)
Vor jeder Änderung wird gesichert. Bei Website-Änderungen wird die Startseite vorher und nachher abgerufen;
liefert sie danach einen Serverfehler, nimmt fix.py die Änderung sofort selbst zurück.
"""
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time

BASE = os.path.join(os.environ.get("UBUSEC_STATE", "/var/lib/ubusec"), "fixes")
DOMAIN_RX = re.compile(r"^[A-Za-z0-9.-]{3,253}$")
ROOTS = ("/home/", "/var/www/", "/srv/")

UPLOAD_BLOCK = ('# ubusec: keine PHP-Ausführung im Upload-Ordner\n'
                '<FilesMatch "\\.(php|phtml|php[0-9])$">\n  Require all denied\n</FilesMatch>\n')
XMLRPC_BLOCK = ('# ubusec: XML-RPC sperren (Passwort-Raten); vor den Blöcken von WordPress/Wordfence\n'
                '<Files xmlrpc.php>\n  Require all denied\n</Files>\n\n')
FILEEDIT_LINE = "define('DISALLOW_FILE_EDIT', true); // ubusec: Datei-Editor im Backend abgeschaltet\n"


class Refuse(Exception):
    pass


def run(cmd, timeout=60):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, str(e)


def http_status(domain):
    if not domain:
        return None
    rc, out = run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "20", "-L", "--max-redirs", "3",
                   "https://%s/" % domain], 30)
    return int(out) if out.isdigit() else None


def safe_path(p, must_exist=True):
    if not re.fullmatch(r"/[A-Za-z0-9._/@+:-]{1,300}", p) or "/../" in p or not p.startswith(ROOTS):
        raise Refuse("Pfad nicht zulässig: %s" % p)
    real = os.path.realpath(p)
    if not real.startswith(ROOTS):
        raise Refuse("Pfad zeigt außerhalb der Webverzeichnisse: %s" % p)
    if must_exist and not os.path.exists(real):
        raise Refuse("Datei oder Ordner gibt es nicht: %s" % p)
    return real


def wp_root_of(path):
    d = path if os.path.isdir(path) else os.path.dirname(path)
    for cand in (d, os.path.dirname(d)):
        if os.path.isfile(os.path.join(cand, "wp-settings.php")) or os.path.isfile(os.path.join(cand, "wp-load.php")):
            return cand
    for cand in (os.path.dirname(os.path.dirname(d)),):   # …/wp-content/uploads → WordPress-Ordner
        if os.path.isfile(os.path.join(cand, "wp-settings.php")):
            return cand
    raise Refuse("Kein WordPress-Ordner: %s" % path)


def backup(fdir, path, changes):
    os.makedirs(os.path.join(fdir, "orig"), mode=0o700, exist_ok=True)
    entry = {"file": path, "existed": os.path.exists(path)}
    if entry["existed"]:
        st = os.stat(path)
        entry.update(mode=stat.S_IMODE(st.st_mode), uid=st.st_uid, gid=st.st_gid)
        b = os.path.join(fdir, "orig", "%d" % len(changes))
        shutil.copy2(path, b)
        os.chmod(b, 0o600)
        entry["backup"] = b
    changes.append(entry)
    return entry


def write_like(path, text, ref_dir_owner=None):
    """Datei schreiben und Besitzer/Rechte des Originals behalten (bzw. des Ordners bei neuen Dateien)."""
    existed = os.path.exists(path)
    st = os.stat(path) if existed else os.stat(ref_dir_owner or os.path.dirname(path))
    tmp = path + ".ubusec-tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.chown(tmp, st.st_uid, st.st_gid)
    os.chmod(tmp, stat.S_IMODE(st.st_mode) if existed else 0o644)
    os.replace(tmp, path)


def restore(changes):
    for c in reversed(changes):
        p = c["file"]
        if c.get("chmod_only"):
            os.chmod(p, c["mode"])
        elif c["existed"]:
            shutil.copy2(c["backup"], p)
            os.chown(p, c["uid"], c["gid"])
            os.chmod(p, c["mode"])
        elif os.path.exists(p):
            os.remove(p)


def read(p):
    try:
        with open(p, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


# ------------------------------------------------------------------ Änderungen ---
def do_wp_chmod(target, fdir, changes):
    p = safe_path(target)
    if os.path.basename(p) != "wp-config.php":
        raise Refuse("Nur wp-config.php")
    wp_root_of(p)
    st = os.stat(p)
    old = stat.S_IMODE(st.st_mode)
    if old & 0o007 == 0:
        return "wp-config.php ist bereits nicht für alle lesbar (Rechte %o) – nichts zu tun." % old, []
    changes.append({"file": p, "chmod_only": True, "mode": old})
    os.chmod(p, 0o640)
    return "Rechte von %s: %o → %o" % (p, old, stat.S_IMODE(os.stat(p).st_mode)), ["chmod 640 " + p]


def do_wp_fileedit(target, fdir, changes):
    p = safe_path(target)
    if os.path.basename(p) != "wp-config.php":
        raise Refuse("Nur wp-config.php")
    wp_root_of(p)
    txt = read(p)
    if re.search(r"define\(\s*['\"]DISALLOW_FILE_EDIT['\"]\s*,\s*true", txt, re.I):
        return "DISALLOW_FILE_EDIT ist bereits gesetzt – nichts zu tun.", []
    if re.search(r"define\(\s*['\"]DISALLOW_FILE_EDIT['\"]", txt, re.I):
        raise Refuse("DISALLOW_FILE_EDIT ist bereits mit anderem Wert gesetzt – bitte von Hand ändern.")
    lines = txt.splitlines(keepends=True)
    idx = next((i for i, l in enumerate(lines) if re.search(r"That's all, stop editing|Das war's, Schluss mit dem Bearbeiten", l, re.I)), None)
    if idx is None:
        idx = next((i for i, l in enumerate(lines) if re.search(r"require_once\s*\(?\s*ABSPATH\s*\.\s*['\"]wp-settings\.php", l)), None)
    if idx is None:
        raise Refuse("Keine passende Stelle in wp-config.php gefunden – bitte von Hand ergänzen.")
    backup(fdir, p, changes)
    lines.insert(idx, FILEEDIT_LINE + "\n")
    write_like(p, "".join(lines))
    if run(["php", "-l", p], 30)[0] != 0 and shutil.which("php"):
        raise Refuse("PHP meldet nach der Änderung einen Syntaxfehler – zurückgenommen.")
    return "In %s vor Zeile %d eingefügt" % (p, idx + 1), ["+ " + FILEEDIT_LINE.strip()]


def do_wp_uploads(target, fdir, changes):
    up = safe_path(target)
    if not up.rstrip("/").endswith("/wp-content/uploads") or not os.path.isdir(up):
        raise Refuse("Kein Upload-Ordner von WordPress")
    wp_root_of(up)
    ht = os.path.join(up, ".htaccess")
    txt = read(ht)
    if re.search(r"(?i)(php_flag\s+engine\s+off|Require all denied|Deny from all|SetHandler\s+none)", txt):
        return "Upload-Ordner ist bereits gesperrt – nichts zu tun.", []
    backup(fdir, ht, changes)
    write_like(ht, (txt + ("\n" if txt and not txt.endswith("\n") else "") + UPLOAD_BLOCK), ref_dir_owner=up)
    return "%s %s" % (ht, "ergänzt" if txt else "angelegt"), ["+ " + l for l in UPLOAD_BLOCK.splitlines()]


def do_wp_xmlrpc(target, fdir, changes):
    root = wp_root_of(safe_path(target))
    ht = os.path.join(root, ".htaccess")
    txt = read(ht)
    if re.search(r"(?i)<Files\s+\"?xmlrpc\.php", txt):
        return "xmlrpc.php ist in der .htaccess bereits geregelt – nichts zu tun.", []
    backup(fdir, ht, changes)
    write_like(ht, XMLRPC_BLOCK + txt, ref_dir_owner=root)
    return "%s: Sperre ganz oben eingefügt (vor den Blöcken von WordPress und Wordfence)" % ht, \
        ["+ " + l for l in XMLRPC_BLOCK.strip().splitlines()]


def do_svc_rpcbind(target, fdir, changes):
    if target != "rpcbind":
        raise Refuse("Nur rpcbind")
    mounts = read("/proc/mounts")
    exports = re.sub(r"(?m)^\s*#.*$", "", read("/etc/exports")).strip()
    if re.search(r"\snfs4?\s", mounts) or exports:
        raise Refuse("NFS wird genutzt (Freigaben oder eingebundene NFS-Laufwerke) – rpcbind wird gebraucht.")
    changes.append({"service": "rpcbind"})
    rc, out = run(["systemctl", "disable", "--now", "rpcbind.socket", "rpcbind.service"], 60)
    if rc != 0:
        raise Refuse("systemctl meldet einen Fehler: %s" % out[:200])
    return "rpcbind gestoppt und abgeschaltet (startet nicht mehr beim Hochfahren)", ["systemctl disable --now rpcbind.socket rpcbind.service"]


ACTIONS = {"wp-chmod": do_wp_chmod, "wp-fileedit": do_wp_fileedit, "wp-uploads": do_wp_uploads,
           "wp-xmlrpc": do_wp_xmlrpc, "svc-rpcbind": do_svc_rpcbind}
WEB_ACTIONS = {"wp-fileedit", "wp-uploads", "wp-xmlrpc", "wp-chmod"}


def save(out, doc):
    doc["time"] = int(time.time())
    tmp = out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False)
    os.replace(tmp, out)


def main():
    if len(sys.argv) < 5:
        sys.exit(2)
    op, kind, target, out = sys.argv[1:5]
    domain = sys.argv[5] if len(sys.argv) > 5 and DOMAIN_RX.match(sys.argv[5]) else ""
    if kind not in ACTIONS or op not in ("apply", "undo"):
        sys.exit(2)
    fid = os.path.basename(out)[:-5]
    fdir = os.path.join(BASE, fid)
    os.makedirs(fdir, mode=0o700, exist_ok=True)
    meta_p = os.path.join(fdir, "meta.json")

    if op == "undo":
        try:
            meta = json.load(open(meta_p))
        except (OSError, ValueError):
            save(out, {"kind": kind, "status": "failed", "message": "Keine Sicherung gefunden – Rückgängig nicht möglich."})
            return
        try:
            if kind == "svc-rpcbind":
                run(["systemctl", "enable", "--now", "rpcbind.socket", "rpcbind.service"], 60)
            else:
                restore(meta["changes"])
            save(out, {"kind": kind, "status": "undone", "message": "Änderung zurückgenommen – der vorherige Zustand ist wiederhergestellt.",
                       "lines": []})
        except OSError as e:
            save(out, {"kind": kind, "status": "failed", "message": "Rückgängig fehlgeschlagen: %s" % e})
        return

    changes = []
    before = http_status(domain) if kind in WEB_ACTIONS else None
    try:
        msg, lines = ACTIONS[kind](target, fdir, changes)
    except Refuse as e:
        restore([c for c in changes if "file" in c])
        save(out, {"kind": kind, "status": "refused", "message": str(e), "lines": []})
        return
    except OSError as e:
        restore([c for c in changes if "file" in c])
        save(out, {"kind": kind, "status": "failed", "message": "Fehler: %s – nichts geändert." % e, "lines": []})
        return
    if not changes:
        save(out, {"kind": kind, "status": "nothing", "message": msg, "lines": []})
        return
    json.dump({"kind": kind, "target": target, "changes": changes}, open(meta_p, "w"))
    os.chmod(meta_p, 0o600)
    doc = {"kind": kind, "status": "applied", "message": msg, "lines": lines}
    if kind in WEB_ACTIONS and domain:
        time.sleep(1)
        after = http_status(domain)
        doc["health"] = {"before": before, "after": after, "domain": domain}
        if after is not None and after >= 500 and (before is None or before < 500):
            restore(changes)
            doc.update(status="rolledback", message="Die Website %s antwortete danach mit Fehler %s – Änderung sofort "
                                                    "zurückgenommen. Bitte von Hand prüfen." % (domain, after))
    save(out, doc)


if __name__ == "__main__":
    main()
