#!/usr/bin/env python3
"""ubusec – Korrekturen auf Knopfdruck (läuft als root).

Aufruf:  fix.py apply|undo ART ZIEL ERGEBNISDATEI [DOMAIN]
Arten (bewusst wenige, gut prüfbare Änderungen; Firewall-Änderungen gibt es hier absichtlich nicht, SSH nur mit
Schutz vor dem Aussperren):
  wp-chmod       wp-config.php auf 640 setzen (nur Besitzer und Gruppe dürfen lesen)
  wp-fileedit    define('DISALLOW_FILE_EDIT', true); in wp-config.php ergänzen
  wp-uploads     PHP-Ausführung im Upload-Ordner per .htaccess sperren
  wp-xmlrpc      xmlrpc.php per .htaccess sperren (ganz oben, außerhalb der Blöcke von WordPress/Wordfence)
  svc-rpcbind    rpcbind abschalten (nur wenn kein NFS genutzt wird)
Vor jeder Änderung wird gesichert. Bei Website-Änderungen wird die Startseite vorher und nachher abgerufen;
liefert sie danach einen Serverfehler, nimmt fix.py die Änderung sofort selbst zurück.
"""
import glob
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
        if "moved" in c:
            if not os.path.exists(c["moved"]):
                shutil.move(c["to"], c["moved"])
            continue
        if "postconf" in c:
            run(["postconf", "-e"] + ["%s = %s" % (k, v) for k, v in c["postconf"].items()], 20)
            run(["systemctl", "reload", "postfix"], 30)
            continue
        if "file" not in c:
            continue
        p = c["file"]
        if c.get("sysctl_old"):
            for k, v in c["sysctl_old"].items():
                run(["sysctl", "-q", "-w", "%s=%s" % (k, v)], 10)
        if c.get("chmod_only"):
            os.chmod(p, c["mode"])
        elif c["existed"]:
            shutil.copy2(c["backup"], p)
            os.chown(p, c["uid"], c["gid"])
            os.chmod(p, c["mode"])
        elif os.path.exists(p):
            os.remove(p)


def reload_after(kind):
    """Dienste nach dem Zurücknehmen neu laden, damit der alte Zustand wieder gilt."""
    if kind in ("ssh-safe", "ssh-root-keyonly"):
        if run(["systemctl", "reload", "ssh"], 30)[0] != 0:
            run(["systemctl", "reload", "sshd"], 30)
    elif kind == "bind-version":
        if run(["systemctl", "reload", "named"], 30)[0] != 0:
            run(["systemctl", "reload", "bind9"], 30)
    elif kind == "php-ini":
        for svc in glob.glob("/lib/systemd/system/php*-fpm.service") + glob.glob("/usr/lib/systemd/system/php*-fpm.service"):
            run(["systemctl", "reload", os.path.basename(svc)], 30)


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


# ------------------------------------------------------------ weitere Korrekturen ---
SYSCTL_SAFE = {   # Werte, die auch mit Docker/VPN unbedenklich sind (ip_forward fehlt bewusst)
    "fs.protected_symlinks": "1", "fs.protected_hardlinks": "1", "fs.suid_dumpable": "0", "kernel.kptr_restrict": "1",
    "kernel.dmesg_restrict": "1", "kernel.yama.ptrace_scope": "1", "net.ipv4.tcp_syncookies": "1",
    "net.ipv4.conf.all.accept_redirects": "0", "net.ipv4.conf.all.send_redirects": "0",
    "net.ipv4.conf.all.accept_source_route": "0", "net.ipv4.conf.all.log_martians": "1",
    "net.ipv6.conf.all.accept_redirects": "0"}
SYSCTL_FILE = "/etc/sysctl.d/99-ubusec.conf"
SSH_FILE = "/etc/ssh/sshd_config.d/01-ubusec.conf"


def do_sysctl(target, fdir, changes):
    if target != "kernel":
        raise Refuse("Nur kernel")
    todo = {}
    for k, v in SYSCTL_SAFE.items():
        rc, cur = run(["sysctl", "-n", k], 10)
        if rc == 0 and cur.strip() != v:
            todo[k] = (cur.strip(), v)
    if not todo:
        return "Alle Kernel-Parameter haben bereits die empfohlenen Werte – nichts zu tun.", []
    backup(fdir, SYSCTL_FILE, changes)
    changes[-1]["sysctl_old"] = {k: o for k, (o, _) in todo.items()}
    old = read(SYSCTL_FILE)
    body = "".join(l for l in old.splitlines(keepends=True) if l.split("=")[0].strip() not in todo)
    body = (body or "# von ubusec – Kernel-Härtung (Rückgängig über die Weboberfläche)\n") + \
        "".join("%s = %s\n" % (k, v) for k, (_, v) in sorted(todo.items()))
    write_like(SYSCTL_FILE, body, ref_dir_owner="/etc/sysctl.d")
    os.chmod(SYSCTL_FILE, 0o644)
    for k, (_, v) in todo.items():
        run(["sysctl", "-q", "-w", "%s=%s" % (k, v)], 10)
    return "%s geschrieben und sofort wirksam" % SYSCTL_FILE, ["%s: %s → %s" % (k, o, v) for k, (o, v) in sorted(todo.items())]


def do_ssh_safe(target, fdir, changes):
    """Nur Einstellungen, die niemanden aussperren: X11Forwarding no, MaxAuthTries 4."""
    if target != "sshd":
        raise Refuse("Nur sshd")
    main = read("/etc/ssh/sshd_config")
    if not re.search(r"(?mi)^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf", main):
        raise Refuse("sshd_config bindet sshd_config.d nicht ein – bitte von Hand in /etc/ssh/sshd_config ändern.")
    backup(fdir, SSH_FILE, changes)
    write_like(SSH_FILE, "# von ubusec – sichere SSH-Härtung (sperrt niemanden aus)\nX11Forwarding no\nMaxAuthTries 4\n",
               ref_dir_owner="/etc/ssh/sshd_config.d")
    os.chmod(SSH_FILE, 0o644)
    sshd = shutil.which("sshd") or "/usr/sbin/sshd"
    rc, out = run([sshd, "-t"], 20)
    if rc != 0:
        raise Refuse("sshd -t meldet einen Fehler: %s" % out[:200])
    rc, eff = run([sshd, "-T"], 20)
    if rc == 0 and ("x11forwarding no" not in eff.lower() or "maxauthtries 4" not in eff.lower()):
        raise Refuse("Eine andere Datei in sshd_config.d legt diese Werte vorher fest – bitte dort ändern.")
    if run(["systemctl", "reload", "ssh"], 30)[0] != 0:
        run(["systemctl", "reload", "sshd"], 30)
    return "%s angelegt, SSH-Dienst neu geladen (bestehende Sitzungen bleiben offen)" % SSH_FILE, \
        ["X11Forwarding no", "MaxAuthTries 4"]


KEYONLY_FILE = "/etc/ssh/sshd_config.d/00-ubusec-root.conf"


def do_ssh_root_keyonly(target, fdir, changes):
    """PermitRootLogin prohibit-password – nur wenn eine Schlüssel-Anmeldung als root nachweislich funktioniert hat."""
    if target != "sshd":
        raise Refuse("Nur sshd")
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import sshkeys
    keys, _ = sshkeys.read_keys()
    good = [k for k in keys if k["valid"] and not k["restricted"]]
    if not good:
        raise Refuse("Für root ist noch kein SSH-Schlüssel eingetragen. Bitte zuerst der Anleitung „SSH-Schlüssel“ "
                     "folgen – sonst würdest du dich aussperren.")
    if not sshkeys.key_login_ok(keys, sshkeys.logins(keys)):
        raise Refuse("Es gab in den letzten %d Tagen noch keine erfolgreiche Anmeldung als root mit einem der "
                     "eingetragenen Schlüssel. Bitte erst von jedem Gerät, das du nutzt, einmal per Schlüssel "
                     "anmelden – dann umstellen." % sshkeys.KEYONLY_DAYS)
    main = read("/etc/ssh/sshd_config")
    if not re.search(r"(?mi)^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf", main):
        raise Refuse("sshd_config bindet sshd_config.d nicht ein – bitte von Hand in /etc/ssh/sshd_config ändern.")
    backup(fdir, KEYONLY_FILE, changes)
    write_like(KEYONLY_FILE, "# von ubusec – root nur noch mit SSH-Schlüssel (Passwort für root abgeschaltet)\n"
                             "# Notfall (z. B. über die Konsole des Anbieters):\n"
                             "#   rm %s && systemctl reload ssh\nPermitRootLogin prohibit-password\n" % KEYONLY_FILE,
               ref_dir_owner="/etc/ssh/sshd_config.d")
    os.chmod(KEYONLY_FILE, 0o644)
    sshd = shutil.which("sshd") or "/usr/sbin/sshd"
    rc, out = run([sshd, "-t"], 20)
    if rc != 0:
        raise Refuse("sshd -t meldet einen Fehler: %s" % out[:200])
    rc, eff = run([sshd, "-T"], 20)
    if rc == 0 and not re.search(r"(?m)^permitrootlogin (without-password|prohibit-password)$", eff.lower()):
        raise Refuse("Eine andere SSH-Einstellung legt PermitRootLogin vorher fest (z. B. direkt in "
                     "/etc/ssh/sshd_config vor der Include-Zeile) – bitte dort ändern.")
    if run(["systemctl", "reload", "ssh"], 30)[0] != 0:
        run(["systemctl", "reload", "sshd"], 30)
    return ("Root meldet sich ab jetzt nur noch mit Schlüssel an (%d Schlüssel eingetragen). Bestehende Sitzungen "
            "bleiben offen – bitte jetzt in einem NEUEN Fenster anmelden und testen." % len(good)), \
        ["PermitRootLogin prohibit-password", "Notfall: sudo rm %s && sudo systemctl reload ssh" % KEYONLY_FILE]


def do_postfix_banner(target, fdir, changes):
    if target != "postfix" or not shutil.which("postconf"):
        raise Refuse("Postfix nicht gefunden")
    old = {k: run(["postconf", "-h", k], 10)[1] for k in ("smtpd_banner", "disable_vrfy_command")}
    changes.append({"postconf": old})
    run(["postconf", "-e", "smtpd_banner = $myhostname ESMTP", "disable_vrfy_command = yes"], 20)
    rc, out = run(["postfix", "check"], 30)
    if rc != 0:
        raise Refuse("postfix check meldet einen Fehler: %s" % out[:200])
    run(["systemctl", "reload", "postfix"], 30)
    return "Postfix-Banner verkürzt, VRFY abgeschaltet", ["smtpd_banner = $myhostname ESMTP (vorher: %s)" % old["smtpd_banner"],
                                                       "disable_vrfy_command = yes"]


def do_bind_version(target, fdir, changes):
    p = "/etc/bind/named.conf.options"
    if target != "bind" or not os.path.isfile(p):
        raise Refuse("BIND-Konfiguration nicht gefunden")
    txt = read(p)
    if re.search(r"(?m)^\s*version\s+", txt):
        return "In named.conf.options ist bereits eine version-Zeile – nichts zu tun.", []
    m = re.search(r"(?m)^\s*options\s*\{[^\n]*\n", txt)
    if not m:
        raise Refuse("Kein options-Block gefunden – bitte von Hand ergänzen.")
    backup(fdir, p, changes)
    write_like(p, txt[:m.end()] + '\tversion "none";   // ubusec: Version nicht verraten\n' + txt[m.end():])
    checker = shutil.which("named-checkconf")
    if checker and run([checker], 30)[0] != 0:
        raise Refuse("named-checkconf meldet einen Fehler – zurückgenommen.")
    if run(["systemctl", "reload", "named"], 30)[0] != 0:
        run(["systemctl", "reload", "bind9"], 30)
    return "%s: version \"none\" ergänzt, BIND neu geladen" % p, ['+ version "none";']


def do_php_ini(target, fdir, changes):
    p = os.path.realpath(target)
    if not (re.fullmatch(r"/etc/php/[0-9.]+/(fpm|cgi|cli|apache2)/php\.ini", p)
            or re.fullmatch(r"/home/[A-Za-z0-9._-]+/(domains/[A-Za-z0-9.-]+/)?etc/php[0-9.]*/php\.ini", p)):
        raise Refuse("Keine php.ini an einem bekannten Ort: %s" % target)
    txt = read(p)
    want = {"session.cookie_httponly": "1", "expose_php": "Off"}
    lines, seen, diff = txt.splitlines(keepends=True), set(), []
    for i, l in enumerate(lines):
        m = re.match(r"^\s*;?\s*(session\.cookie_httponly|expose_php)\s*=\s*(.*?)\s*$", l)
        if m and m.group(1) not in seen and not l.lstrip().startswith(";"):
            k = m.group(1)
            seen.add(k)
            if m.group(2).lower() not in (want[k].lower(), "true" if want[k] == "1" else "x"):
                lines[i] = "%s = %s\n" % (k, want[k])
                diff.append("%s: %s → %s" % (k, m.group(2) or "(leer)", want[k]))
    add = [k for k in want if k not in seen]
    if not diff and not add:
        return "Werte sind bereits gesetzt – nichts zu tun.", []
    backup(fdir, p, changes)
    new = "".join(lines)
    if add:
        new += ("" if new.endswith("\n") else "\n") + "; von ubusec ergänzt\n" + "".join("%s = %s\n" % (k, want[k]) for k in add)
        diff += ["+ %s = %s" % (k, want[k]) for k in add]
    write_like(p, new)
    for svc in glob.glob("/lib/systemd/system/php*-fpm.service") + glob.glob("/usr/lib/systemd/system/php*-fpm.service"):
        run(["systemctl", "reload", os.path.basename(svc)], 30)
    return "%s angepasst, PHP-FPM neu geladen" % p, diff


QUARANTINE_OK = re.compile(r"/(wp-content/uploads|uploads|upload|media/files|sites/[^/]+/files)/(.+/)?[^/]+\.(php[0-9]?|phtml)$|/(phpinfo|info|test)\.php$|/\.DS_Store$|/wp-content/(plugins|themes)/[^/]+/[^/]+\.(zip|tar|tar\.gz|tgz|7z|rar)$|/installer$")


def do_quarantine(target, fdir, changes):
    """Datei/Ordner aus dem Webverzeichnis in die Sicherung von ubusec verschieben (Rückgängig: zurückschieben)."""
    p = safe_path(target)
    if not QUARANTINE_OK.search(p):
        raise Refuse("Diese Datei verschiebt ubusec nicht automatisch: %s" % p)
    if p.endswith("/installer") and not (os.path.isdir(p) and os.path.isfile(os.path.join(os.path.dirname(p), "program/include/iniset.php"))):
        raise Refuse("Kein Roundcube-Installer-Ordner: %s" % p)
    if re.search(r"/(phpinfo|info|test)\.php$", p) and "/uploads/" not in p and "phpinfo" not in read(p).lower():
        raise Refuse("Die Datei enthält kein phpinfo() – bitte selbst ansehen: %s" % p)
    os.makedirs(os.path.join(fdir, "orig"), mode=0o700, exist_ok=True)
    dest = os.path.join(fdir, "orig", "q%d" % len(changes))
    st = os.lstat(p)
    shutil.move(p, dest)
    changes.append({"moved": p, "to": dest, "uid": st.st_uid, "gid": st.st_gid})
    return "%s in die Sicherung von ubusec verschoben (%s)" % (p, dest), ["- " + p]


def do_sticky(target, fdir, changes):
    """Sticky-Bit für einen für alle beschreibbaren Ordner: Schreiben bleibt erlaubt, aber nur der Besitzer
    einer Datei darf sie löschen oder umbenennen (wie bei /tmp)."""
    if not re.fullmatch(r"/[A-Za-z0-9._/@+:-]{1,300}", target) or "/../" in target or \
            target.rstrip("/") in ("", "/proc", "/sys", "/dev") or target.startswith(("/proc/", "/sys/")):
        raise Refuse("Pfad nicht zulässig: %s" % target)
    p = os.path.realpath(target)
    if not os.path.isdir(p) or os.path.islink(target):
        raise Refuse("Kein Ordner: %s" % target)
    m = stat.S_IMODE(os.stat(p).st_mode)
    if m & 0o1000:
        return "Sticky-Bit ist bereits gesetzt – nichts zu tun.", []
    if not m & 0o002:
        return "Ordner ist nicht für alle beschreibbar – nichts zu tun.", []
    changes.append({"file": p, "chmod_only": True, "mode": m})
    os.chmod(p, m | 0o1000)
    return "Sticky-Bit für %s gesetzt (%o → %o)" % (p, m, m | 0o1000), ["chmod +t " + p]


ACTIONS = {"wp-chmod": do_wp_chmod, "sticky": do_sticky, "wp-fileedit": do_wp_fileedit, "wp-uploads": do_wp_uploads,
           "wp-xmlrpc": do_wp_xmlrpc, "svc-rpcbind": do_svc_rpcbind, "sysctl": do_sysctl, "ssh-safe": do_ssh_safe,
           "ssh-root-keyonly": do_ssh_root_keyonly,
           "postfix-banner": do_postfix_banner, "bind-version": do_bind_version, "php-ini": do_php_ini,
           "quarantine": do_quarantine}
WEB_ACTIONS = {"wp-fileedit", "wp-uploads", "wp-xmlrpc", "wp-chmod", "php-ini", "quarantine"}


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
                reload_after(kind)
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
        restore(changes)
        reload_after(kind)
        save(out, {"kind": kind, "status": "refused", "message": str(e), "lines": []})
        return
    except OSError as e:
        restore(changes)
        reload_after(kind)
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
            reload_after(kind)
            doc.update(status="rolledback", message="Die Website %s antwortete danach mit Fehler %s – Änderung sofort "
                                                    "zurückgenommen. Bitte von Hand prüfen." % (domain, after))
    save(out, doc)


if __name__ == "__main__":
    main()
