#!/usr/bin/env python3
"""ubusec – SSH-Schlüssel für root verwalten (läuft als root).

Aufruf:  sshkeys.py status AUSGABE
         sshkeys.py add SCHLÜSSEL_BASE64URL AUSGABE
         sshkeys.py del FINGERABDRUCK AUSGABE
Es werden nur ÖFFENTLICHE Schlüssel angenommen (eine Zeile im OpenSSH-Format oder das PuTTY/RFC4716-Format).
Vor jeder Änderung an /root/.ssh/authorized_keys wird eine Sicherung angelegt.
"""
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

STATE = os.environ.get("UBUSEC_STATE", "/var/lib/ubusec")
AUTH = "/root/.ssh/authorized_keys"
KEYONLY_FILE = "/etc/ssh/sshd_config.d/00-ubusec-root.conf"
BACKUP_DIR = os.path.join(STATE, "ssh-backup")
TYPES = ("ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa",
         "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com")
KEY_RX = re.compile(r"^(%s) ([A-Za-z0-9+/]{60,2000}={0,3})(?: (.{0,200}))?$" % "|".join(re.escape(t) for t in TYPES))
FP_RX = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
LOGIN_RX = re.compile(r"^(\S+) \S+ \S+: Accepted (publickey|password|keyboard-interactive/pam) for root from (\S+) "
                      r"port \d+ \S+?(?:: (\S+) (SHA256:\S+))?\s*$")
KEYONLY_DAYS = 30


def run(cmd, timeout=30, stdin=None):
    try:
        p = subprocess.run(cmd, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout,
                           text=True, errors="replace")
        return p.returncode, p.stdout
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, str(e)


def keygen():
    return shutil.which("ssh-keygen") or "/usr/bin/ssh-keygen"


def fingerprint(line):
    """(bits, SHA256:…, TYP) einer Schlüsselzeile oder None."""
    with tempfile.NamedTemporaryFile("w", dir=_tmpdir(), delete=False) as t:
        t.write(line + "\n")
    try:
        rc, out = run([keygen(), "-l", "-f", t.name], 10)
    finally:
        os.unlink(t.name)
    m = re.match(r"^(\d+) (SHA256:\S+) .*\((\S+)\)\s*$", out.strip().splitlines()[0] if out.strip() else "")
    return (int(m.group(1)), m.group(2), m.group(3)) if rc == 0 and m else None


def _tmpdir():
    d = os.path.join(STATE, "work")
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d


def split_options(line):
    """Optionen vor dem Schlüsseltyp abtrennen (from="…",command="…" usw.)."""
    for t in TYPES:
        i = line.find(t + " ")
        if i == 0:
            return "", line
        if i > 0 and line[i - 1] == " ":
            return line[:i - 1], line[i:]
    return None, line


def read_keys():
    keys = []
    try:
        lines = open(AUTH, encoding="utf-8", errors="replace").read().splitlines()
    except OSError:
        return keys, []
    for i, raw in enumerate(lines):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        opts, key = split_options(s)
        fp = fingerprint(key) if opts is not None else None
        parts = key.split(" ", 2)
        keys.append({"idx": i, "valid": bool(fp), "options": bool(opts), "type": fp[2] if fp else parts[0][:30],
                     "bits": fp[0] if fp else 0, "fp": fp[1] if fp else "",
                     "comment": (parts[2] if len(parts) > 2 else "")[:80],
                     "restricted": bool(opts and re.search(r'(^|,)\s*(command=|restrict)', opts))})
    return keys, lines


def sshd_effective():
    sshd = shutil.which("sshd") or "/usr/sbin/sshd"
    rc, out = run([sshd, "-T"], 20)
    eff = {}
    if rc == 0:
        for ln in out.splitlines():
            k, _, v = ln.partition(" ")
            if k in ("permitrootlogin", "passwordauthentication", "pubkeyauthentication", "port",
                     "kbdinteractiveauthentication"):
                eff.setdefault(k, v.strip())
    return eff


def journal(pattern, since):
    base = ["journalctl", "--no-pager", "-q", "-o", "short-iso", "-t", "sshd", "-t", "sshd-session", "--since", since]
    rc, out = run(base + ["-g", pattern], 60)
    if rc in (0, 1) and "pattern" not in out.lower()[:200]:
        return [l for l in out.splitlines() if re.search(pattern, l)]
    return []


def authlog(pattern):
    out = []
    for p in ("/var/log/auth.log.1", "/var/log/auth.log"):
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                out += [l.rstrip("\n") for l in f if re.search(pattern, l)]
        except OSError:
            pass
    return out


def logins(keys):
    pat = r"Accepted (publickey|password|keyboard-interactive/pam) for root from"
    lines = journal(pat, "-60d")
    src = "journal"
    if not lines:
        lines, src = authlog(pat), "auth.log"
    names = {k["fp"]: k["comment"] or k["type"] for k in keys if k["fp"]}
    res = []
    for l in lines[-200:]:
        if src == "auth.log":
            # klassisches Syslog-Format: „Nov  8 10:12:13 host sshd[1]: …“ → Zeit ohne Jahr
            m0 = re.match(r"^(\w{3}\s+\d+ [\d:]{8}|\S+T\S+) (.*)$", l)
            if not m0:
                continue
            l = m0.group(1).replace(" ", "_") + " " + m0.group(2)
        m = LOGIN_RX.match(l)
        if not m:
            continue
        t, method, ip, ktype, fp = m.groups()
        res.append({"time": t.replace("_", " "), "method": "Schlüssel" if method == "publickey" else "Passwort",
                    "ip": ip, "fp": fp or "", "key": names.get(fp or "", "(nicht mehr eingetragen)" if fp else "")})
    return res[-25:][::-1]


def failed_root():
    return len(journal(r"Failed (password|none) for root from|authentication failure.*user=root", "-7d"))


def key_login_ok(keys, logs):
    """Gab es in den letzten Tagen eine Schlüssel-Anmeldung als root mit einem noch eingetragenen Schlüssel?"""
    fps = {k["fp"] for k in keys if k["valid"] and not k["restricted"]}
    if not fps:
        return False
    limit = time.time() - KEYONLY_DAYS * 86400
    for l in logs:
        if l["method"] != "Schlüssel" or l["fp"] not in fps:
            continue
        try:
            ts = time.mktime(time.strptime(l["time"][:19], "%Y-%m-%dT%H:%M:%S"))
        except ValueError:
            ts = time.time()  # auth.log ohne Jahr – kommt aus den letzten beiden Logdateien, also aktuell genug
        if ts >= limit:
            return True
    return False


def status(last=None):
    keys, _ = read_keys()
    logs = logins(keys)
    eff = sshd_effective()
    doc = {"time": int(time.time()), "keys": keys, "logins": logs, "failed_root_7d": failed_root(), "sshd": eff,
           "keyonly_file": os.path.exists(KEYONLY_FILE), "keyonly_days": KEYONLY_DAYS,
           "key_login_ok": key_login_ok(keys, logs), "auth_file": AUTH,
           "backups": sorted(os.listdir(BACKUP_DIR))[-5:] if os.path.isdir(BACKUP_DIR) else []}
    if last:
        doc["last"] = last
    return doc


def backup():
    if not os.path.exists(AUTH):
        return None
    os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)
    b = os.path.join(BACKUP_DIR, "authorized_keys.%s-%06d" % (time.strftime("%Y%m%d-%H%M%S"), time.time() * 1e6 % 1e6))
    shutil.copy2(AUTH, b)
    os.chmod(b, 0o600)
    old = sorted(os.listdir(BACKUP_DIR))
    for f in old[:-20]:
        os.unlink(os.path.join(BACKUP_DIR, f))
    return b


def write_auth(lines):
    os.makedirs("/root/.ssh", mode=0o700, exist_ok=True)
    os.chmod("/root/.ssh", 0o700)
    tmp = AUTH + ".ubusec-tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines).rstrip("\n") + "\n")
    os.chown(tmp, 0, 0)
    os.chmod(tmp, 0o600)
    os.replace(tmp, AUTH)
    if shutil.which("restorecon"):
        run(["restorecon", AUTH], 10)


def normalize(text):
    """Eingefügten Text in eine OpenSSH-Schlüsselzeile verwandeln – oder ValueError mit verständlicher Meldung."""
    text = text.replace("\r", "").strip()
    if "PRIVATE KEY" in text or "PuTTY-User-Key-File" in text:
        raise ValueError("Das ist ein PRIVATER Schlüssel – der darf nie auf den Server. Bitte den öffentlichen Teil "
                         "einfügen (Datei mit der Endung .pub bzw. in PuTTYgen das Feld oben).")
    if "BEGIN SSH2 PUBLIC KEY" in text:
        with tempfile.NamedTemporaryFile("w", dir=_tmpdir(), delete=False) as t:
            t.write(text + "\n")
        try:
            rc, out = run([keygen(), "-i", "-m", "RFC4716", "-f", t.name], 10)
        finally:
            os.unlink(t.name)
        if rc != 0:
            raise ValueError("Das PuTTY-Format konnte nicht umgewandelt werden.")
        cm = re.search(r'^Comment:\s*"?([^"\n]*)"?', text, re.M)
        text = out.strip().splitlines()[0] + (" " + cm.group(1) if cm else "")
    text = " ".join(text.split())  # Zeilenumbrüche beim Kopieren entfernen
    m = KEY_RX.match(text)
    if not m:
        if re.match(r"^\S+=|^(command|from|restrict|no-)", text):
            raise ValueError("Bitte nur den Schlüssel selbst einfügen, ohne Optionen davor.")
        raise ValueError("Das sieht nicht wie ein öffentlicher SSH-Schlüssel aus. Er beginnt mit „ssh-ed25519 “ "
                         "(oder ssh-rsa / ecdsa-sha2-…) und besteht aus einer einzigen Zeile.")
    ktype, b64, comment = m.groups()
    comment = re.sub(r"[^A-Za-z0-9._@+:-]+", "-", (comment or "").strip()).strip("-")[:60]
    if not comment:
        comment = "ubusec-%s" % time.strftime("%Y-%m-%d")
    return "%s %s %s" % (ktype, b64, comment)


def add(b64):
    try:
        text = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4)).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return {"op": "add", "ok": False, "message": "Ungültige Eingabe."}
    try:
        line = normalize(text)
    except ValueError as e:
        return {"op": "add", "ok": False, "message": str(e)}
    fp = fingerprint(line)
    if not fp:
        return {"op": "add", "ok": False, "message": "ssh-keygen erkennt den Schlüssel nicht – beim Kopieren ist "
                                                      "vermutlich etwas abgeschnitten worden."}
    bits, f, typ = fp
    if typ == "RSA" and bits < 3072:
        return {"op": "add", "ok": False, "message": "RSA-Schlüssel mit %d Bit ist zu schwach. Bitte einen neuen "
                                                      "Ed25519-Schlüssel erzeugen (ssh-keygen -t ed25519)." % bits}
    keys, lines = read_keys()
    if any(k["fp"] == f for k in keys):
        return {"op": "add", "ok": True, "message": "Dieser Schlüssel ist bereits eingetragen (%s)." % f}
    backup()
    write_auth(lines + [line])
    return {"op": "add", "ok": True, "fp": f,
            "message": "Schlüssel „%s“ (%s, %s) eingetragen. Jetzt von diesem Gerät aus anmelden und testen."
                       % (line.split(" ", 2)[2], typ, f)}


def delete(fp):
    keys, lines = read_keys()
    hit = [k for k in keys if k["fp"] == fp]
    if not hit:
        return {"op": "del", "ok": False, "message": "Schlüssel nicht gefunden."}
    rest = [k for k in keys if k["valid"] and k["fp"] != fp and not k["restricted"]]
    eff = sshd_effective().get("permitrootlogin", "yes")
    if not rest and eff != "yes":
        return {"op": "del", "ok": False,
                "message": "Das ist der letzte Schlüssel, und der Root-Login per Passwort ist abgeschaltet – ohne ihn "
                           "kämst du nicht mehr als root per SSH auf den Server. Erst einen anderen Schlüssel eintragen "
                           "oder die Umstellung rückgängig machen."}
    backup()
    drop = {k["idx"] for k in hit}
    write_auth([l for i, l in enumerate(lines) if i not in drop])
    return {"op": "del", "ok": True, "message": "Schlüssel „%s“ entfernt. Das Gerät kann sich damit nicht mehr "
                                                "anmelden; bestehende Sitzungen bleiben offen." % (hit[0]["comment"] or fp)}


def save(out, doc):
    tmp = out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False)
    os.replace(tmp, out)


def main():
    if len(sys.argv) < 3:
        sys.exit(2)
    op = sys.argv[1]
    last = None
    if op == "status" and len(sys.argv) == 3:
        out = sys.argv[2]
        try:  # Ergebnis der letzten Änderung noch eine Weile mitführen, damit die Oberfläche es anzeigen kann
            prev = json.load(open(out)).get("last")
            if prev and time.time() - prev.get("time", 0) < 120:
                last = prev
        except (OSError, ValueError, AttributeError):
            pass
    elif op == "add" and len(sys.argv) == 4 and re.fullmatch(r"[A-Za-z0-9_-]{20,4000}", sys.argv[2]):
        out = sys.argv[3]
        last = add(sys.argv[2])
    elif op == "del" and len(sys.argv) == 4 and FP_RX.match(sys.argv[2]):
        out = sys.argv[3]
        last = delete(sys.argv[2])
    else:
        sys.exit(2)
    if last and op != "status":
        last["time"] = int(time.time())
    save(out, status(last))


if __name__ == "__main__":
    main()
