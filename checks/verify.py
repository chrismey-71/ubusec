#!/usr/bin/env python3
"""ubusec – Nachprüfungen auf Knopfdruck (läuft als root, nur lesend).

Aufruf:  verify.py ART ERGEBNISDATEI ARGUMENT…
Arten:
  binaries  Programme (Namen) byte-genau mit dem frisch geladenen Ubuntu-Paket vergleichen
  pkgfiles  Dateien (Pfade) byte-genau mit dem frisch geladenen Ubuntu-Paket vergleichen
  fileinfo  Datei-Steckbrief: Typ, Besitzer, Alter, Prüfsumme, Paket, nutzende Prozesse
  ports     Welches Programm lauscht auf dem Port, gehört es zu einem Paket?
Schreibt JSON: {"kind", "time", "verdict": ok|warn|bad|info, "summary", "rows": [{"item","result","state"}]}
"""
import glob
import hashlib
import json
import os
import pwd
import re
import shutil
import subprocess
import sys
import tempfile
import time

NAME_RX = re.compile(r"^[a-z0-9._+-]{1,40}$")
PATH_RX = re.compile(r"^/[A-Za-z0-9._/@+:-]{1,300}$")
PORT_RX = re.compile(r"^[0-9]{1,5}$")


def run(cmd, timeout=120, cwd=None):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        return p.returncode, p.stdout
    except (OSError, subprocess.TimeoutExpired):
        return 1, ""


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def owner_pkg(path):
    for p in (path, os.path.realpath(path)):
        rc, out = run(["dpkg", "-S", p], 30)
        if rc == 0 and out:
            return out.split(":", 1)[0].split(",")[0].strip()
    return ""


class Debs:
    """Originalpakete in der installierten Version laden und entpacken (je Paket einmal)."""

    def __init__(self):
        self.tmp = tempfile.mkdtemp(prefix="ubusec-verify-")
        os.chmod(self.tmp, 0o755)
        try:
            shutil.chown(self.tmp, user="_apt")
        except (LookupError, OSError):
            pass
        self.dirs = {}

    def get(self, pkg):
        if pkg in self.dirs:
            return self.dirs[pkg]
        rc, ver = run(["dpkg-query", "-W", "-f=${Version}", pkg], 30)
        d = os.path.join(self.tmp, re.sub(r"[^A-Za-z0-9.+-]", "_", pkg))
        os.makedirs(d, exist_ok=True)
        try:
            shutil.chown(d, user="_apt")
        except (LookupError, OSError):
            pass
        ok = False
        if rc == 0 and ver:
            rc2, _ = run(["apt-get", "download", "-q", "%s=%s" % (pkg, ver)], 180, cwd=d)
            debs = glob.glob(os.path.join(d, "*.deb"))
            if rc2 == 0 and debs:
                ok = run(["dpkg-deb", "-x", debs[0], os.path.join(d, "x")], 180)[0] == 0
        self.dirs[pkg] = (os.path.join(d, "x") if ok else None, ver)
        return self.dirs[pkg]

    def close(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


def compare(paths, labels=None):
    debs = Debs()
    rows, seen = [], set()
    try:
        for i, path in enumerate(paths):
            label = labels[i] if labels else path
            if not os.path.exists(path):
                rows.append({"item": label, "result": "Datei existiert nicht (mehr)", "state": "info"})
                continue
            real = os.path.realpath(path)
            pkg = owner_pkg(path)
            if not pkg:
                rows.append({"item": label, "result": "%s gehört zu keinem Paket – Herkunft selbst klären" % real, "state": "warn"})
                continue
            d, ver = debs.get(pkg)
            if not d:
                rc, out = run(["dpkg", "--verify", pkg], 120)
                changed = any(line.endswith(" " + real) or line.endswith(" " + path) for line in out.splitlines())
                rows.append({"item": label, "result": "Paket %s %s: Original nicht ladbar; laut lokaler Prüfsumme %s"
                             % (pkg, ver, "VERÄNDERT" if changed else "unverändert"), "state": "bad" if changed else "warn"})
                continue
            cands = [d + real, d + path, d + "/usr" + path[4:] if path.startswith("/usr/") else d + "/usr" + path, d + real.replace("/usr", "", 1)]
            orig = next((c for c in cands if os.path.isfile(c)), None)
            key = (real, pkg)
            if orig is None:
                rows.append({"item": label, "result": "Paket %s %s: Datei nicht im Originalpaket (z. B. später erzeugt)" % (pkg, ver), "state": "warn"})
            elif sha256(real) == sha256(orig):
                note = "" if key not in seen else " (gleiche Datei wie oben)"
                rows.append({"item": label, "result": "identisch mit dem Original aus %s %s%s" % (pkg, ver, note), "state": "ok"})
            else:
                rows.append({"item": label, "result": "WEICHT AB vom Original aus %s %s – nichts löschen, Notfall-Hinweise befolgen" % (pkg, ver),
                             "state": "bad"})
            seen.add(key)
    finally:
        debs.close()
    return rows


def users_of(path):
    users = set()
    for maps in glob.glob("/proc/[0-9]*/maps") + glob.glob("/proc/[0-9]*/exe"):
        pid = maps.split("/")[2]
        try:
            if maps.endswith("exe"):
                hit = os.readlink(maps) == path
            else:
                with open(maps, errors="replace") as f:
                    hit = path in f.read()
            if hit:
                with open("/proc/%s/comm" % pid) as f:
                    users.add("%s (PID %s)" % (f.read().strip(), pid))
        except OSError:
            pass
    return sorted(users)[:6]


def fileinfo(paths):
    rows = []
    for p in paths:
        if not os.path.lexists(p):
            rows.append({"item": p, "result": "existiert nicht (mehr)", "state": "info"})
            continue
        st = os.lstat(p)
        try:
            own = pwd.getpwuid(st.st_uid).pw_name
        except KeyError:
            own = str(st.st_uid)
        parts = ["Besitzer %s" % own, "geändert %s" % time.strftime("%d.%m.%Y %H:%M", time.localtime(st.st_mtime))]
        state = "info"
        if os.path.isdir(p):
            n = sum(len(f) for _, _, f in os.walk(p))
            parts.insert(0, "Ordner mit %d Dateien" % n)
        else:
            rc, typ = run(["file", "-b", p], 30)
            typ = typ.strip()[:90]
            parts.insert(0, "%s, %d Bytes" % (typ or "Datei", st.st_size))
            if st.st_size < 200 * 1024 * 1024 and os.path.isfile(p):
                parts.append("SHA256 %s" % sha256(p)[:16] + "…")
            pkg = owner_pkg(p)
            parts.append("aus Paket %s" % pkg if pkg else "zu keinem Paket gehörig")
            us = users_of(os.path.realpath(p))
            parts.append("genutzt von " + ", ".join(us) if us else "von keinem Prozess genutzt")
            if not pkg and ("ELF" in typ or st.st_mode & 0o111) and re.match(r"^/(tmp|var/tmp|dev/shm)/", p):
                state = "warn"
        rows.append({"item": p, "result": "; ".join(parts), "state": state})
    return rows


def ports(nums):
    rows = []
    rc, out = run(["ss", "-H", "-tulnp"], 30)
    for n in nums:
        lines = [l for l in out.splitlines() if re.search(r":%s\s" % n, l)]
        if not lines:
            rows.append({"item": "Port %s" % n, "result": "derzeit lauscht dort kein Programm", "state": "info"})
            continue
        procs = sorted(set(re.findall(r'\("([^"]+)",pid=(\d+)', " ".join(lines))))
        addrs = sorted(set(l.split()[4] if len(l.split()) > 4 else "" for l in lines))
        desc = []
        state = "ok"
        for name, pid in procs[:4]:
            try:
                exe = os.readlink("/proc/%s/exe" % pid)
            except OSError:
                exe = "?"
            pkg = owner_pkg(exe) if exe != "?" else ""
            if exe == "?":
                desc.append("%s (Programmdatei nicht ermittelbar)" % name)
            else:
                desc.append("%s (%s%s)" % (name, exe, ", Paket " + pkg if pkg else ", KEIN Paket"))
            if not pkg:
                state = "warn"
        public = [a for a in addrs if not re.match(r"^(127\.|\[::1\]|::1)", a)]
        rows.append({"item": "Port %s" % n, "result": "%s; lauscht auf %s%s" % (", ".join(desc) or "?", ", ".join(addrs),
                                                                               " (öffentlich)" if public else " (nur lokal)"),
                     "state": state})
    return rows


SHELL_RX = re.compile(r"eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|strrev)\s*\(|assert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)"
                      r"|(system|passthru|shell_exec|exec|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)"
                      r"|\$_(POST|GET|REQUEST|COOKIE)\[[^]]+\]\s*\(|FilesMan|c99shell|r57shell|b374k|WSO [0-9]"
                      r"|\$GLOBALS\[.{0,40}\]\[[0-9]+\]\(|move_uploaded_file\s*\(|file_put_contents\s*\([^;]{0,80}\$_(GET|POST|REQUEST)", re.I)


def phpscan(paths):
    """PHP-Dateien auf Schadcode prüfen: typische Webshell-Muster und Virenscanner."""
    rows, files = [], [p for p in paths if os.path.isfile(p)]
    clam = {}
    if files:
        if shutil.which("clamdscan"):
            rc, out = run(["clamdscan", "--fdpass", "--no-summary"] + files, 300)
        elif shutil.which("clamscan"):
            rc, out = run(["nice", "-n", "19", "clamscan", "--no-summary"] + files, 600)
        else:
            out = ""
        for line in out.splitlines():
            m = re.match(r"^(.*): (.+) FOUND$", line)
            if m:
                clam[m.group(1)] = m.group(2)
    for p in paths:
        if not os.path.isfile(p):
            rows.append({"item": p, "result": "existiert nicht (mehr)", "state": "info"})
            continue
        try:
            with open(p, "rb") as f:
                txt = f.read(1 << 20).decode("utf-8", "replace")
        except OSError:
            txt = ""
        st = os.stat(p)
        try:
            own = pwd.getpwuid(st.st_uid).pw_name
        except KeyError:
            own = str(st.st_uid)
        first = next((l.strip() for l in txt.splitlines() if l.strip()), "")[:70]
        hits = sorted(set(m.group(0)[:40] for m in SHELL_RX.finditer(txt)))[:3]
        info = "%d Bytes, Besitzer %s, geändert %s; erste Zeile: %s" % (
            st.st_size, own, time.strftime("%d.%m.%Y %H:%M", time.localtime(st.st_mtime)), first or "(leer)")
        if p in clam:
            rows.append({"item": p, "result": "VIRENSCANNER: %s – %s" % (clam[p], info), "state": "bad"})
        elif hits:
            rows.append({"item": p, "result": "verdächtige Befehle: %s – %s" % (", ".join(hits), info), "state": "bad"})
        elif re.search(r"base64_decode|gzinflate|eval\s*\(|\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x", txt, re.I):
            rows.append({"item": p, "result": "enthält verschleierten Code (eval/base64) – genauer ansehen – " + info, "state": "warn"})
        else:
            rows.append({"item": p, "result": "keine Schadcode-Muster gefunden – " + info, "state": "ok"})
    return rows


# ------------------------------------------------------------ chkrootkit-Meldungen einordnen ---
NET_PROGS = {"systemd-networkd", "dhclient", "dhcpcd", "NetworkManager", "wpa_supplicant", "lldpd", "tcpdump",
             "keepalived", "systemd-resolved", "dnsmasq", "arpwatch", "suricata", "snort", "fail2ban-server", "wireshark"}


def collabora_dirs():
    """Entpackte Collabora-AppImages in /tmp, deren Ordnername der MD5-Prüfsumme eines AppImage aus einer Nextcloud entspricht."""
    pats = ["/home/*/public_html/*/apps/richdocumentscode*/collabora/*.AppImage",
            "/home/*/public_html/apps/richdocumentscode*/collabora/*.AppImage",
            "/home/*/domains/*/public_html/*/apps/richdocumentscode*/collabora/*.AppImage",
            "/home/*/domains/*/public_html/apps/richdocumentscode*/collabora/*.AppImage",
            "/var/www/*/apps/richdocumentscode*/collabora/*.AppImage", "/var/www/*/*/apps/richdocumentscode*/collabora/*.AppImage",
            "/srv/*/apps/richdocumentscode*/collabora/*.AppImage"]
    sums = {}
    for pat in pats:
        for ai in glob.glob(pat):
            try:
                h = hashlib.md5()
                with open(ai, "rb") as f:
                    for b in iter(lambda: f.read(1 << 20), b""):
                        h.update(b)
                sums[h.hexdigest()] = ai
            except OSError:
                pass
    return {"/tmp/appimage_extracted_" + k: v for k, v in sums.items()}


def proc_check(pid, debs):
    """(Zustand, Text) für einen von chkrootkit genannten Prozess: Programm, Paket, Vergleich mit dem Original."""
    try:
        exe = os.readlink("/proc/%s/exe" % pid)
        comm = open("/proc/%s/comm" % pid).read().strip()
    except OSError:
        return "info", "Prozess %s läuft nicht mehr" % pid
    pkg = owner_pkg(exe)
    if not pkg:
        return "bad", "%s (PID %s, %s) gehört zu keinem Paket" % (comm, pid, exe)
    d, ver = debs.get(pkg)
    known = " – nutzt Netzwerkpakete von Berufs wegen (z. B. DHCP)" if comm in NET_PROGS or os.path.basename(exe) in NET_PROGS else ""
    if d:
        orig = next((c for c in (d + exe, d + exe.replace("/usr", "", 1), d + "/usr" + exe) if os.path.isfile(c)), None)
        if orig and sha256(exe) == sha256(orig):
            return "ok", "%s (PID %s): %s aus Paket %s %s, identisch mit dem Original%s" % (comm, pid, exe, pkg, ver, known)
        if orig:
            return "bad", "%s (PID %s): %s WEICHT AB vom Original aus %s %s" % (comm, pid, exe, pkg, ver)
    rc, out = run(["dpkg", "--verify", pkg], 120)
    changed = any(l.endswith(" " + exe) for l in out.splitlines())
    return ("bad" if changed else "warn"), "%s (PID %s): %s aus Paket %s – Original nicht ladbar, laut lokaler Prüfsumme %s%s" % (
        comm, pid, exe, pkg, "VERÄNDERT" if changed else "unverändert", known)


def chk_classify(infile, outfile):
    """chkrootkit-Abschnitte („WARNING: …“) einzeln bewerten und als Befunde ausgeben (F/D-Zeilen)."""
    lines = [l.rstrip("\n") for l in open(infile, errors="replace")]
    sections, cur, rest = [], None, []
    for l in lines:
        if cur is None and l.strip() and not l.startswith("WARNING: ") and \
                not re.search(r"INFECTED|not (found|tested|infected)|nothing (found|detected)|^RTNETLINK answers", l, re.I):
            rest.append(l.strip())
            continue
        if l.startswith("WARNING: "):
            cur = [l[9:].rstrip(":"), []]
            sections.append(cur)
            # ifpromisc schreibt die Meldung teils in dieselbe Zeile
        elif cur is not None and l.strip() and not re.search(r"INFECTED|not infected|not found|nothing found", l):
            cur[1].append(l.strip())
        elif not l.strip():
            cur = None
    out, debs, cdirs = [], Debs(), None

    def emit(sev, msg, details):
        out.append("F\t%s\t%s" % (sev, msg))
        out.extend("D\t" + d for d in details[:12])
        if len(details) > 12:
            out.append("D\t… und %d weitere" % (len(details) - 12))
    try:
        for head, items in sections:
            if head.startswith("The following suspicious files and directories were found"):
                ok, bad, other = [], [], []
                for it in items:
                    m = re.match(r"^(/\S.*?) \[From Debian package: ([^\]]+)\]$", it)
                    if m and owner_pkg(m.group(1)):
                        path, pkg = m.group(1), owner_pkg(m.group(1))
                        rc, vo = run(["dpkg", "--verify", pkg], 120)
                        (bad if any(x.endswith(" " + path) for x in vo.splitlines()) else ok).append("%s (%s)" % (path, pkg))
                    else:
                        other.append(re.sub(r" \[Not from a Debian package\]$", "", it))
                if ok:
                    emit("INFO", "chkrootkit: %d versteckte Dateien gehören zu Ubuntu-Paketen und sind unverändert (harmlos)" % len(ok), ok)
                if bad:
                    emit("HOCH", "chkrootkit: versteckte Paketdateien wurden verändert", bad + ["Vergleich: sudo dpkg --verify <paket>"])
                if other:
                    emit("MITTEL", "chkrootkit: versteckte Dateien, die zu keinem Paket gehören", other +
                         ["Erklärbar (z. B. eigene Konfiguration)? Sonst Inhalt prüfen: ls -la <pfad>; sudo head <pfad>"])
            elif head.startswith("Possible Linux.Xor.DDoS"):
                if cdirs is None:
                    cdirs = collabora_dirs()
                ok, bad = [], []
                for it in items:
                    path = re.sub(r" \[(Not from|From) a? ?Debian package.*\]$", "", it)
                    cd = next((d for d in cdirs if path.startswith(d + "/")), None)
                    if cd:
                        ok.append(path)
                        continue
                    m = re.match(r"^/tmp/coolwsd\.[^/]+/systemplate(/.+)$", path)
                    if m and os.path.isfile(m.group(1)) and os.path.isfile(path) and sha256(path) == sha256(m.group(1)):
                        ok.append(path)
                        continue
                    bad.append(path)
                if ok:
                    emit("INFO", "chkrootkit „Linux.Xor.DDoS“: %d Dateien gehören zu Collabora Online (Nextcloud Office) – geprüft, harmlos" % len(ok),
                         ok[:3] + ["AppImage-Ordner per MD5-Prüfsumme der Original-Datei bestätigt; Systemvorlage byte-gleich mit den Systemdateien"])
                if bad:
                    emit("HOCH", "chkrootkit „Linux.Xor.DDoS“: Programmdateien in /tmp ohne bekannte Herkunft", bad +
                         ["chkrootkit meldet jede ausführbare Datei in /tmp; Herkunft klären (Prüfen-Knopf zeigt Besitzer, Datum, Paket)"])
            elif head.startswith("Possible Linux BPFDoor"):
                res = []
                for it in items:
                    m = re.match(r"^/proc/(\d+)/", it)
                    if m:
                        res.append(proc_check(m.group(1), debs))
                st = {r[0] for r in res}
                if res and st == {"info"}:
                    emit("INFO", "chkrootkit „BPFDoor“: Prozess läuft nicht mehr – beim nächsten Scan erneut prüfen", [r[1] for r in res])
                elif res and st <= {"ok", "info"}:
                    emit("INFO", "chkrootkit „BPFDoor“: Fehlalarm – Prozess ist ein unverändertes Ubuntu-Programm", [r[1] for r in res] +
                         ["chkrootkit erkennt BPFDoor an einem Warte-Zustand im Netzwerkcode, den auch normale Netzwerkdienste haben"])
                elif res:
                    emit("KRITISCH" if "bad" in st else "MITTEL", "chkrootkit „BPFDoor“: Prozess genauer prüfen", [r[1] for r in res])
            elif head.startswith("Output from ifpromisc"):
                res = []
                for it in items:
                    for exe, pid in re.findall(r"([^\s(\[,]+)\[(\d+)\]", it):
                        res.append(proc_check(pid, debs))
                st = {r[0] for r in res}
                if res and st == {"info"}:
                    emit("INFO", "chkrootkit „Packet Sniffer“: Prozess läuft nicht mehr – beim nächsten Scan erneut prüfen", [r[1] for r in res])
                elif res and st <= {"ok", "info"}:
                    emit("INFO", "chkrootkit „Packet Sniffer“: Fehlalarm – Netzwerkdienst aus einem unveränderten Ubuntu-Paket",
                         [r[1] for r in res] + ["chkrootkit meldet jedes Programm mit Rohzugriff aufs Netzwerk; DHCP-Dienste brauchen das"])
                elif res:
                    emit("KRITISCH" if "bad" in st else "MITTEL", "chkrootkit „Packet Sniffer“: Programm genauer prüfen", [r[1] for r in res])
            else:
                emit("MITTEL", "chkrootkit: " + head[:150], items or ["(ohne weitere Angaben)"])
        if rest:
            emit("MITTEL", "chkrootkit meldet weitere Auffälligkeiten (oft harmlos, bitte prüfen)", rest)
    finally:
        debs.close()
    with open(outfile, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + ("\n" if out else ""))


def main():
    if len(sys.argv) >= 4 and sys.argv[1] == "chkrootkit-classify":
        chk_classify(sys.argv[2], sys.argv[3])
        return
    if len(sys.argv) < 4:
        sys.exit(2)
    kind, out, args = sys.argv[1], sys.argv[2], sys.argv[3:21]
    if kind == "binaries":
        args = [a for a in args if NAME_RX.match(a)]
        paths, labels = [], []
        for a in args:
            p = next((d + a for d in ("/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/") if os.path.exists(d + a)), None)
            if p:
                paths.append(p)
                labels.append(a)
        rows = compare(paths, labels)
    elif kind == "pkgfiles":
        rows = compare([a for a in args if PATH_RX.match(a) and "/../" not in a])
    elif kind == "fileinfo":
        rows = fileinfo([a for a in args if PATH_RX.match(a) and "/../" not in a])
    elif kind == "phpscan":
        rows = phpscan([a for a in args if PATH_RX.match(a) and "/../" not in a])
    elif kind == "ports":
        rows = ports([a for a in args if PORT_RX.match(a)])
    else:
        sys.exit(2)
    states = {r["state"] for r in rows}
    verdict = "bad" if "bad" in states else "warn" if "warn" in states else "ok" if states == {"ok"} else "info"
    summary = {"ok": "Alles in Ordnung – keine Auffälligkeit gefunden.",
               "warn": "Nicht eindeutig – bitte die markierten Zeilen ansehen.",
               "bad": "Abweichung gefunden – bitte die Notfall-Hinweise befolgen.",
               "info": "Ergebnis der Prüfung:"}[verdict]
    doc = {"kind": kind, "time": int(time.time()), "verdict": verdict, "summary": summary, "rows": rows}
    tmp = out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False)
    os.replace(tmp, out)


if __name__ == "__main__":
    main()
