// ubusec – kleine Helfer. Die Oberfläche funktioniert auch ohne JavaScript;
// dieses Skript ergänzt Live-Fortschritt, Filter und Kopieren.
(function () {
  "use strict";
  const body = document.body;

  // Bestätigung vor heiklen Aktionen
  document.addEventListener("click", (e) => {
    const b = e.target.closest("[data-confirm]");
    if (b && !window.confirm(b.dataset.confirm)) e.preventDefault();
  });

  // Befehle kopieren
  document.addEventListener("click", async (e) => {
    const b = e.target.closest(".copy");
    if (!b) return;
    try {
      await navigator.clipboard.writeText(b.dataset.copy);
      const t = b.textContent; b.textContent = "Kopiert"; setTimeout(() => (b.textContent = t), 1500);
    } catch (_) { /* z. B. ohne HTTPS: Text bleibt markierbar */ }
  });

  // Klick auf ein Feld der Befundleiste öffnet den Befund
  document.addEventListener("click", (e) => {
    const a = e.target.closest(".strip .cell");
    if (!a) return;
    const d = document.querySelector(a.getAttribute("href"));
    if (d && d.tagName === "DETAILS") d.open = true;
  });
  if (location.hash) {
    const d = document.querySelector(location.hash);
    if (d && d.tagName === "DETAILS") d.open = true;
  }

  // Scan-Formular: Bereiche nur bei „Ausgewählte Bereiche“ zeigen
  const form = document.querySelector(".scan-form");
  if (form) {
    const mods = document.getElementById("modules");
    const sync = () => { mods.hidden = form.querySelector("input[name=kind]:checked").value !== "custom"; };
    form.addEventListener("change", sync); sync();
  }

  // Scan-Einstellungen: Warnung, wenn mehr clamscan-Prozesse gewählt sind, als in die Speichergrenze passen
  const par = document.getElementById("clam-parallel");
  const parWarn = document.getElementById("clam-parallel-warn");
  if (par && parWarn) {
    const eng = par.form && par.form.querySelector("select[name=CLAM_ENGINE]");
    const check = () => {
      const viaClamd = par.dataset.clamd === "1" && (!eng || eng.value === "auto");
      parWarn.hidden = viaClamd || Number(par.value) <= Number(par.dataset.fit || 1);
    };
    par.addEventListener("change", check);
    if (eng) eng.addEventListener("change", check);
    check();
  }

  // Nachprüfung auf Knopfdruck: auf das Ergebnis warten, dann neu laden
  document.querySelectorAll(".verify[data-pending='1']").forEach((box) => {
    const det = box.closest("details"); if (det) det.open = true;
    const poll = async () => {
      try {
        const r = await fetch("/api/pruefung/" + box.dataset.vid, { credentials: "same-origin" });
        const j = await r.json();
        if (!j.pending) { location.reload(); return; }
      } catch (_) { /* später erneut */ }
      setTimeout(poll, 2500);
    };
    setTimeout(poll, 2000);
  });

  // Empfehlungen: nach Aufwand ordnen und filtern
  const ebar = document.getElementById("effort-bar");
  if (ebar) {
    ebar.hidden = false;
    const flat = document.getElementById("effort-flat");
    const items = Array.from(document.querySelectorAll(".sev-group details.finding"));
    const home = new Map(items.map((el) => [el, { parent: el.parentNode, next: el.nextSibling }]));
    const sevRank = { KRITISCH: 0, HOCH: 1, MITTEL: 2, NIEDRIG: 3 };
    const KEY = "ubusec-effort";
    try {
      const saved = JSON.parse(localStorage.getItem(KEY) || "null");
      if (saved) {
        ebar.querySelector("input[value=" + saved.order + "]").checked = true;
        ebar.querySelectorAll("input[name=eg]").forEach((c) => { c.checked = saved.groups.includes(c.value); });
      }
    } catch (_) { /* ohne gespeicherte Auswahl */ }
    const applyEffort = () => {
      const order = ebar.querySelector("input[name=order]:checked").value;
      const groups = Array.from(ebar.querySelectorAll("input[name=eg]:checked")).map((c) => c.value);
      try { localStorage.setItem(KEY, JSON.stringify({ order, groups })); } catch (_) { /* egal */ }
      if (order === "effort") {
        items.slice().sort((a, b) => (+a.dataset.effort - +b.dataset.effort) || (sevRank[a.dataset.sev] - sevRank[b.dataset.sev]))
          .forEach((el) => flat.appendChild(el));
      } else {
        items.forEach((el) => { const h = home.get(el); h.parent.appendChild(el); });
        // ursprüngliche Reihenfolge wiederherstellen
        items.forEach((el) => home.get(el).parent.appendChild(el));
      }
      let shown = 0;
      items.forEach((el) => { el.hidden = !groups.includes(el.dataset.egroup); if (!el.hidden) shown++; });
      flat.hidden = order !== "effort";
      document.querySelectorAll(".sev-group").forEach((sec) => {
        sec.hidden = order === "effort" || !sec.querySelector("details.finding:not([hidden])");
      });
      document.getElementById("effort-count").textContent = shown + " von " + items.length + " Punkten";
    };
    ebar.addEventListener("change", applyEffort);
    applyEffort();
  }

  // Berichtsfilter
  const filters = document.getElementById("filters");
  if (filters) {
    filters.hidden = false;
    const apply = () => {
      const on = new Set([...filters.querySelectorAll("input[value]:checked")].map((i) => i.value));
      const onlyNew = document.getElementById("only-new").checked;
      document.querySelectorAll(".mod").forEach((sec) => {
        let shown = 0;
        sec.querySelectorAll(".finding").forEach((f) => {
          const v = on.has(f.dataset.sev) && (!onlyNew || f.dataset.new === "1");
          f.hidden = !v; if (v) shown++;
        });
        sec.classList.toggle("is-empty", sec.querySelector(".finding") !== null && shown === 0);
      });
    };
    filters.addEventListener("change", apply);
  }

  // Live-Status des Scans
  const url = body.dataset.statusUrl;
  if (!url) return;

  // Einstellungen: neu laden, sobald root die Änderung übernommen hat
  const pending = document.getElementById("ctl-pending");
  if (pending) {
    const check = async () => {
      try {
        const st = await (await fetch(url, { credentials: "same-origin" })).json();
        if (!st.ctl_pending) { window.location.reload(); return; }
      } catch (_) { /* weiter versuchen */ }
      setTimeout(check, 1500);
    };
    setTimeout(check, 1200);
  }
  const pill = document.getElementById("running-pill");
  const box = document.getElementById("progress-box");
  let wasRunning = box ? box.dataset.running === "1" : false;
  let timer = null;
  let idlePolls = 0;

  async function poll() {
    let st;
    try {
      const r = await fetch(url, { headers: { "Accept": "application/json" }, credentials: "same-origin" });
      if (r.redirected || !r.ok) return schedule(30000);
      st = await r.json();
    } catch (_) { return schedule(15000); }
    const busy = st.running || st.queued;
    if (pill) pill.hidden = !busy || !!box;
    if (box && busy) {
      document.getElementById("pg-title").textContent = st.running ? st.label + " läuft" : "Scan wird gestartet …";
      const bar = document.getElementById("pg-bar");
      bar.max = st.total || 1; bar.value = st.running ? Math.max(0, st.index - 1) : 0;
      document.getElementById("pg-text").textContent = st.running
        ? "Schritt " + st.index + " von " + st.total + ": " + st.module_title
        : "Warte auf den Start …";
    }
    const sub = document.getElementById("pg-sub");
    if (box && sub && busy) {
      const hasSub = st.running && (st.sub_total > 0 || st.sub_text);
      sub.hidden = !hasSub;
      if (hasSub) {
        const sb = document.getElementById("pg-subbar");
        sb.max = st.sub_total || 1; sb.value = st.sub_done || 0; sb.hidden = !st.sub_total;
        const fmt = (n) => Number(n || 0).toLocaleString("de-AT");
        let t = st.sub_total ? fmt(st.sub_done) + " von " + fmt(st.sub_total) + " Dateien" : "";
        if (st.sub_total && st.sub_done > 0 && st.sub_start) {
          const pct = Math.floor(100 * st.sub_done / st.sub_total);
          const secs = (Date.now() / 1000 - st.sub_start) * (st.sub_total - st.sub_done) / st.sub_done;
          const rest = secs < 90 ? "unter 2 Minuten" : secs < 5400 ? "etwa " + Math.round(secs / 60) + " Minuten"
                     : "etwa " + (secs / 3600).toFixed(1).replace(".", ",") + " Stunden";
          t += " (" + pct + " %, noch " + rest + ")";
        }
        document.getElementById("pg-subtext").textContent = t;
        document.getElementById("pg-dir").textContent = st.sub_text || "";
        // Hauptbalken anteilig füllen
        if (st.sub_total) document.getElementById("pg-bar").value = Math.max(0, st.index - 1) + st.sub_done / st.sub_total;
      }
    }
    if (wasRunning && !busy) {
      // erst nach zwei Abfragen ohne Scan neu laden (Übergang Auftrag → Scan überbrücken)
      idlePolls++;
      if (idlePolls >= 2) { window.location.reload(); return; }
      return schedule(2500);
    }
    idlePolls = 0;
    // Scan hat begonnen, die Seite zeigt aber noch keinen Fortschritt → einmal neu laden
    if (busy && !box && document.querySelector(".scan-form")) { window.location.reload(); return; }
    wasRunning = wasRunning || busy;
    schedule(busy ? 3000 : 20000);
  }
  function schedule(ms) { clearTimeout(timer); timer = setTimeout(poll, ms); }
  poll();
})();
