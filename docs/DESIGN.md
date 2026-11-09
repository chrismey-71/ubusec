# ubusec – Gestaltung der Projektseite

Leitidee: **Prüfprotokoll.** Die Seite sieht aus wie ein sauber gesetzter technischer Bericht, nicht wie
Werbung. Sie übernimmt Farben, Schriften und Logo der Weboberfläche, damit Seite und Programm
zusammengehören. Farbe gibt es nur für Links/Aktionen und – wie im Programm – für Schweregrade.
Keine Verläufe, kein Glas-Effekt, keine Emoji, keine drei gleichen Kacheln.

## Farbe (Werte wie in `web/static/app.css`)

| Name | Hell | Dunkel | Rolle |
|---|---|---|---|
| `--paper` | `#e8edf1` | `#0e1520` | Seitenhintergrund |
| `--surface` | `#f7f9fb` | `#151e2b` | Flächen: Codeblöcke, Tabellen, Screenshot-Rahmen |
| `--ink` | `#15233c` | `#e2e8f0` | Text, Überschriften |
| `--muted` | `#56627a` | `#94a1b5` | Nebentext, Bildunterschriften |
| `--line` | `#c8d1db` | `#283548` | Linien, Rahmen |
| `--action` | `#1d58a3` | `#6fa2e6` | Links, Hauptknopf, Fokusrahmen |
| `--code-bg` | `#dfe6ed` | `#1f2a3a` | Inline-Code |
| `--krit` `--hoch` `--mittel` `--niedrig` `--ok` | wie Programm | wie Programm | nur in der Schweregrad-Legende |

Kontrast: `--ink` auf `--paper` ≈ 13:1, `--muted` auf `--paper` ≈ 5,2:1, `--action` auf `--paper` ≈ 5,9:1.

## Schrift

- **Instrument Sans** (400, 700) für alles, **Red Hat Mono** (400) für Befehle und Pfade – beide liegen im Repo.
- Größen: 14 · 16 (Fließtext) · 18 · 22 · 28 · 40 px; Zeilenhöhe 1.6 für Text, 1.15 für große Überschriften.
- Textbreite höchstens 68 Zeichen; Seitenbreite 1080 px.

## Abstände und Form

- 4-px-Raster: 4 · 8 · 12 · 16 · 24 · 32 · 48 · 72. Abschnitte 72 px (Handy 48 px).
- Radius 6 px (Knöpfe, Codeblöcke), 10 px (Screenshot-Rahmen). Ein Schatten nur für Screenshots.

## Bausteine

- Knöpfe: primär (`--action` gefüllt), sekundär (Rahmen `--line`), jeweils mit sichtbarem Fokusrahmen.
- Codeblock mit „Kopieren“-Knopf (Red Hat Mono, `--surface`, Rahmen `--line`).
- Tabellen wie im README, linksbündig, dünne Linien.
- Kopfzeile: Logo (Schild mit Haken) + Name, rechts GitHub. Fußzeile: Lizenz, Copyright, Links.

## Bilder

- Echte Screenshots der Weboberfläche mit **Beispieldaten** (so beschriftet), hell und dunkel.
- Keine Stockfotos, keine Illustrationen, keine Icon-Sammlung – das Schild-Logo genügt.
