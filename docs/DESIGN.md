# ubusec – Gestaltung der Projektseite

Leitidee: **Gerätefront.** Seite und Weboberfläche sehen aus wie die Frontplatte eines Messgeräts: graues Gehäuse,
dunkles Typenschild oben, dichte Raster, Messwerte und Befehle in Festbreite. Die Projektseite übernimmt Farben,
Schriften und Logo der Weboberfläche (`web/static/app.css`), damit Seite und Programm zusammengehören. Farbe gibt es
nur für Links/Aktionen und – wie im Programm – für Zustand und Schweregrad. Keine Verläufe, kein Glas-Effekt,
keine weichen Schatten, keine Emoji, keine drei gleichen Kacheln.

## Farbe

| Name | Hell | Dunkel | Rolle |
|---|---|---|---|
| `--paper` | `#dfe3e7` | `#171c21` | Gehäuse, Seitenhintergrund |
| `--surface` | `#eef1f3` | `#1e252c` | Anzeigefelder: Band, Knöpfe, Screenshot-Hintergrund |
| `--ink` | `#1b2127` | `#e1e6ea` | Text, Überschriften |
| `--muted` | `#56616c` | `#97a3ae` | Nebentext, Bildunterschriften |
| `--line` / `--line-strong` | `#b4bcc4` / `#7d8893` | `#313b45` / `#56636f` | Linien, Rahmen |
| `--action` | `#1f5c9a` | `#7cb2ea` | Links, Hauptknopf, Fokusrahmen (Signalblau) |
| `--plate` | `#1b2127` | `#0f1317` | Typenschild (Kopfzeile) und Befehlsblöcke |
| `--code-bg` | `#d6dce1` | `#262f38` | Inline-Code |

Kontrast: `--ink` auf `--paper` ≈ 12:1, `--muted` auf `--paper` ≈ 4,9:1, `--action` auf `--paper` ≈ 5,2:1.

## Schrift

- **Barlow Semi Condensed** (600, 700) für Überschriften und Namen, **Barlow** (400, 600) für Text,
  **Red Hat Mono** (400) für Befehle, Pfade und Messwerte – alle liegen im Repo (SIL Open Font License).
- Größen: 14 · 16 (Fließtext) · 18 · 22 · 28 · 44 px; Zeilenhöhe 1.6 für Text, 1.1 für große Überschriften.
- Textbreite höchstens 68 Zeichen; Seitenbreite 1080 px.

## Abstände und Form

- 4-px-Raster: 4 · 8 · 12 · 16 · 24 · 32 · 48 · 72. Abschnitte 72 px (Handy 48 px).
- Radius 2 px (Knöpfe, Codeblöcke), 3 px (Screenshot-Rahmen). Keine Schatten; Screenshots bekommen eine kräftige Linie.

## Bausteine

- Knöpfe: primär (`--action` gefüllt), sekundär (Rahmen `--line`), jeweils mit sichtbarem Fokusrahmen.
- Codeblock auf dunklem Typenschild mit „Kopieren“-Knopf (Red Hat Mono).
- Prüfliste in zwei Spalten mit kräftiger Linie über jedem Punkt; Werkzeuge darunter in Festbreite.
- Kopfzeile: dunkles Typenschild mit Logo (Schild mit Haken) + Name, rechts Prüfungen, Installation, GitHub.
  Fußzeile: Lizenz, Copyright, Links.

## Bilder

- Echte Screenshots der Weboberfläche mit **Beispieldaten** (`server.example.de`, so beschriftet), hell und dunkel,
  als WebP in doppelter Auflösung.
- Keine Stockfotos, keine Illustrationen, keine Icon-Sammlung – das Schild-Logo genügt.
