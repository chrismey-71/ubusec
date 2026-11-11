# Sicherheit / Security

## Unterstützte Versionen

Sicherheitskorrekturen gibt es nur für die jeweils neueste Version.
Aktualisieren: `sudo ubusec --update`

## Eine Lücke melden

Bitte **kein öffentliches Issue** anlegen. Meldungen bitte vertraulich über
**Security → Report a vulnerability** in diesem Repository
(GitHub Private Vulnerability Reporting).

Hilfreich sind: betroffene Version, Ubuntu-Version, Schritte zum Nachvollziehen
und – falls bekannt – die Auswirkung.

Ich bestätige den Eingang in der Regel innerhalb weniger Tage und melde mich,
sobald eine Korrektur veröffentlicht ist. ubusec ist ein Freizeitprojekt;
feste Reaktionszeiten kann ich nicht zusagen.

*Please report vulnerabilities privately via Security → Report a vulnerability.
Reports in English are welcome.*

## Was besonders interessiert

ubusec läuft als root. Besonders wichtig sind deshalb:

- Wege, über die ein unprivilegierter Benutzer oder eine Website auf dem Server
  über ubusec Root-Rechte erlangt (z. B. über die Auftragswarteschlange, Dateien
  in Webordnern, die ubusec liest, oder Korrekturen mit „Korrigieren“)
- Zugriff auf die Weboberfläche ohne Anmeldung oder von außen
  (sie lauscht nur auf 127.0.0.1)
- Schwächen im Update-Weg (`--update`, Prüfsummen, Releases)

Kein Sicherheitsproblem im Sinne dieser Richtlinie sind Befunde, die ubusec auf
deinem eigenen Server meldet, die sind ja gerade sein Zweck.
