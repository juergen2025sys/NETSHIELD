# Workflow Health Report

**Stand:** 2026-07-24 03:35 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 10 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 12
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 71
- **Skip-Runs:** 88
- **Fehlgeschlagene Runs:** 28
- **Lucken >210min:** 1
- **Groesste Lucke:** 2026-07-19 22:03 UTC -> 2026-07-20 03:54 UTC (351 min = 5h 51min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 270
- **Watchdog-Fehler:** 3
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 42

Letzte Watchdog-Eingriffe:
- 2026-07-23 12:57 UTC (Run #30009146601, Laufzeit 27m 7s)
- 2026-07-23 15:32 UTC (Run #30021026752, Laufzeit 20m 28s)
- 2026-07-23 18:37 UTC (Run #30034534561, Laufzeit 26m 7s)
- 2026-07-23 21:31 UTC (Run #30046514251, Laufzeit 27m 10s)
- 2026-07-24 00:56 UTC (Run #30057609605, Laufzeit 25m 49s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-07-22 04:00 UTC - cancelled - Run #29889926127 (2m 2s)
- 2026-07-22 09:14 UTC - cancelled - Run #29907202157 (17m 53s)
- 2026-07-22 16:38 UTC - cancelled - Run #29938890374 (13s)
- 2026-07-22 22:31 UTC - cancelled - Run #29963169938 (8m 26s)
- 2026-07-23 01:00 UTC - cancelled - Run #29970638495 (25m 49s)
- 2026-07-23 03:51 UTC - cancelled - Run #29978057512 (7m 20s)
- 2026-07-23 03:58 UTC - cancelled - Run #29978360643 (5m 33s)
- 2026-07-23 09:04 UTC - cancelled - Run #29993795143 (4m 39s)
- 2026-07-23 11:22 UTC - cancelled - Run #30002894051 (9m 53s)
- 2026-07-23 11:32 UTC - cancelled - Run #30003522690 (12m 14s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
