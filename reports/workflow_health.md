# Workflow Health Report

**Stand:** 2026-07-08 19:49 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 12 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 9
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 68
- **Skip-Runs:** 86
- **Fehlgeschlagene Runs:** 27
- **Lucken >210min:** 6
- **Groesste Lucke:** 2026-07-06 04:52 UTC -> 2026-07-06 09:36 UTC (283 min = 4h 43min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 226
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 50

Letzte Watchdog-Eingriffe:
- 2026-07-08 06:39 UTC (Run #28922903545, Laufzeit 21m 10s)
- 2026-07-08 12:58 UTC (Run #28944437549, Laufzeit 26m 53s)
- 2026-07-08 15:42 UTC (Run #28955632902, Laufzeit 10m 40s)
- 2026-07-08 16:50 UTC (Run #28960157544, Laufzeit 21m 2s)
- 2026-07-08 18:45 UTC (Run #28967279175, Laufzeit 26m 0s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-07-07 04:30 UTC - cancelled - Run #28841655523 (6m 34s)
- 2026-07-07 10:14 UTC - cancelled - Run #28858661349 (18m 39s)
- 2026-07-07 15:22 UTC - cancelled - Run #28877800454 (11m 49s)
- 2026-07-08 03:52 UTC - cancelled - Run #28916179136 (6m 4s)
- 2026-07-08 03:58 UTC - cancelled - Run #28916396450 (3m 7s)
- 2026-07-08 09:04 UTC - cancelled - Run #28930839109 (6m 44s)
- 2026-07-08 11:30 UTC - cancelled - Run #28939226442 (17m 28s)
- 2026-07-08 15:42 UTC - cancelled - Run #28955632902 (10m 40s)
- 2026-07-08 16:55 UTC - cancelled - Run #28960455660 (14m 32s)
- 2026-07-08 17:09 UTC - cancelled - Run #28961343599 (1m 48s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
