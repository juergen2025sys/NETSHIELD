# Workflow Health Report

**Stand:** 2026-07-08 14:35 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 13 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 8
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 67
- **Skip-Runs:** 90
- **Fehlgeschlagene Runs:** 24
- **Lucken >210min:** 6
- **Groesste Lucke:** 2026-07-06 04:52 UTC -> 2026-07-06 09:36 UTC (283 min = 4h 43min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 224
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 49

Letzte Watchdog-Eingriffe:
- 2026-07-07 18:29 UTC (Run #28889366528, Laufzeit 27m 28s)
- 2026-07-07 21:43 UTC (Run #28900776255, Laufzeit 26m 45s)
- 2026-07-08 01:03 UTC (Run #28909810879, Laufzeit 26m 15s)
- 2026-07-08 06:39 UTC (Run #28922903545, Laufzeit 21m 10s)
- 2026-07-08 12:58 UTC (Run #28944437549, Laufzeit 26m 53s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-07-05 04:37 UTC - cancelled - Run #28729658902 (2m 19s)
- 2026-07-05 09:31 UTC - cancelled - Run #28736326627 (10m 47s)
- 2026-07-05 22:09 UTC - cancelled - Run #28756553233 (3m 18s)
- 2026-07-07 04:30 UTC - cancelled - Run #28841655523 (6m 34s)
- 2026-07-07 10:14 UTC - cancelled - Run #28858661349 (18m 39s)
- 2026-07-07 15:22 UTC - cancelled - Run #28877800454 (11m 49s)
- 2026-07-08 03:52 UTC - cancelled - Run #28916179136 (6m 4s)
- 2026-07-08 03:58 UTC - cancelled - Run #28916396450 (3m 7s)
- 2026-07-08 09:04 UTC - cancelled - Run #28930839109 (6m 44s)
- 2026-07-08 11:30 UTC - cancelled - Run #28939226442 (17m 28s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
