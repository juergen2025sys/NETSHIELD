# Workflow Health Report

**Stand:** 2026-06-12 20:22 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 11 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 6
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-06-12 15:59 UTC -> 2026-06-12 19:29 UTC (210 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 69
- **Skip-Runs:** 68
- **Fehlgeschlagene Runs:** 22
- **Lucken >210min:** 9
- **Groesste Lucke:** 2026-06-05 22:07 UTC -> 2026-06-06 02:31 UTC (263 min = 4h 23min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 191
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 44

Letzte Watchdog-Eingriffe:
- 2026-06-11 22:16 UTC (Run #27380908858, Laufzeit 20m 36s)
- 2026-06-12 01:40 UTC (Run #27388927796, Laufzeit 21m 10s)
- 2026-06-12 06:56 UTC (Run #27399981584, Laufzeit 21m 15s)
- 2026-06-12 12:28 UTC (Run #27415668053, Laufzeit 21m 27s)
- 2026-06-12 19:29 UTC (Run #27438229233, Laufzeit 20m 56s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-06-09 15:36 UTC - cancelled - Run #27217535905 (8m 4s)
- 2026-06-09 15:44 UTC - cancelled - Run #27218026088 (2m 44s)
- 2026-06-10 04:55 UTC - cancelled - Run #27254161716 (6m 6s)
- 2026-06-10 15:59 UTC - failure - Run #27288776680 (21m 19s)
- 2026-06-10 16:26 UTC - cancelled - Run #27290192234 (12m 6s)
- 2026-06-11 05:07 UTC - cancelled - Run #27325175029 (5m 31s)
- 2026-06-12 05:12 UTC - cancelled - Run #27396013364 (4m 7s)
- 2026-06-12 10:46 UTC - cancelled - Run #27410903213 (6m 3s)
- 2026-06-12 10:52 UTC - cancelled - Run #27411175233 (5m 57s)
- 2026-06-12 15:45 UTC - cancelled - Run #27426476111 (9m 12s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
