# Workflow Health Report

**Stand:** 2026-06-16 21:15 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 10 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 8
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-06-15 22:11 UTC -> 2026-06-16 01:47 UTC (216 min)
  - 2026-06-16 13:26 UTC -> 2026-06-16 17:16 UTC (230 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 68
- **Skip-Runs:** 64
- **Fehlgeschlagene Runs:** 14
- **Lucken >210min:** 7
- **Groesste Lucke:** 2026-06-11 10:11 UTC -> 2026-06-11 14:15 UTC (243 min = 4h 3min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 167
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 40

Letzte Watchdog-Eingriffe:
- 2026-06-16 01:47 UTC (Run #27588525977, Laufzeit 20m 40s)
- 2026-06-16 04:11 UTC (Run #27593599711, Laufzeit 20m 59s)
- 2026-06-16 09:34 UTC (Run #27608292454, Laufzeit 20m 27s)
- 2026-06-16 13:05 UTC (Run #27619611670, Laufzeit 21m 2s)
- 2026-06-16 18:45 UTC (Run #27640183164, Laufzeit 20m 46s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-06-12 05:12 UTC - cancelled - Run #27396013364 (4m 7s)
- 2026-06-12 10:46 UTC - cancelled - Run #27410903213 (6m 3s)
- 2026-06-12 10:52 UTC - cancelled - Run #27411175233 (5m 57s)
- 2026-06-12 15:45 UTC - cancelled - Run #27426476111 (9m 12s)
- 2026-06-13 04:57 UTC - cancelled - Run #27457175275 (6m 15s)
- 2026-06-13 09:41 UTC - cancelled - Run #27463188704 (4m 42s)
- 2026-06-13 09:46 UTC - cancelled - Run #27463289167 (4m 28s)
- 2026-06-13 16:54 UTC - cancelled - Run #27473054418 (8m 26s)
- 2026-06-14 10:01 UTC - cancelled - Run #27495391072 (7m 4s)
- 2026-06-15 12:47 UTC - cancelled - Run #27547250930 (6m 38s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
