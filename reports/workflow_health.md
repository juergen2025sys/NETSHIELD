# Workflow Health Report

**Stand:** 2026-06-20 04:36 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 8 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 7
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-06-19 22:01 UTC -> 2026-06-20 01:51 UTC (230 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 68
- **Skip-Runs:** 63
- **Fehlgeschlagene Runs:** 15
- **Lucken >210min:** 9
- **Groesste Lucke:** 2026-06-18 21:49 UTC -> 2026-06-19 02:06 UTC (256 min = 4h 16min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 167
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 39

Letzte Watchdog-Eingriffe:
- 2026-06-19 07:23 UTC (Run #27811746567, Laufzeit 21m 29s)
- 2026-06-19 12:31 UTC (Run #27825846193, Laufzeit 23m 19s)
- 2026-06-19 18:50 UTC (Run #27843187515, Laufzeit 21m 6s)
- 2026-06-19 21:39 UTC (Run #27849641264, Laufzeit 21m 40s)
- 2026-06-20 01:51 UTC (Run #27856640640, Laufzeit 21m 18s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-06-15 12:47 UTC - cancelled - Run #27547250930 (6m 38s)
- 2026-06-16 21:27 UTC - cancelled - Run #27649317806 (7m 7s)
- 2026-06-17 05:22 UTC - cancelled - Run #27667680318 (2m 52s)
- 2026-06-17 11:20 UTC - cancelled - Run #27685234412 (2m 36s)
- 2026-06-18 05:13 UTC - cancelled - Run #27738275736 (1m 45s)
- 2026-06-19 05:32 UTC - cancelled - Run #27807503538 (7m 0s)
- 2026-06-19 11:01 UTC - cancelled - Run #27821830743 (5m 26s)
- 2026-06-19 11:07 UTC - cancelled - Run #27822080589 (3m 20s)
- 2026-06-19 15:46 UTC - cancelled - Run #27835395108 (6m 38s)
- 2026-06-19 15:53 UTC - cancelled - Run #27835705718 (5m 12s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
