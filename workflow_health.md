# Workflow Health Report

**Stand:** 2026-05-30 14:00 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 15
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 68
- **Skip-Runs:** 70
- **Fehlgeschlagene Runs:** 17
- **Lucken >210min:** 7
- **Groesste Lucke:** 2026-05-28 21:59 UTC -> 2026-05-29 04:36 UTC (397 min = 6h 37min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 77
- **Watchdog-Fehler:** 1
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 38

Letzte Watchdog-Eingriffe:
- 2026-05-29 22:03 UTC (Run #26664515229, Laufzeit 14m 7s)
- 2026-05-30 01:29 UTC (Run #26670708119, Laufzeit 24m 1s)
- 2026-05-30 07:50 UTC (Run #26678502202, Laufzeit 24m 47s)
- 2026-05-30 09:48 UTC (Run #26680775839, Laufzeit 23m 34s)
- 2026-05-30 11:48 UTC (Run #26683037133, Laufzeit 23m 51s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-05-27 04:54 UTC - cancelled - Run #26491591427 (10m 8s)
- 2026-05-27 05:04 UTC - cancelled - Run #26491921676 (5s)
- 2026-05-27 16:22 UTC - cancelled - Run #26524034981 (5m 17s)
- 2026-05-27 16:28 UTC - cancelled - Run #26524321235 (10s)
- 2026-05-27 22:55 UTC - cancelled - Run #26543576226 (9m 13s)
- 2026-05-27 23:04 UTC - cancelled - Run #26543935463 (5s)
- 2026-05-28 16:37 UTC - cancelled - Run #26588251011 (6m 21s)
- 2026-05-28 16:43 UTC - cancelled - Run #26588591330 (7s)
- 2026-05-30 04:32 UTC - cancelled - Run #26674562614 (7m 24s)
- 2026-05-30 04:39 UTC - cancelled - Run #26674707879 (3s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
