# Workflow Health Report

**Stand:** 2026-05-30 04:13 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 10 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 12
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-05-29 05:04 UTC -> 2026-05-29 08:36 UTC (211 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 70
- **Skip-Runs:** 67
- **Fehlgeschlagene Runs:** 17
- **Lucken >210min:** 8
- **Groesste Lucke:** 2026-05-28 21:59 UTC -> 2026-05-29 04:36 UTC (397 min = 6h 37min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 78
- **Watchdog-Fehler:** 3
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 37

Letzte Watchdog-Eingriffe:
- 2026-05-29 14:32 UTC (Run #26643310877, Laufzeit 19m 17s)
- 2026-05-29 17:55 UTC (Run #26653339440, Laufzeit 25m 18s)
- 2026-05-29 20:05 UTC (Run #26659485325, Laufzeit 24m 34s)
- 2026-05-29 22:03 UTC (Run #26664515229, Laufzeit 14m 7s)
- 2026-05-30 01:29 UTC (Run #26670708119, Laufzeit 24m 1s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-05-26 22:46 UTC - cancelled - Run #26479500493 (8m 46s)
- 2026-05-26 22:54 UTC - cancelled - Run #26479838963 (5s)
- 2026-05-27 04:54 UTC - cancelled - Run #26491591427 (10m 8s)
- 2026-05-27 05:04 UTC - cancelled - Run #26491921676 (5s)
- 2026-05-27 16:22 UTC - cancelled - Run #26524034981 (5m 17s)
- 2026-05-27 16:28 UTC - cancelled - Run #26524321235 (10s)
- 2026-05-27 22:55 UTC - cancelled - Run #26543576226 (9m 13s)
- 2026-05-27 23:04 UTC - cancelled - Run #26543935463 (5s)
- 2026-05-28 16:37 UTC - cancelled - Run #26588251011 (6m 21s)
- 2026-05-28 16:43 UTC - cancelled - Run #26588591330 (7s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
