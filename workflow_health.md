# Workflow Health Report

**Stand:** 2026-06-01 18:14 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 2
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-05-31 22:10 UTC -> 2026-06-01 02:00 UTC (230 min)
  - 2026-06-01 07:23 UTC -> 2026-06-01 11:53 UTC (269 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 65
- **Skip-Runs:** 59
- **Fehlgeschlagene Runs:** 23
- **Lucken >210min:** 7
- **Groesste Lucke:** 2026-05-28 21:59 UTC -> 2026-05-29 04:36 UTC (397 min = 6h 37min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 73
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 35

Letzte Watchdog-Eingriffe:
- 2026-05-31 13:06 UTC (Run #26713452525, Laufzeit 23m 51s)
- 2026-05-31 15:58 UTC (Run #26717371289, Laufzeit 19m 43s)
- 2026-05-31 21:45 UTC (Run #26725358435, Laufzeit 24m 49s)
- 2026-06-01 02:00 UTC (Run #26731265765, Laufzeit 25m 11s)
- 2026-06-01 06:58 UTC (Run #26740075245, Laufzeit 24m 38s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-05-30 04:39 UTC - cancelled - Run #26674707879 (3s)
- 2026-05-30 14:12 UTC - cancelled - Run #26685945503 (5m 55s)
- 2026-05-30 14:17 UTC - cancelled - Run #26686069424 (4s)
- 2026-05-31 04:58 UTC - cancelled - Run #26703729739 (11m 19s)
- 2026-05-31 05:09 UTC - cancelled - Run #26703939050 (4s)
- 2026-05-31 08:00 UTC - cancelled - Run #26707155296 (8m 8s)
- 2026-05-31 19:47 UTC - cancelled - Run #26722679497 (6m 30s)
- 2026-05-31 19:53 UTC - cancelled - Run #26722826689 (4s)
- 2026-06-01 05:23 UTC - cancelled - Run #26736785118 (7m 23s)
- 2026-06-01 05:30 UTC - cancelled - Run #26737010438 (4s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
