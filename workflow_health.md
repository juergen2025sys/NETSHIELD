# Workflow Health Report

**Stand:** 2026-06-02 04:57 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 8 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 1
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-06-01 07:23 UTC -> 2026-06-01 11:53 UTC (269 min)
  - 2026-06-01 12:26 UTC -> 2026-06-01 18:13 UTC (346 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 62
- **Skip-Runs:** 55
- **Fehlgeschlagene Runs:** 27
- **Lucken >210min:** 7
- **Groesste Lucke:** 2026-05-28 21:59 UTC -> 2026-05-29 04:36 UTC (397 min = 6h 37min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 76
- **Watchdog-Fehler:** 2
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 35

Letzte Watchdog-Eingriffe:
- 2026-05-31 21:45 UTC (Run #26725358435, Laufzeit 24m 49s)
- 2026-06-01 02:00 UTC (Run #26731265765, Laufzeit 25m 11s)
- 2026-06-01 06:58 UTC (Run #26740075245, Laufzeit 24m 38s)
- 2026-06-01 21:47 UTC (Run #26784030033, Laufzeit 24m 30s)
- 2026-06-02 01:36 UTC (Run #26792947537, Laufzeit 25m 35s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-05-31 05:09 UTC - cancelled - Run #26703939050 (4s)
- 2026-05-31 08:00 UTC - cancelled - Run #26707155296 (8m 8s)
- 2026-05-31 19:47 UTC - cancelled - Run #26722679497 (6m 30s)
- 2026-05-31 19:53 UTC - cancelled - Run #26722826689 (4s)
- 2026-06-01 05:23 UTC - cancelled - Run #26736785118 (7m 23s)
- 2026-06-01 05:30 UTC - cancelled - Run #26737010438 (4s)
- 2026-06-01 18:22 UTC - cancelled - Run #26773615146 (5m 54s)
- 2026-06-01 18:28 UTC - cancelled - Run #26773916488 (7s)
- 2026-06-01 21:47 UTC - cancelled - Run #26784057532 (6m 15s)
- 2026-06-01 21:53 UTC - cancelled - Run #26784354955 (5s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
