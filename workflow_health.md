# Workflow Health Report

**Stand:** 2026-06-02 21:21 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 8 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 2
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-06-02 07:21 UTC -> 2026-06-02 10:52 UTC (210 min)
  - 2026-06-02 11:17 UTC -> 2026-06-02 14:53 UTC (215 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 64
- **Skip-Runs:** 50
- **Fehlgeschlagene Runs:** 31
- **Lucken >210min:** 8
- **Groesste Lucke:** 2026-05-28 21:59 UTC -> 2026-05-29 04:36 UTC (397 min = 6h 37min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 79
- **Watchdog-Fehler:** 2
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 36

Letzte Watchdog-Eingriffe:
- 2026-06-02 01:36 UTC (Run #26792947537, Laufzeit 25m 35s)
- 2026-06-02 06:57 UTC (Run #26803796116, Laufzeit 24m 16s)
- 2026-06-02 14:53 UTC (Run #26827951649, Laufzeit 24m 22s)
- 2026-06-02 16:55 UTC (Run #26834927743, Laufzeit 25m 7s)
- 2026-06-02 18:29 UTC (Run #26839908532, Laufzeit 21m 14s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-06-01 18:22 UTC - cancelled - Run #26773615146 (5m 54s)
- 2026-06-01 18:28 UTC - cancelled - Run #26773916488 (7s)
- 2026-06-01 21:47 UTC - cancelled - Run #26784057532 (6m 15s)
- 2026-06-01 21:53 UTC - cancelled - Run #26784354955 (5s)
- 2026-06-02 05:08 UTC - cancelled - Run #26799721689 (7m 57s)
- 2026-06-02 05:16 UTC - cancelled - Run #26799985245 (5s)
- 2026-06-02 11:02 UTC - cancelled - Run #26815509959 (6m 6s)
- 2026-06-02 11:08 UTC - cancelled - Run #26815795532 (5s)
- 2026-06-02 16:59 UTC - cancelled - Run #26835147145 (9m 3s)
- 2026-06-02 17:08 UTC - cancelled - Run #26835627939 (10s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
