# Workflow Health Report

**Stand:** 2026-06-03 21:27 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 8 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 4
- **Lucken (>210min zwischen echten Runs):** 3
  - 2026-06-02 21:41 UTC -> 2026-06-03 01:46 UTC (245 min)
  - 2026-06-03 07:25 UTC -> 2026-06-03 11:20 UTC (234 min)
  - 2026-06-03 11:41 UTC -> 2026-06-03 17:07 UTC (326 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 63
- **Skip-Runs:** 51
- **Fehlgeschlagene Runs:** 29
- **Lucken >210min:** 11
- **Groesste Lucke:** 2026-05-28 21:59 UTC -> 2026-05-29 04:36 UTC (397 min = 6h 37min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 84
- **Watchdog-Fehler:** 2
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 35

Letzte Watchdog-Eingriffe:
- 2026-06-02 16:55 UTC (Run #26834927743, Laufzeit 25m 7s)
- 2026-06-02 18:29 UTC (Run #26839908532, Laufzeit 21m 14s)
- 2026-06-03 01:46 UTC (Run #26858747670, Laufzeit 21m 35s)
- 2026-06-03 07:04 UTC (Run #26869202777, Laufzeit 20m 44s)
- 2026-06-03 20:26 UTC (Run #26910975773, Laufzeit 21m 45s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-06-02 05:08 UTC - cancelled - Run #26799721689 (7m 57s)
- 2026-06-02 05:16 UTC - cancelled - Run #26799985245 (5s)
- 2026-06-02 11:02 UTC - cancelled - Run #26815509959 (6m 6s)
- 2026-06-02 11:08 UTC - cancelled - Run #26815795532 (5s)
- 2026-06-02 16:59 UTC - cancelled - Run #26835147145 (9m 3s)
- 2026-06-02 17:08 UTC - cancelled - Run #26835627939 (10s)
- 2026-06-02 21:28 UTC - cancelled - Run #26849124751 (7m 45s)
- 2026-06-03 05:24 UTC - cancelled - Run #26865480372 (1m 55s)
- 2026-06-03 11:26 UTC - cancelled - Run #26881661573 (5m 36s)
- 2026-06-03 17:25 UTC - cancelled - Run #26901448723 (4m 7s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
