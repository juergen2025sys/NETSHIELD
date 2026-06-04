# Workflow Health Report

**Stand:** 2026-06-04 10:10 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 6
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-06-03 11:41 UTC -> 2026-06-03 17:07 UTC (326 min)
  - 2026-06-03 21:52 UTC -> 2026-06-04 02:06 UTC (253 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 62
- **Skip-Runs:** 53
- **Fehlgeschlagene Runs:** 28
- **Lucken >210min:** 12
- **Groesste Lucke:** 2026-05-28 21:59 UTC -> 2026-05-29 04:36 UTC (397 min = 6h 37min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 91
- **Watchdog-Fehler:** 2
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 35

Letzte Watchdog-Eingriffe:
- 2026-06-03 20:26 UTC (Run #26910975773, Laufzeit 21m 45s)
- 2026-06-03 21:30 UTC (Run #26914210799, Laufzeit 22m 3s)
- 2026-06-04 02:06 UTC (Run #26925600146, Laufzeit 20m 46s)
- 2026-06-04 03:39 UTC (Run #26928969088, Laufzeit 21m 44s)
- 2026-06-04 07:04 UTC (Run #26936438080, Laufzeit 21m 55s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-06-02 05:16 UTC - cancelled - Run #26799985245 (5s)
- 2026-06-02 11:02 UTC - cancelled - Run #26815509959 (6m 6s)
- 2026-06-02 11:08 UTC - cancelled - Run #26815795532 (5s)
- 2026-06-02 16:59 UTC - cancelled - Run #26835147145 (9m 3s)
- 2026-06-02 17:08 UTC - cancelled - Run #26835627939 (10s)
- 2026-06-02 21:28 UTC - cancelled - Run #26849124751 (7m 45s)
- 2026-06-03 05:24 UTC - cancelled - Run #26865480372 (1m 55s)
- 2026-06-03 11:26 UTC - cancelled - Run #26881661573 (5m 36s)
- 2026-06-03 17:25 UTC - cancelled - Run #26901448723 (4m 7s)
- 2026-06-03 21:34 UTC - cancelled - Run #26914410165 (4m 35s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
