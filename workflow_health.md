# Workflow Health Report

**Stand:** 2026-06-05 04:43 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 7 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 10
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-06-04 10:29 UTC -> 2026-06-04 14:14 UTC (225 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 63
- **Skip-Runs:** 51
- **Fehlgeschlagene Runs:** 29
- **Lucken >210min:** 12
- **Groesste Lucke:** 2026-05-30 22:42 UTC -> 2026-05-31 04:46 UTC (363 min = 6h 3min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 103
- **Watchdog-Fehler:** 2
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 36

Letzte Watchdog-Eingriffe:
- 2026-06-04 07:04 UTC (Run #26936438080, Laufzeit 21m 55s)
- 2026-06-04 14:14 UTC (Run #26957407158, Laufzeit 21m 4s)
- 2026-06-04 15:52 UTC (Run #26963126984, Laufzeit 21m 6s)
- 2026-06-04 19:32 UTC (Run #26974752139, Laufzeit 20m 33s)
- 2026-06-04 21:55 UTC (Run #26981941926, Laufzeit 20m 46s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-06-02 16:59 UTC - cancelled - Run #26835147145 (9m 3s)
- 2026-06-02 17:08 UTC - cancelled - Run #26835627939 (10s)
- 2026-06-02 21:28 UTC - cancelled - Run #26849124751 (7m 45s)
- 2026-06-03 05:24 UTC - cancelled - Run #26865480372 (1m 55s)
- 2026-06-03 11:26 UTC - cancelled - Run #26881661573 (5m 36s)
- 2026-06-03 17:25 UTC - cancelled - Run #26901448723 (4m 7s)
- 2026-06-03 21:34 UTC - cancelled - Run #26914410165 (4m 35s)
- 2026-06-04 10:14 UTC - cancelled - Run #26945519544 (13m 42s)
- 2026-06-04 10:28 UTC - cancelled - Run #26946166707 (41s)
- 2026-06-04 15:56 UTC - cancelled - Run #26963345882 (8m 55s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
