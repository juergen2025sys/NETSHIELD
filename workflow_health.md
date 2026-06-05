# Workflow Health Report

**Stand:** 2026-06-05 10:10 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 8 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 8
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-06-04 10:29 UTC -> 2026-06-04 14:14 UTC (225 min)
  - 2026-06-04 22:16 UTC -> 2026-06-05 04:41 UTC (385 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 63
- **Skip-Runs:** 52
- **Fehlgeschlagene Runs:** 30
- **Lucken >210min:** 12
- **Groesste Lucke:** 2026-06-04 22:16 UTC -> 2026-06-05 04:41 UTC (385 min = 6h 25min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 107
- **Watchdog-Fehler:** 2
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 36

Letzte Watchdog-Eingriffe:
- 2026-06-04 14:14 UTC (Run #26957407158, Laufzeit 21m 4s)
- 2026-06-04 15:52 UTC (Run #26963126984, Laufzeit 21m 6s)
- 2026-06-04 19:32 UTC (Run #26974752139, Laufzeit 20m 33s)
- 2026-06-04 21:55 UTC (Run #26981941926, Laufzeit 20m 46s)
- 2026-06-05 08:37 UTC (Run #27004698964, Laufzeit 21m 12s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-06-02 17:08 UTC - cancelled - Run #26835627939 (10s)
- 2026-06-02 21:28 UTC - cancelled - Run #26849124751 (7m 45s)
- 2026-06-03 05:24 UTC - cancelled - Run #26865480372 (1m 55s)
- 2026-06-03 11:26 UTC - cancelled - Run #26881661573 (5m 36s)
- 2026-06-03 17:25 UTC - cancelled - Run #26901448723 (4m 7s)
- 2026-06-03 21:34 UTC - cancelled - Run #26914410165 (4m 35s)
- 2026-06-04 10:14 UTC - cancelled - Run #26945519544 (13m 42s)
- 2026-06-04 10:28 UTC - cancelled - Run #26946166707 (41s)
- 2026-06-04 15:56 UTC - cancelled - Run #26963345882 (8m 55s)
- 2026-06-05 04:54 UTC - cancelled - Run #26996197515 (9m 2s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
