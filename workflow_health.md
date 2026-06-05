# Workflow Health Report

**Stand:** 2026-06-05 20:06 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 11
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-06-04 22:16 UTC -> 2026-06-05 04:41 UTC (385 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 64
- **Skip-Runs:** 50
- **Fehlgeschlagene Runs:** 32
- **Lucken >210min:** 12
- **Groesste Lucke:** 2026-06-04 22:16 UTC -> 2026-06-05 04:41 UTC (385 min = 6h 25min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 118
- **Watchdog-Fehler:** 2
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 36

Letzte Watchdog-Eingriffe:
- 2026-06-05 08:37 UTC (Run #27004698964, Laufzeit 21m 12s)
- 2026-06-05 10:36 UTC (Run #27010022897, Laufzeit 21m 39s)
- 2026-06-05 12:43 UTC (Run #27015526657, Laufzeit 20m 37s)
- 2026-06-05 13:25 UTC (Run #27017554625, Laufzeit 20m 38s)
- 2026-06-05 18:28 UTC (Run #27032797645, Laufzeit 24m 27s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-06-03 05:24 UTC - cancelled - Run #26865480372 (1m 55s)
- 2026-06-03 11:26 UTC - cancelled - Run #26881661573 (5m 36s)
- 2026-06-03 17:25 UTC - cancelled - Run #26901448723 (4m 7s)
- 2026-06-03 21:34 UTC - cancelled - Run #26914410165 (4m 35s)
- 2026-06-04 10:14 UTC - cancelled - Run #26945519544 (13m 42s)
- 2026-06-04 10:28 UTC - cancelled - Run #26946166707 (41s)
- 2026-06-04 15:56 UTC - cancelled - Run #26963345882 (8m 55s)
- 2026-06-05 04:54 UTC - cancelled - Run #26996197515 (9m 2s)
- 2026-06-05 10:36 UTC - cancelled - Run #27010031379 (21m 25s)
- 2026-06-05 15:39 UTC - cancelled - Run #27024548471 (14m 42s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
