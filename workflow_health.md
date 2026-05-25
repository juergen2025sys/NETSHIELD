# Workflow Health Report

**Stand:** 2026-05-25 19:55 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 10 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 7
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-05-24 22:06 UTC -> 2026-05-25 01:37 UTC (210 min)
  - 2026-05-25 05:14 UTC -> 2026-05-25 10:42 UTC (328 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 72
- **Skip-Runs:** 56
- **Fehlgeschlagene Runs:** 9
- **Lucken >210min:** 15
- **Groesste Lucke:** 2026-05-20 20:56 UTC -> 2026-05-21 04:38 UTC (461 min = 7h 41min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 62
- **Watchdog-Fehler:** 3
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 27

Letzte Watchdog-Eingriffe:
- 2026-05-24 21:43 UTC (Run #26373555952, Laufzeit 23m 19s)
- 2026-05-25 01:37 UTC (Run #26378760586, Laufzeit 24m 2s)
- 2026-05-25 13:54 UTC (Run #26404046364, Laufzeit 24m 19s)
- 2026-05-25 16:13 UTC (Run #26409714528, Laufzeit 24m 37s)
- 2026-05-25 19:19 UTC (Run #26416225424, Laufzeit 24m 23s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-05-19 20:11 UTC - cancelled - Run #26122470879 (8m 0s)
- 2026-05-20 09:58 UTC - cancelled - Run #26155300581 (4m 12s)
- 2026-05-22 22:33 UTC - cancelled - Run #26315176210 (9m 1s)
- 2026-05-22 22:42 UTC - cancelled - Run #26315468390 (4s)
- 2026-05-23 10:49 UTC - cancelled - Run #26330756852 (11m 26s)
- 2026-05-23 11:01 UTC - cancelled - Run #26330970787 (4s)
- 2026-05-24 16:09 UTC - cancelled - Run #26366195577 (6m 2s)
- 2026-05-25 10:54 UTC - cancelled - Run #26396870294 (4m 46s)
- 2026-05-25 10:59 UTC - cancelled - Run #26397054107 (4s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
