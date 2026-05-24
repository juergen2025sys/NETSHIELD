# Workflow Health Report

**Stand:** 2026-05-24 08:43 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 12 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 12
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-05-23 21:58 UTC -> 2026-05-24 01:34 UTC (215 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 67
- **Skip-Runs:** 38
- **Fehlgeschlagene Runs:** 6
- **Lucken >210min:** 16
- **Groesste Lucke:** 2026-05-20 20:56 UTC -> 2026-05-21 04:38 UTC (461 min = 7h 41min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 42
- **Watchdog-Fehler:** 3
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 20

Letzte Watchdog-Eingriffe:
- 2026-05-23 12:53 UTC (Run #26333228645, Laufzeit 23m 52s)
- 2026-05-23 15:37 UTC (Run #26336750816, Laufzeit 22m 38s)
- 2026-05-23 21:34 UTC (Run #26344142880, Laufzeit 23m 53s)
- 2026-05-24 01:34 UTC (Run #26348668062, Laufzeit 21m 58s)
- 2026-05-24 08:13 UTC (Run #26356057007, Laufzeit 23m 44s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-05-19 20:11 UTC - cancelled - Run #26122470879 (8m 0s)
- 2026-05-20 09:58 UTC - cancelled - Run #26155300581 (4m 12s)
- 2026-05-22 22:33 UTC - cancelled - Run #26315176210 (9m 1s)
- 2026-05-22 22:42 UTC - cancelled - Run #26315468390 (4s)
- 2026-05-23 10:49 UTC - cancelled - Run #26330756852 (11m 26s)
- 2026-05-23 11:01 UTC - cancelled - Run #26330970787 (4s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
