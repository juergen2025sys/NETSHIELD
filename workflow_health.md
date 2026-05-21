# Workflow Health Report

**Stand:** 2026-05-21 20:07 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 11 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 8
- **Lucken (>210min zwischen echten Runs):** 3
  - 2026-05-20 20:56 UTC -> 2026-05-21 04:38 UTC (461 min)
  - 2026-05-21 05:00 UTC -> 2026-05-21 09:59 UTC (299 min)
  - 2026-05-21 10:29 UTC -> 2026-05-21 14:26 UTC (236 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 53
- **Skip-Runs:** 13
- **Fehlgeschlagene Runs:** 2
- **Lucken >210min:** 19
- **Groesste Lucke:** 2026-05-20 20:56 UTC -> 2026-05-21 04:38 UTC (461 min = 7h 41min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 8
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 6

Letzte Watchdog-Eingriffe:
- 2026-05-18 18:41 UTC (Run #26053163903, Laufzeit 21m 4s)
- 2026-05-20 15:14 UTC (Run #26171808458, Laufzeit 22m 46s)
- 2026-05-21 14:26 UTC (Run #26232215774, Laufzeit 22m 24s)
- 2026-05-21 17:09 UTC (Run #26241213692, Laufzeit 17m 53s)
- 2026-05-21 19:14 UTC (Run #26247621548, Laufzeit 22m 41s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-05-19 20:11 UTC - cancelled - Run #26122470879 (8m 0s)
- 2026-05-20 09:58 UTC - cancelled - Run #26155300581 (4m 12s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
