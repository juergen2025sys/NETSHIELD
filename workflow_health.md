# Workflow Health Report

**Stand:** 2026-05-21 10:00 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 7 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 7
- **Lucken (>210min zwischen echten Runs):** 3
  - 2026-05-20 10:14 UTC -> 2026-05-20 15:14 UTC (300 min)
  - 2026-05-20 15:37 UTC -> 2026-05-20 20:28 UTC (290 min)
  - 2026-05-20 20:56 UTC -> 2026-05-21 04:38 UTC (461 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 51
- **Skip-Runs:** 9
- **Fehlgeschlagene Runs:** 2
- **Lucken >210min:** 17
- **Groesste Lucke:** 2026-05-20 20:56 UTC -> 2026-05-21 04:38 UTC (461 min = 7h 41min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 4
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 3

Letzte Watchdog-Eingriffe:
- 2026-05-17 17:38 UTC (Run #25997997717, Laufzeit 22m 0s)
- 2026-05-18 18:41 UTC (Run #26053163903, Laufzeit 21m 4s)
- 2026-05-20 15:14 UTC (Run #26171808458, Laufzeit 22m 46s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-05-19 20:11 UTC - cancelled - Run #26122470879 (8m 0s)
- 2026-05-20 09:58 UTC - cancelled - Run #26155300581 (4m 12s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
