# Workflow Health Report

**Stand:** 2026-08-01 19:23 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 20 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 10
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 95
- **Skip-Runs:** 94
- **Fehlgeschlagene Runs:** 1
- **Lucken >210min:** 3
- **Groesste Lucke:** 2026-07-29 21:58 UTC -> 2026-07-30 03:16 UTC (317 min = 5h 17min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 252
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 49

Letzte Watchdog-Eingriffe:
- 2026-08-01 14:42 UTC (Run #30704321503, Laufzeit 31m 21s)
- 2026-08-01 15:32 UTC (Run #30706147685, Laufzeit 57m 14s)
- 2026-08-01 15:37 UTC (Run #30706321726, Laufzeit 84m 25s)
- 2026-08-01 18:33 UTC (Run #30712795237, Laufzeit 27m 53s)
- 2026-08-01 18:36 UTC (Run #30712895483, Laufzeit 1s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-08-01 04:54 UTC - action_required - Run #30684814132 (1s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
