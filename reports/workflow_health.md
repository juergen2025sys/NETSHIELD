# Workflow Health Report

**Stand:** 2026-06-14 05:02 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 11
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-06-13 22:10 UTC -> 2026-06-14 01:43 UTC (213 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 69
- **Skip-Runs:** 63
- **Fehlgeschlagene Runs:** 23
- **Lucken >210min:** 8
- **Groesste Lucke:** 2026-06-08 07:07 UTC -> 2026-06-08 11:16 UTC (249 min = 4h 9min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 183
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 43

Letzte Watchdog-Eingriffe:
- 2026-06-13 13:12 UTC (Run #27467748107, Laufzeit 16m 55s)
- 2026-06-13 15:19 UTC (Run #27470727888, Laufzeit 18m 55s)
- 2026-06-13 18:44 UTC (Run #27475703420, Laufzeit 20m 34s)
- 2026-06-13 21:49 UTC (Run #27480137113, Laufzeit 20m 23s)
- 2026-06-14 01:43 UTC (Run #27485020443, Laufzeit 20m 30s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-06-10 16:26 UTC - cancelled - Run #27290192234 (12m 6s)
- 2026-06-11 05:07 UTC - cancelled - Run #27325175029 (5m 31s)
- 2026-06-12 05:12 UTC - cancelled - Run #27396013364 (4m 7s)
- 2026-06-12 10:46 UTC - cancelled - Run #27410903213 (6m 3s)
- 2026-06-12 10:52 UTC - cancelled - Run #27411175233 (5m 57s)
- 2026-06-12 15:45 UTC - cancelled - Run #27426476111 (9m 12s)
- 2026-06-13 04:57 UTC - cancelled - Run #27457175275 (6m 15s)
- 2026-06-13 09:41 UTC - cancelled - Run #27463188704 (4m 42s)
- 2026-06-13 09:46 UTC - cancelled - Run #27463289167 (4m 28s)
- 2026-06-13 16:54 UTC - cancelled - Run #27473054418 (8m 26s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
