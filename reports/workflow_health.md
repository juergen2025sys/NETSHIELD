# Workflow Health Report

**Stand:** 2026-08-03 10:02 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 15 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 8
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 105
- **Skip-Runs:** 86
- **Fehlgeschlagene Runs:** 4
- **Lucken >210min:** 3
- **Groesste Lucke:** 2026-07-29 21:58 UTC -> 2026-07-30 03:16 UTC (317 min = 5h 17min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 252
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 51

Letzte Watchdog-Eingriffe:
- 2026-08-02 15:33 UTC (Run #30754628925, Laufzeit 30m 23s)
- 2026-08-02 18:29 UTC (Run #30761219596, Laufzeit 29m 13s)
- 2026-08-02 21:32 UTC (Run #30768120425, Laufzeit 27m 24s)
- 2026-08-03 01:10 UTC (Run #30776223038, Laufzeit 30m 29s)
- 2026-08-03 07:46 UTC (Run #30794877721, Laufzeit 35m 9s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-08-01 04:54 UTC - action_required - Run #30684814132 (1s)
- 2026-08-01 18:36 UTC - cancelled - Run #30712895483 (56m 57s)
- 2026-08-02 09:30 UTC - cancelled - Run #30741887134 (9m 19s)
- 2026-08-02 16:27 UTC - action_required - Run #30756671523 (0s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
