# Workflow Health Report

**Stand:** 2026-08-02 13:47 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 23 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 8
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 101
- **Skip-Runs:** 91
- **Fehlgeschlagene Runs:** 3
- **Lucken >210min:** 3
- **Groesste Lucke:** 2026-07-29 21:58 UTC -> 2026-07-30 03:16 UTC (317 min = 5h 17min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 252
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 51

Letzte Watchdog-Eingriffe:
- 2026-08-02 06:45 UTC (Run #30736506086, Laufzeit 30m 20s)
- 2026-08-02 08:55 UTC (Run #30740718477, Laufzeit 30m 17s)
- 2026-08-02 09:30 UTC (Run #30741887134, Laufzeit 9m 19s)
- 2026-08-02 09:40 UTC (Run #30742214489, Laufzeit 31m 44s)
- 2026-08-02 12:50 UTC (Run #30748683972, Laufzeit 30m 8s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-08-01 04:54 UTC - action_required - Run #30684814132 (1s)
- 2026-08-01 18:36 UTC - cancelled - Run #30712895483 (56m 57s)
- 2026-08-02 09:30 UTC - cancelled - Run #30741887134 (9m 19s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
