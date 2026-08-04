# Workflow Health Report

**Stand:** 2026-08-04 14:35 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 18 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 8
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 110
- **Skip-Runs:** 78
- **Fehlgeschlagene Runs:** 4
- **Lucken >210min:** 2
- **Groesste Lucke:** 2026-07-29 21:58 UTC -> 2026-07-30 03:16 UTC (317 min = 5h 17min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 250
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 49

Letzte Watchdog-Eingriffe:
- 2026-08-03 19:07 UTC (Run #30844396421, Laufzeit 31m 25s)
- 2026-08-03 21:30 UTC (Run #30854913616, Laufzeit 31m 56s)
- 2026-08-04 01:05 UTC (Run #30867650595, Laufzeit 34m 48s)
- 2026-08-04 07:07 UTC (Run #30886585047, Laufzeit 31m 8s)
- 2026-08-04 13:10 UTC (Run #30912503632, Laufzeit 31m 36s)

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
