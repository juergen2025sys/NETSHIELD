# Workflow Health Report

**Stand:** 2026-07-20 03:57 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 8 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 14
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 67
- **Skip-Runs:** 94
- **Fehlgeschlagene Runs:** 25
- **Lucken >210min:** 1
- **Groesste Lucke:** 2026-07-16 09:50 UTC -> 2026-07-16 14:13 UTC (263 min = 4h 23min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 279
- **Watchdog-Fehler:** 3
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 42

Letzte Watchdog-Eingriffe:
- 2026-07-19 06:43 UTC (Run #29676901406, Laufzeit 27m 14s)
- 2026-07-19 10:07 UTC (Run #29682789263, Laufzeit 27m 1s)
- 2026-07-19 15:31 UTC (Run #29693007858, Laufzeit 27m 3s)
- 2026-07-19 18:34 UTC (Run #29698959987, Laufzeit 27m 49s)
- 2026-07-19 21:31 UTC (Run #29704504045, Laufzeit 27m 0s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-07-16 09:02 UTC - cancelled - Run #29485659738 (3m 37s)
- 2026-07-17 03:45 UTC - cancelled - Run #29553147515 (6m 25s)
- 2026-07-17 03:51 UTC - cancelled - Run #29553407430 (2m 11s)
- 2026-07-18 03:40 UTC - cancelled - Run #29629224822 (5m 5s)
- 2026-07-18 03:45 UTC - cancelled - Run #29629376425 (1m 29s)
- 2026-07-18 19:39 UTC - cancelled - Run #29658201607 (6m 53s)
- 2026-07-18 22:11 UTC - cancelled - Run #29663005899 (13m 32s)
- 2026-07-19 04:02 UTC - cancelled - Run #29672685133 (5m 40s)
- 2026-07-19 13:59 UTC - cancelled - Run #29689931827 (12m 59s)
- 2026-07-19 14:12 UTC - cancelled - Run #29690364975 (32s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
