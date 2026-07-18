# Workflow Health Report

**Stand:** 2026-07-18 08:05 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 11 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 17
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 75
- **Skip-Runs:** 93
- **Fehlgeschlagene Runs:** 25
- **Lucken >210min:** 1
- **Groesste Lucke:** 2026-07-16 09:50 UTC -> 2026-07-16 14:13 UTC (263 min = 4h 23min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 280
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 47

Letzte Watchdog-Eingriffe:
- 2026-07-17 15:40 UTC (Run #29593077250, Laufzeit 23m 17s)
- 2026-07-17 18:52 UTC (Run #29605458382, Laufzeit 26m 21s)
- 2026-07-17 21:29 UTC (Run #29614874770, Laufzeit 27m 3s)
- 2026-07-18 00:55 UTC (Run #29624153525, Laufzeit 24m 32s)
- 2026-07-18 06:29 UTC (Run #29634068456, Laufzeit 26m 6s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-07-15 03:43 UTC - cancelled - Run #29387212358 (5m 16s)
- 2026-07-15 03:48 UTC - cancelled - Run #29387421351 (5s)
- 2026-07-15 08:40 UTC - cancelled - Run #29401624201 (15m 57s)
- 2026-07-16 03:45 UTC - cancelled - Run #29469725148 (6m 2s)
- 2026-07-16 03:51 UTC - cancelled - Run #29469954244 (3m 50s)
- 2026-07-16 09:02 UTC - cancelled - Run #29485659738 (3m 37s)
- 2026-07-17 03:45 UTC - cancelled - Run #29553147515 (6m 25s)
- 2026-07-17 03:51 UTC - cancelled - Run #29553407430 (2m 11s)
- 2026-07-18 03:40 UTC - cancelled - Run #29629224822 (5m 5s)
- 2026-07-18 03:45 UTC - cancelled - Run #29629376425 (1m 29s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
