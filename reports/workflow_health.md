# Workflow Health Report

**Stand:** 2026-07-16 08:28 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 10 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 16
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 72
- **Skip-Runs:** 83
- **Fehlgeschlagene Runs:** 29
- **Lucken >210min:** 2
- **Groesste Lucke:** 2026-07-10 04:32 UTC -> 2026-07-10 08:35 UTC (243 min = 4h 3min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 262
- **Watchdog-Fehler:** 1
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 47

Letzte Watchdog-Eingriffe:
- 2026-07-15 15:50 UTC (Run #29429824382, Laufzeit 26m 47s)
- 2026-07-15 18:38 UTC (Run #29441330822, Laufzeit 26m 34s)
- 2026-07-15 21:44 UTC (Run #29453004397, Laufzeit 19m 26s)
- 2026-07-16 01:04 UTC (Run #29463205116, Laufzeit 21m 54s)
- 2026-07-16 06:31 UTC (Run #29476966749, Laufzeit 27m 23s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-07-13 17:41 UTC - cancelled - Run #29271444839 (1m 20s)
- 2026-07-13 18:53 UTC - cancelled - Run #29276271106 (6m 5s)
- 2026-07-13 22:24 UTC - cancelled - Run #29289782575 (5m 21s)
- 2026-07-14 03:42 UTC - cancelled - Run #29304156090 (5m 29s)
- 2026-07-14 03:47 UTC - cancelled - Run #29304375919 (25s)
- 2026-07-15 03:43 UTC - cancelled - Run #29387212358 (5m 16s)
- 2026-07-15 03:48 UTC - cancelled - Run #29387421351 (5s)
- 2026-07-15 08:40 UTC - cancelled - Run #29401624201 (15m 57s)
- 2026-07-16 03:45 UTC - cancelled - Run #29469725148 (6m 2s)
- 2026-07-16 03:51 UTC - cancelled - Run #29469954244 (3m 50s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
