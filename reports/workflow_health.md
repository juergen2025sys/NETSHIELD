# Workflow Health Report

**Stand:** 2026-07-16 19:27 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 10 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 14
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-07-16 09:50 UTC -> 2026-07-16 14:13 UTC (263 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 74
- **Skip-Runs:** 88
- **Fehlgeschlagene Runs:** 27
- **Lucken >210min:** 2
- **Groesste Lucke:** 2026-07-16 09:50 UTC -> 2026-07-16 14:13 UTC (263 min = 4h 23min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 266
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 47

Letzte Watchdog-Eingriffe:
- 2026-07-16 01:04 UTC (Run #29463205116, Laufzeit 21m 54s)
- 2026-07-16 06:31 UTC (Run #29476966749, Laufzeit 27m 23s)
- 2026-07-16 09:28 UTC (Run #29487270545, Laufzeit 21m 38s)
- 2026-07-16 15:54 UTC (Run #29513273709, Laufzeit 22m 26s)
- 2026-07-16 18:40 UTC (Run #29524944405, Laufzeit 27m 38s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-07-13 18:53 UTC - cancelled - Run #29276271106 (6m 5s)
- 2026-07-13 22:24 UTC - cancelled - Run #29289782575 (5m 21s)
- 2026-07-14 03:42 UTC - cancelled - Run #29304156090 (5m 29s)
- 2026-07-14 03:47 UTC - cancelled - Run #29304375919 (25s)
- 2026-07-15 03:43 UTC - cancelled - Run #29387212358 (5m 16s)
- 2026-07-15 03:48 UTC - cancelled - Run #29387421351 (5s)
- 2026-07-15 08:40 UTC - cancelled - Run #29401624201 (15m 57s)
- 2026-07-16 03:45 UTC - cancelled - Run #29469725148 (6m 2s)
- 2026-07-16 03:51 UTC - cancelled - Run #29469954244 (3m 50s)
- 2026-07-16 09:02 UTC - cancelled - Run #29485659738 (3m 37s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
