# Workflow Health Report

**Stand:** 2026-07-20 14:28 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 10 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 9
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-07-19 22:03 UTC -> 2026-07-20 03:54 UTC (351 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 70
- **Skip-Runs:** 94
- **Fehlgeschlagene Runs:** 25
- **Lucken >210min:** 2
- **Groesste Lucke:** 2026-07-19 22:03 UTC -> 2026-07-20 03:54 UTC (351 min = 5h 51min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 282
- **Watchdog-Fehler:** 3
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 42

Letzte Watchdog-Eingriffe:
- 2026-07-19 15:31 UTC (Run #29693007858, Laufzeit 27m 3s)
- 2026-07-19 18:34 UTC (Run #29698959987, Laufzeit 27m 49s)
- 2026-07-19 21:31 UTC (Run #29704504045, Laufzeit 27m 0s)
- 2026-07-20 07:29 UTC (Run #29724770292, Laufzeit 26m 50s)
- 2026-07-20 12:37 UTC (Run #29742943841, Laufzeit 23m 15s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-07-18 03:40 UTC - cancelled - Run #29629224822 (5m 5s)
- 2026-07-18 03:45 UTC - cancelled - Run #29629376425 (1m 29s)
- 2026-07-18 19:39 UTC - cancelled - Run #29658201607 (6m 53s)
- 2026-07-18 22:11 UTC - cancelled - Run #29663005899 (13m 32s)
- 2026-07-19 04:02 UTC - cancelled - Run #29672685133 (5m 40s)
- 2026-07-19 13:59 UTC - cancelled - Run #29689931827 (12m 59s)
- 2026-07-19 14:12 UTC - cancelled - Run #29690364975 (32s)
- 2026-07-20 04:11 UTC - cancelled - Run #29716287390 (10m 27s)
- 2026-07-20 09:40 UTC - cancelled - Run #29732296990 (5m 15s)
- 2026-07-20 09:45 UTC - cancelled - Run #29732613925 (12m 50s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
