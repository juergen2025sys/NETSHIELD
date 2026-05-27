# Workflow Health Report

**Stand:** 2026-05-27 20:28 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 10 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 3
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 76
- **Skip-Runs:** 62
- **Fehlgeschlagene Runs:** 15
- **Lucken >210min:** 10
- **Groesste Lucke:** 2026-05-20 20:56 UTC -> 2026-05-21 04:38 UTC (461 min = 7h 41min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 78
- **Watchdog-Fehler:** 3
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 34

Letzte Watchdog-Eingriffe:
- 2026-05-26 19:36 UTC (Run #26470724480, Laufzeit 23m 39s)
- 2026-05-27 02:02 UTC (Run #26486283962, Laufzeit 24m 52s)
- 2026-05-27 06:39 UTC (Run #26495213068, Laufzeit 25m 51s)
- 2026-05-27 14:02 UTC (Run #26516045704, Laufzeit 23m 55s)
- 2026-05-27 19:39 UTC (Run #26534369154, Laufzeit 24m 54s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-05-25 10:54 UTC - cancelled - Run #26396870294 (4m 46s)
- 2026-05-25 10:59 UTC - cancelled - Run #26397054107 (4s)
- 2026-05-26 10:32 UTC - failure - Run #26447071549 (23m 17s)
- 2026-05-26 10:37 UTC - failure - Run #26447297366 (18m 23s)
- 2026-05-26 22:46 UTC - cancelled - Run #26479500493 (8m 46s)
- 2026-05-26 22:54 UTC - cancelled - Run #26479838963 (5s)
- 2026-05-27 04:54 UTC - cancelled - Run #26491591427 (10m 8s)
- 2026-05-27 05:04 UTC - cancelled - Run #26491921676 (5s)
- 2026-05-27 16:22 UTC - cancelled - Run #26524034981 (5m 17s)
- 2026-05-27 16:28 UTC - cancelled - Run #26524321235 (10s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
