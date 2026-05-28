# Workflow Health Report

**Stand:** 2026-05-28 20:35 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 7
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 75
- **Skip-Runs:** 60
- **Fehlgeschlagene Runs:** 19
- **Lucken >210min:** 7
- **Groesste Lucke:** 2026-05-25 22:23 UTC -> 2026-05-26 04:20 UTC (356 min = 5h 56min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 81
- **Watchdog-Fehler:** 3
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 37

Letzte Watchdog-Eingriffe:
- 2026-05-28 06:01 UTC (Run #26557723263, Laufzeit 24m 43s)
- 2026-05-28 07:06 UTC (Run #26560139792, Laufzeit 24m 24s)
- 2026-05-28 09:55 UTC (Run #26567753146, Laufzeit 24m 17s)
- 2026-05-28 12:59 UTC (Run #26576171847, Laufzeit 24m 47s)
- 2026-05-28 19:31 UTC (Run #26597425530, Laufzeit 27m 17s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-05-26 22:46 UTC - cancelled - Run #26479500493 (8m 46s)
- 2026-05-26 22:54 UTC - cancelled - Run #26479838963 (5s)
- 2026-05-27 04:54 UTC - cancelled - Run #26491591427 (10m 8s)
- 2026-05-27 05:04 UTC - cancelled - Run #26491921676 (5s)
- 2026-05-27 16:22 UTC - cancelled - Run #26524034981 (5m 17s)
- 2026-05-27 16:28 UTC - cancelled - Run #26524321235 (10s)
- 2026-05-27 22:55 UTC - cancelled - Run #26543576226 (9m 13s)
- 2026-05-27 23:04 UTC - cancelled - Run #26543935463 (5s)
- 2026-05-28 16:37 UTC - cancelled - Run #26588251011 (6m 21s)
- 2026-05-28 16:43 UTC - cancelled - Run #26588591330 (7s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
