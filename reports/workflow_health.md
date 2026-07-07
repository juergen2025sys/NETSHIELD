# Workflow Health Report

**Stand:** 2026-07-07 09:57 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 8 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 13
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-07-07 04:43 UTC -> 2026-07-07 08:36 UTC (233 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 65
- **Skip-Runs:** 93
- **Fehlgeschlagene Runs:** 22
- **Lucken >210min:** 6
- **Groesste Lucke:** 2026-07-06 04:52 UTC -> 2026-07-06 09:36 UTC (283 min = 4h 43min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 220
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 51

Letzte Watchdog-Eingriffe:
- 2026-07-06 17:21 UTC (Run #28810071325, Laufzeit 16m 48s)
- 2026-07-06 19:11 UTC (Run #28816670523, Laufzeit 26m 10s)
- 2026-07-06 21:50 UTC (Run #28825660593, Laufzeit 26m 22s)
- 2026-07-07 01:12 UTC (Run #28834430922, Laufzeit 26m 34s)
- 2026-07-07 08:36 UTC (Run #28852973735, Laufzeit 26m 33s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-07-04 11:11 UTC - cancelled - Run #28704365176 (5m 50s)
- 2026-07-04 16:11 UTC - cancelled - Run #28712013779 (4m 55s)
- 2026-07-04 16:16 UTC - cancelled - Run #28712144532 (13m 10s)
- 2026-07-04 16:29 UTC - cancelled - Run #28712484652 (1m 3s)
- 2026-07-04 16:30 UTC - cancelled - Run #28712511670 (1m 53s)
- 2026-07-04 16:42 UTC - cancelled - Run #28712831215 (22m 55s)
- 2026-07-05 04:37 UTC - cancelled - Run #28729658902 (2m 19s)
- 2026-07-05 09:31 UTC - cancelled - Run #28736326627 (10m 47s)
- 2026-07-05 22:09 UTC - cancelled - Run #28756553233 (3m 18s)
- 2026-07-07 04:30 UTC - cancelled - Run #28841655523 (6m 34s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
