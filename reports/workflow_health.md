# Workflow Health Report

**Stand:** 2026-07-05 09:19 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 11
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-07-05 04:39 UTC -> 2026-07-05 08:16 UTC (217 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 66
- **Skip-Runs:** 87
- **Fehlgeschlagene Runs:** 28
- **Lucken >210min:** 5
- **Groesste Lucke:** 2026-06-28 21:59 UTC -> 2026-06-29 02:05 UTC (245 min = 4h 5min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 218
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 53

Letzte Watchdog-Eingriffe:
- 2026-07-04 16:32 UTC (Run #28712564905, Laufzeit 32m 53s)
- 2026-07-04 18:09 UTC (Run #28715141889, Laufzeit 24m 39s)
- 2026-07-04 21:30 UTC (Run #28720251371, Laufzeit 25m 2s)
- 2026-07-05 01:15 UTC (Run #28725398791, Laufzeit 25m 5s)
- 2026-07-05 08:16 UTC (Run #28734505371, Laufzeit 24m 40s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-07-04 04:09 UTC - cancelled - Run #28694464140 (8m 19s)
- 2026-07-04 10:58 UTC - cancelled - Run #28704019076 (6m 16s)
- 2026-07-04 11:04 UTC - cancelled - Run #28704191296 (7m 17s)
- 2026-07-04 11:11 UTC - cancelled - Run #28704365176 (5m 50s)
- 2026-07-04 16:11 UTC - cancelled - Run #28712013779 (4m 55s)
- 2026-07-04 16:16 UTC - cancelled - Run #28712144532 (13m 10s)
- 2026-07-04 16:29 UTC - cancelled - Run #28712484652 (1m 3s)
- 2026-07-04 16:30 UTC - cancelled - Run #28712511670 (1m 53s)
- 2026-07-04 16:42 UTC - cancelled - Run #28712831215 (22m 55s)
- 2026-07-05 04:37 UTC - cancelled - Run #28729658902 (2m 19s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
