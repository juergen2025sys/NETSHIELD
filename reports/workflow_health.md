# Workflow Health Report

**Stand:** 2026-07-04 19:33 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 10 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 12
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 69
- **Skip-Runs:** 85
- **Fehlgeschlagene Runs:** 29
- **Lucken >210min:** 4
- **Groesste Lucke:** 2026-06-28 21:59 UTC -> 2026-06-29 02:05 UTC (245 min = 4h 5min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 215
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 55

Letzte Watchdog-Eingriffe:
- 2026-07-04 12:44 UTC (Run #28706614906, Laufzeit 31m 13s)
- 2026-07-04 16:16 UTC (Run #28712144532, Laufzeit 13m 10s)
- 2026-07-04 16:29 UTC (Run #28712484652, Laufzeit 1m 3s)
- 2026-07-04 16:32 UTC (Run #28712564905, Laufzeit 32m 53s)
- 2026-07-04 18:09 UTC (Run #28715141889, Laufzeit 24m 39s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-07-03 22:31 UTC - cancelled - Run #28686124835 (2m 35s)
- 2026-07-04 04:09 UTC - cancelled - Run #28694464140 (8m 19s)
- 2026-07-04 10:58 UTC - cancelled - Run #28704019076 (6m 16s)
- 2026-07-04 11:04 UTC - cancelled - Run #28704191296 (7m 17s)
- 2026-07-04 11:11 UTC - cancelled - Run #28704365176 (5m 50s)
- 2026-07-04 16:11 UTC - cancelled - Run #28712013779 (4m 55s)
- 2026-07-04 16:16 UTC - cancelled - Run #28712144532 (13m 10s)
- 2026-07-04 16:29 UTC - cancelled - Run #28712484652 (1m 3s)
- 2026-07-04 16:30 UTC - cancelled - Run #28712511670 (1m 53s)
- 2026-07-04 16:42 UTC - cancelled - Run #28712831215 (22m 55s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
