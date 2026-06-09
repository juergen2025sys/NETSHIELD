# Workflow Health Report

**Stand:** 2026-06-09 15:24 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 10 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 10
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-06-09 04:44 UTC -> 2026-06-09 08:46 UTC (242 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 66
- **Skip-Runs:** 64
- **Fehlgeschlagene Runs:** 25
- **Lucken >210min:** 13
- **Groesste Lucke:** 2026-06-04 22:16 UTC -> 2026-06-05 04:41 UTC (385 min = 6h 25min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 184
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 44

Letzte Watchdog-Eingriffe:
- 2026-06-08 22:01 UTC (Run #27169771689, Laufzeit 21m 13s)
- 2026-06-09 01:30 UTC (Run #27178039230, Laufzeit 17m 23s)
- 2026-06-09 08:46 UTC (Run #27194704119, Laufzeit 21m 27s)
- 2026-06-09 10:03 UTC (Run #27198790835, Laufzeit 21m 50s)
- 2026-06-09 12:51 UTC (Run #27207362088, Laufzeit 22m 6s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-06-06 14:20 UTC - cancelled - Run #27064723617 (5m 10s)
- 2026-06-07 05:04 UTC - cancelled - Run #27083345206 (7m 42s)
- 2026-06-07 09:44 UTC - cancelled - Run #27088980124 (6m 55s)
- 2026-06-07 09:51 UTC - cancelled - Run #27089123760 (4m 17s)
- 2026-06-07 16:25 UTC - cancelled - Run #27098172676 (2m 57s)
- 2026-06-08 05:10 UTC - cancelled - Run #27117335945 (7m 23s)
- 2026-06-08 11:24 UTC - cancelled - Run #27134325320 (6m 22s)
- 2026-06-08 11:30 UTC - cancelled - Run #27134632211 (7m 35s)
- 2026-06-09 10:07 UTC - cancelled - Run #27198974335 (16m 34s)
- 2026-06-09 10:23 UTC - cancelled - Run #27199810485 (1m 46s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
