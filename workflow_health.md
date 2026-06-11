# Workflow Health Report

**Stand:** 2026-06-11 04:55 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 8 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 8
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 66
- **Skip-Runs:** 71
- **Fehlgeschlagene Runs:** 23
- **Lucken >210min:** 9
- **Groesste Lucke:** 2026-06-04 22:16 UTC -> 2026-06-05 04:41 UTC (385 min = 6h 25min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 199
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 44

Letzte Watchdog-Eingriffe:
- 2026-06-10 06:42 UTC (Run #27258337976, Laufzeit 21m 26s)
- 2026-06-10 12:44 UTC (Run #27277095510, Laufzeit 21m 47s)
- 2026-06-10 19:54 UTC (Run #27302294962, Laufzeit 22m 2s)
- 2026-06-10 22:20 UTC (Run #27310074879, Laufzeit 21m 28s)
- 2026-06-11 01:40 UTC (Run #27318087145, Laufzeit 19m 48s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-06-08 05:10 UTC - cancelled - Run #27117335945 (7m 23s)
- 2026-06-08 11:24 UTC - cancelled - Run #27134325320 (6m 22s)
- 2026-06-08 11:30 UTC - cancelled - Run #27134632211 (7m 35s)
- 2026-06-09 10:07 UTC - cancelled - Run #27198974335 (16m 34s)
- 2026-06-09 10:23 UTC - cancelled - Run #27199810485 (1m 46s)
- 2026-06-09 15:36 UTC - cancelled - Run #27217535905 (8m 4s)
- 2026-06-09 15:44 UTC - cancelled - Run #27218026088 (2m 44s)
- 2026-06-10 04:55 UTC - cancelled - Run #27254161716 (6m 6s)
- 2026-06-10 15:59 UTC - failure - Run #27288776680 (21m 19s)
- 2026-06-10 16:26 UTC - cancelled - Run #27290192234 (12m 6s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
