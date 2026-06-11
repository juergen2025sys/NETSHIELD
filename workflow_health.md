# Workflow Health Report

**Stand:** 2026-06-11 16:18 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 10
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-06-11 10:11 UTC -> 2026-06-11 14:15 UTC (243 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 67
- **Skip-Runs:** 71
- **Fehlgeschlagene Runs:** 21
- **Lucken >210min:** 9
- **Groesste Lucke:** 2026-06-04 22:16 UTC -> 2026-06-05 04:41 UTC (385 min = 6h 25min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 198
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 45

Letzte Watchdog-Eingriffe:
- 2026-06-11 01:40 UTC (Run #27318087145, Laufzeit 19m 48s)
- 2026-06-11 07:04 UTC (Run #27329935628, Laufzeit 20m 39s)
- 2026-06-11 09:50 UTC (Run #27338564199, Laufzeit 21m 3s)
- 2026-06-11 14:15 UTC (Run #27353260701, Laufzeit 21m 6s)
- 2026-06-11 15:27 UTC (Run #27358031005, Laufzeit 21m 25s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-06-08 11:24 UTC - cancelled - Run #27134325320 (6m 22s)
- 2026-06-08 11:30 UTC - cancelled - Run #27134632211 (7m 35s)
- 2026-06-09 10:07 UTC - cancelled - Run #27198974335 (16m 34s)
- 2026-06-09 10:23 UTC - cancelled - Run #27199810485 (1m 46s)
- 2026-06-09 15:36 UTC - cancelled - Run #27217535905 (8m 4s)
- 2026-06-09 15:44 UTC - cancelled - Run #27218026088 (2m 44s)
- 2026-06-10 04:55 UTC - cancelled - Run #27254161716 (6m 6s)
- 2026-06-10 15:59 UTC - failure - Run #27288776680 (21m 19s)
- 2026-06-10 16:26 UTC - cancelled - Run #27290192234 (12m 6s)
- 2026-06-11 05:07 UTC - cancelled - Run #27325175029 (5m 31s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
