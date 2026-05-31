# Workflow Health Report

**Stand:** 2026-05-31 09:19 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 11 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 8
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-05-30 22:42 UTC -> 2026-05-31 04:46 UTC (363 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 68
- **Skip-Runs:** 63
- **Fehlgeschlagene Runs:** 22
- **Lucken >210min:** 7
- **Groesste Lucke:** 2026-05-28 21:59 UTC -> 2026-05-29 04:36 UTC (397 min = 6h 37min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 77
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 37

Letzte Watchdog-Eingriffe:
- 2026-05-30 09:48 UTC (Run #26680775839, Laufzeit 23m 34s)
- 2026-05-30 11:48 UTC (Run #26683037133, Laufzeit 23m 51s)
- 2026-05-30 18:46 UTC (Run #26691963858, Laufzeit 23m 42s)
- 2026-05-31 08:00 UTC (Run #26707155296, Laufzeit 8m 8s)
- 2026-05-31 08:20 UTC (Run #26707560101, Laufzeit 25m 10s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-05-27 23:04 UTC - cancelled - Run #26543935463 (5s)
- 2026-05-28 16:37 UTC - cancelled - Run #26588251011 (6m 21s)
- 2026-05-28 16:43 UTC - cancelled - Run #26588591330 (7s)
- 2026-05-30 04:32 UTC - cancelled - Run #26674562614 (7m 24s)
- 2026-05-30 04:39 UTC - cancelled - Run #26674707879 (3s)
- 2026-05-30 14:12 UTC - cancelled - Run #26685945503 (5m 55s)
- 2026-05-30 14:17 UTC - cancelled - Run #26686069424 (4s)
- 2026-05-31 04:58 UTC - cancelled - Run #26703729739 (11m 19s)
- 2026-05-31 05:09 UTC - cancelled - Run #26703939050 (4s)
- 2026-05-31 08:00 UTC - cancelled - Run #26707155296 (8m 8s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
