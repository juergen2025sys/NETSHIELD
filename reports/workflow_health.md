# Workflow Health Report

**Stand:** 2026-08-08 07:08 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 10 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 4
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 86
- **Skip-Runs:** 38
- **Fehlgeschlagene Runs:** 70
- **Lucken >210min:** 1
- **Groesste Lucke:** 2026-08-05 11:58 UTC -> 2026-08-07 19:08 UTC (3309 min = 55h 9min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 269
- **Watchdog-Fehler:** 2
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 49

Letzte Watchdog-Eingriffe:
- 2026-08-07 15:09 UTC (Run #31191234375, Laufzeit 37m 33s)
- 2026-08-07 18:02 UTC (Run #31205138173, Laufzeit 10m 39s)
- 2026-08-07 18:12 UTC (Run #31205878843, Laufzeit 31m 31s)
- 2026-08-08 00:40 UTC (Run #31230748289, Laufzeit 51m 58s)
- 2026-08-08 03:52 UTC (Run #31238164010, Laufzeit 36m 21s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-08-07 11:58 UTC - failure - Run #31176255079 (32m 25s)
- 2026-08-07 13:22 UTC - failure - Run #31182310565 (27m 58s)
- 2026-08-07 13:46 UTC - failure - Run #31184282805 (37m 37s)
- 2026-08-07 13:59 UTC - failure - Run #31185300314 (60m 27s)
- 2026-08-07 15:09 UTC - failure - Run #31191234375 (37m 33s)
- 2026-08-07 16:02 UTC - failure - Run #31195605518 (33m 29s)
- 2026-08-07 16:13 UTC - failure - Run #31196561654 (58m 27s)
- 2026-08-07 16:34 UTC - failure - Run #31198213491 (73m 55s)
- 2026-08-07 18:02 UTC - cancelled - Run #31205138173 (10m 39s)
- 2026-08-07 18:12 UTC - failure - Run #31205878843 (31m 31s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
