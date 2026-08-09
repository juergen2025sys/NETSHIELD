# Workflow Health Report

**Stand:** 2026-08-09 20:55 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 19 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 6
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 88
- **Skip-Runs:** 28
- **Fehlgeschlagene Runs:** 71
- **Lucken >210min:** 1
- **Groesste Lucke:** 2026-08-05 13:58 CEST (Europe/Berlin) -> 2026-08-07 21:08 CEST (Europe/Berlin) (3309 min = 55h 9min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 330
- **Watchdog-Fehler:** 2
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 39

Letzte Watchdog-Eingriffe:
- 2026-08-09 06:07 CEST (Europe/Berlin) (Run #31293894733, Laufzeit 35m 49s)
- 2026-08-09 08:31 CEST (Europe/Berlin) (Run #31299068926, Laufzeit 2s)
- 2026-08-09 08:45 CEST (Europe/Berlin) (Run #31299598098, Laufzeit 37m 1s)
- 2026-08-09 17:47 CEST (Europe/Berlin) (Run #31322037756, Laufzeit 89m 21s)
- 2026-08-09 17:54 CEST (Europe/Berlin) (Run #31322354608, Laufzeit 122m 6s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-08-07 17:09 CEST (Europe/Berlin) - failure - Run #31191234375 (37m 33s)
- 2026-08-07 18:02 CEST (Europe/Berlin) - failure - Run #31195605518 (33m 29s)
- 2026-08-07 18:13 CEST (Europe/Berlin) - failure - Run #31196561654 (58m 27s)
- 2026-08-07 18:34 CEST (Europe/Berlin) - failure - Run #31198213491 (73m 55s)
- 2026-08-07 20:02 CEST (Europe/Berlin) - cancelled - Run #31205138173 (10m 39s)
- 2026-08-07 20:12 CEST (Europe/Berlin) - failure - Run #31205878843 (31m 31s)
- 2026-08-08 21:06 CEST (Europe/Berlin) - action_required - Run #31273617530 (0s)
- 2026-08-09 08:31 CEST (Europe/Berlin) - action_required - Run #31299068926 (2s)
- 2026-08-09 17:55 CEST (Europe/Berlin) - cancelled - Run #31322406332 (125m 20s)
- 2026-08-09 18:04 CEST (Europe/Berlin) - cancelled - Run #31322806850 (115m 26s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
