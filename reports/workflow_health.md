# Workflow Health Report

**Stand:** 2026-08-11 15:34 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 10 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 20
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 76
- **Skip-Runs:** 51
- **Fehlgeschlagene Runs:** 76
- **Lucken >210min:** 1
- **Groesste Lucke:** 2026-08-05 13:58 CEST (Europe/Berlin) -> 2026-08-07 21:08 CEST (Europe/Berlin) (3309 min = 55h 9min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 386
- **Watchdog-Fehler:** 3
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 45

Letzte Watchdog-Eingriffe:
- 2026-08-11 02:55 CEST (Europe/Berlin) (Run #31447665771, Laufzeit 19m 56s)
- 2026-08-11 06:13 CEST (Europe/Berlin) (Run #31457833457, Laufzeit 20m 39s)
- 2026-08-11 08:59 CEST (Europe/Berlin) (Run #31467158780, Laufzeit 19m 55s)
- 2026-08-11 11:32 CEST (Europe/Berlin) (Run #31478126598, Laufzeit 22m 3s)
- 2026-08-11 15:24 CEST (Europe/Berlin) (Run #31495983626, Laufzeit 11s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-08-07 20:12 CEST (Europe/Berlin) - failure - Run #31205878843 (31m 31s)
- 2026-08-08 21:06 CEST (Europe/Berlin) - action_required - Run #31273617530 (0s)
- 2026-08-09 08:31 CEST (Europe/Berlin) - action_required - Run #31299068926 (2s)
- 2026-08-09 17:55 CEST (Europe/Berlin) - cancelled - Run #31322406332 (125m 20s)
- 2026-08-09 18:04 CEST (Europe/Berlin) - cancelled - Run #31322806850 (115m 26s)
- 2026-08-09 20:57 CEST (Europe/Berlin) - cancelled - Run #31330367759 (50m 17s)
- 2026-08-09 21:00 CEST (Europe/Berlin) - cancelled - Run #31330530555 (44m 25s)
- 2026-08-09 21:09 CEST (Europe/Berlin) - cancelled - Run #31330921720 (36m 54s)
- 2026-08-09 21:19 CEST (Europe/Berlin) - cancelled - Run #31331350528 (27m 32s)
- 2026-08-10 18:05 CEST (Europe/Berlin) - action_required - Run #31407080526 (0s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
