# Workflow Health Dashboard

**Stand:** 2026-08-14 21:09 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 14 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 23
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 93
- **Skip-Runs:** 112
- **Fehlgeschlagene Runs:** 12
- **Lucken >210min:** 4
- **Groesste Lucke:** 2026-08-13 00:17 CEST (Europe/Berlin) -> 2026-08-13 04:37 CEST (Europe/Berlin) (260 min = 4h 20min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 464
- **Watchdog-Fehler:** 1
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 50

Letzte Watchdog-Eingriffe:
- 2026-08-14 15:38 CEST (Europe/Berlin) (Run #31805357478, Laufzeit 23m 7s)
- 2026-08-14 16:11 CEST (Europe/Berlin) (Run #31808298109, Laufzeit 22m 27s)
- 2026-08-14 17:59 CEST (Europe/Berlin) (Run #31817148322, Laufzeit 25m 17s)
- 2026-08-14 20:02 CEST (Europe/Berlin) (Run #31826802254, Laufzeit 19m 54s)
- 2026-08-14 21:02 CEST (Europe/Berlin) (Run #31831466509, Laufzeit 11s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-08-09 17:55 CEST (Europe/Berlin) - cancelled - Run #31322406332 (125m 20s)
- 2026-08-09 18:04 CEST (Europe/Berlin) - cancelled - Run #31322806850 (115m 26s)
- 2026-08-09 20:57 CEST (Europe/Berlin) - cancelled - Run #31330367759 (50m 17s)
- 2026-08-09 21:00 CEST (Europe/Berlin) - cancelled - Run #31330530555 (44m 25s)
- 2026-08-09 21:09 CEST (Europe/Berlin) - cancelled - Run #31330921720 (36m 54s)
- 2026-08-09 21:19 CEST (Europe/Berlin) - cancelled - Run #31331350528 (27m 32s)
- 2026-08-10 18:05 CEST (Europe/Berlin) - action_required - Run #31407080526 (0s)
- 2026-08-12 05:10 CEST (Europe/Berlin) - failure - Run #31559262855 (10s)
- 2026-08-13 13:36 CEST (Europe/Berlin) - cancelled - Run #31696234312 (95m 18s)
- 2026-08-13 20:30 CEST (Europe/Berlin) - cancelled - Run #31731085374 (8m 7s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
