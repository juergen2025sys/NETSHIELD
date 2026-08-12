# Workflow Health Dashboard

**Stand:** 2026-08-12 09:47 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 8 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 20
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-08-11 11:54 CEST (Europe/Berlin) -> 2026-08-11 15:24 CEST (Europe/Berlin) (210 min)
  - 2026-08-12 00:17 CEST (Europe/Berlin) -> 2026-08-12 04:35 CEST (Europe/Berlin) (257 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 73
- **Skip-Runs:** 59
- **Fehlgeschlagene Runs:** 75
- **Lucken >210min:** 3
- **Groesste Lucke:** 2026-08-05 13:58 CEST (Europe/Berlin) -> 2026-08-07 21:08 CEST (Europe/Berlin) (3309 min = 55h 9min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 406
- **Watchdog-Fehler:** 3
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 45

Letzte Watchdog-Eingriffe:
- 2026-08-11 15:24 CEST (Europe/Berlin) (Run #31495983626, Laufzeit 23m 11s)
- 2026-08-11 17:34 CEST (Europe/Berlin) (Run #31507732319, Laufzeit 20m 23s)
- 2026-08-11 20:31 CEST (Europe/Berlin) (Run #31523136983, Laufzeit 20m 37s)
- 2026-08-12 06:25 CEST (Europe/Berlin) (Run #31563241860, Laufzeit 38m 32s)
- 2026-08-12 08:54 CEST (Europe/Berlin) (Run #31571789739, Laufzeit 21m 56s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-08-08 21:06 CEST (Europe/Berlin) - action_required - Run #31273617530 (0s)
- 2026-08-09 08:31 CEST (Europe/Berlin) - action_required - Run #31299068926 (2s)
- 2026-08-09 17:55 CEST (Europe/Berlin) - cancelled - Run #31322406332 (125m 20s)
- 2026-08-09 18:04 CEST (Europe/Berlin) - cancelled - Run #31322806850 (115m 26s)
- 2026-08-09 20:57 CEST (Europe/Berlin) - cancelled - Run #31330367759 (50m 17s)
- 2026-08-09 21:00 CEST (Europe/Berlin) - cancelled - Run #31330530555 (44m 25s)
- 2026-08-09 21:09 CEST (Europe/Berlin) - cancelled - Run #31330921720 (36m 54s)
- 2026-08-09 21:19 CEST (Europe/Berlin) - cancelled - Run #31331350528 (27m 32s)
- 2026-08-10 18:05 CEST (Europe/Berlin) - action_required - Run #31407080526 (0s)
- 2026-08-12 05:10 CEST (Europe/Berlin) - failure - Run #31559262855 (10s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
