# Workflow Health Dashboard

**Stand:** 2026-08-12 15:39 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 8 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 21
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-08-12 00:17 CEST (Europe/Berlin) -> 2026-08-12 04:35 CEST (Europe/Berlin) (257 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 70
- **Skip-Runs:** 64
- **Fehlgeschlagene Runs:** 74
- **Lucken >210min:** 2
- **Groesste Lucke:** 2026-08-12 00:17 CEST (Europe/Berlin) -> 2026-08-12 04:35 CEST (Europe/Berlin) (257 min = 4h 17min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 412
- **Watchdog-Fehler:** 3
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 46

Letzte Watchdog-Eingriffe:
- 2026-08-11 20:31 CEST (Europe/Berlin) (Run #31523136983, Laufzeit 20m 37s)
- 2026-08-12 06:25 CEST (Europe/Berlin) (Run #31563241860, Laufzeit 38m 32s)
- 2026-08-12 08:54 CEST (Europe/Berlin) (Run #31571789739, Laufzeit 21m 56s)
- 2026-08-12 11:44 CEST (Europe/Berlin) (Run #31584309522, Laufzeit 20m 10s)
- 2026-08-12 14:28 CEST (Europe/Berlin) (Run #31596645747, Laufzeit 23m 1s)

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
