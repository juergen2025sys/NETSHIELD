# Workflow Health Dashboard

**Stand:** 2026-08-23 14:59 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 11 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 23
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 61
- **Skip-Runs:** 159
- **Fehlgeschlagene Runs:** 5
- **Lucken >210min:** 1
- **Groesste Lucke:** 2026-08-19 06:13 CEST (Europe/Berlin) -> 2026-08-19 17:02 CEST (Europe/Berlin) (649 min = 10h 49min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 754
- **Watchdog-Fehler:** 1
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 58

Letzte Watchdog-Eingriffe:
- 2026-08-23 07:02 CEST (Europe/Berlin) (Run #32619377193, Laufzeit 22m 47s)
- 2026-08-23 08:39 CEST (Europe/Berlin) (Run #32623475476, Laufzeit 20m 52s)
- 2026-08-23 11:42 CEST (Europe/Berlin) (Run #32631754727, Laufzeit 16m 59s)
- 2026-08-23 12:08 CEST (Europe/Berlin) (Run #32632927397, Laufzeit 20m 55s)
- 2026-08-23 14:40 CEST (Europe/Berlin) (Run #32640043581, Laufzeit 1s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-08-16 19:36 CEST (Europe/Berlin) - failure - Run #31962089791 (3m 41s)
- 2026-08-16 19:43 CEST (Europe/Berlin) - cancelled - Run #31962436032 (3m 38s)
- 2026-08-16 19:47 CEST (Europe/Berlin) - cancelled - Run #31962640642 (40s)
- 2026-08-23 14:40 CEST (Europe/Berlin) - action_required - Run #32640043581 (1s)
- 2026-08-23 14:55 CEST (Europe/Berlin) - action_required - Run #32640807973 (0s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
