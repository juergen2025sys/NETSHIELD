# Workflow Health Dashboard

**Stand:** 2026-09-08 23:05 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 12 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 11
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-09-08 02:52 CEST (Europe/Berlin) -> 2026-09-08 06:23 CEST (Europe/Berlin) (210 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 68
- **Skip-Runs:** 78
- **Fehlgeschlagene Runs:** 4
- **Lucken >210min:** 4
- **Groesste Lucke:** 2026-09-06 06:42 CEST (Europe/Berlin) -> 2026-09-06 10:50 CEST (Europe/Berlin) (247 min = 4h 7min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 285
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 47

Letzte Watchdog-Eingriffe:
- 2026-09-08 13:52 CEST (Europe/Berlin) (Run #34222969839, Laufzeit 21m 54s)
- 2026-09-08 17:26 CEST (Europe/Berlin) (Run #34244807050, Laufzeit 21m 2s)
- 2026-09-08 20:37 CEST (Europe/Berlin) (Run #34264191058, Laufzeit 21m 4s)
- 2026-09-08 20:59 CEST (Europe/Berlin) (Run #34266292775, Laufzeit 27m 9s)
- 2026-09-08 22:01 CEST (Europe/Berlin) (Run #34272346818, Laufzeit 16m 45s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-09-02 18:28 CEST (Europe/Berlin) - action_required - Run #33655138414 (0s)
- 2026-09-03 20:53 CEST (Europe/Berlin) - cancelled - Run #33793182301 (8m 11s)
- 2026-09-04 15:51 CEST (Europe/Berlin) - cancelled - Run #33880368309 (2m 13s)
- 2026-09-06 17:22 CEST (Europe/Berlin) - failure - Run #34042104282 (19m 11s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
