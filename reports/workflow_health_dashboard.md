# Workflow Health Dashboard

**Stand:** 2026-09-27 18:55 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 8 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 9
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-09-27 02:56 CEST (Europe/Berlin) -> 2026-09-27 07:08 CEST (Europe/Berlin) (251 min)
  - 2026-09-27 08:51 CEST (Europe/Berlin) -> 2026-09-27 13:54 CEST (Europe/Berlin) (302 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 73
- **Skip-Runs:** 67
- **Fehlgeschlagene Runs:** 3
- **Lucken >210min:** 8
- **Groesste Lucke:** 2026-09-27 08:51 CEST (Europe/Berlin) -> 2026-09-27 13:54 CEST (Europe/Berlin) (302 min = 5h 2min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 285
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 55

Letzte Watchdog-Eingriffe:
- 2026-09-26 20:33 CEST (Europe/Berlin) (Run #36262972872, Laufzeit 17m 32s)
- 2026-09-26 21:29 CEST (Europe/Berlin) (Run #36266228891, Laufzeit 20m 14s)
- 2026-09-26 23:32 CEST (Europe/Berlin) (Run #36273264367, Laufzeit 21m 3s)
- 2026-09-27 02:42 CEST (Europe/Berlin) (Run #36283304197, Laufzeit 14m 32s)
- 2026-09-27 08:34 CEST (Europe/Berlin) (Run #36300483363, Laufzeit 17m 7s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-09-21 02:31 CEST (Europe/Berlin) - cancelled - Run #35547981772 (5m 42s)
- 2026-09-23 19:43 CEST (Europe/Berlin) - cancelled - Run #35897617505 (2m 6s)
- 2026-09-26 14:28 CEST (Europe/Berlin) - cancelled - Run #36242007151 (4m 18s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
