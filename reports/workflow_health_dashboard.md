# Workflow Health Dashboard

**Stand:** 2026-09-29 14:43 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 13 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 7
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-09-28 23:32 CEST (Europe/Berlin) -> 2026-09-29 03:06 CEST (Europe/Berlin) (214 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 77
- **Skip-Runs:** 62
- **Fehlgeschlagene Runs:** 2
- **Lucken >210min:** 9
- **Groesste Lucke:** 2026-09-27 08:51 CEST (Europe/Berlin) -> 2026-09-27 13:54 CEST (Europe/Berlin) (302 min = 5h 2min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 273
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 56

Letzte Watchdog-Eingriffe:
- 2026-09-28 20:17 CEST (Europe/Berlin) (Run #36464195880, Laufzeit 22m 4s)
- 2026-09-29 03:55 CEST (Europe/Berlin) (Run #36510204008, Laufzeit 21m 30s)
- 2026-09-29 04:45 CEST (Europe/Berlin) (Run #36514107594, Laufzeit 20m 56s)
- 2026-09-29 09:03 CEST (Europe/Berlin) (Run #36534401199, Laufzeit 20m 51s)
- 2026-09-29 10:50 CEST (Europe/Berlin) (Run #36545231880, Laufzeit 20m 56s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-09-23 19:43 CEST (Europe/Berlin) - cancelled - Run #35897617505 (2m 6s)
- 2026-09-26 14:28 CEST (Europe/Berlin) - cancelled - Run #36242007151 (4m 18s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
