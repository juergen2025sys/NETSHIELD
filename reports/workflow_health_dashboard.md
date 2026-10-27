# Workflow Health Dashboard

**Stand:** 2026-10-27 23:07 CET (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 8 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 8
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-10-27 01:43 CET (Europe/Berlin) -> 2026-10-27 06:24 CET (Europe/Berlin) (281 min)
  - 2026-10-27 10:11 CET (Europe/Berlin) -> 2026-10-27 13:47 CET (Europe/Berlin) (216 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 58
- **Skip-Runs:** 67
- **Fehlgeschlagene Runs:** 1
- **Lucken >210min:** 11
- **Groesste Lucke:** 2026-10-25 05:43 CET (Europe/Berlin) -> 2026-10-25 10:28 CET (Europe/Berlin) (284 min = 4h 44min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 283
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 37

Letzte Watchdog-Eingriffe:
- 2026-10-27 06:24 CET (Europe/Berlin) (Run #40455144447, Laufzeit 19m 25s)
- 2026-10-27 07:47 CET (Europe/Berlin) (Run #40463197935, Laufzeit 19m 4s)
- 2026-10-27 13:47 CET (Europe/Berlin) (Run #40506564039, Laufzeit 16m 50s)
- 2026-10-27 19:49 CET (Europe/Berlin) (Run #40563507578, Laufzeit 17m 28s)
- 2026-10-27 22:27 CET (Europe/Berlin) (Run #40586884250, Laufzeit 20m 12s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-10-26 01:43 CET (Europe/Berlin) - cancelled - Run #40250723975 (3m 10s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
