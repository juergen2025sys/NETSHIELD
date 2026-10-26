# Workflow Health Dashboard

**Stand:** 2026-10-26 05:36 CET (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 7 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 12
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-10-25 05:43 CET (Europe/Berlin) -> 2026-10-25 10:28 CET (Europe/Berlin) (284 min)
  - 2026-10-25 13:11 CET (Europe/Berlin) -> 2026-10-25 17:00 CET (Europe/Berlin) (229 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 58
- **Skip-Runs:** 69
- **Fehlgeschlagene Runs:** 1
- **Lucken >210min:** 10
- **Groesste Lucke:** 2026-10-25 05:43 CET (Europe/Berlin) -> 2026-10-25 10:28 CET (Europe/Berlin) (284 min = 4h 44min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 287
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 38

Letzte Watchdog-Eingriffe:
- 2026-10-25 20:45 CET (Europe/Berlin) (Run #40227550694, Laufzeit 16m 36s)
- 2026-10-25 21:18 CET (Europe/Berlin) (Run #40230139707, Laufzeit 15m 35s)
- 2026-10-25 23:07 CET (Europe/Berlin) (Run #40238710495, Laufzeit 21m 26s)
- 2026-10-26 01:43 CET (Europe/Berlin) (Run #40250723975, Laufzeit 3m 10s)
- 2026-10-26 01:46 CET (Europe/Berlin) (Run #40250971294, Laufzeit 17m 21s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-10-26 01:43 CET (Europe/Berlin) - cancelled - Run #40250723975 (3m 10s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
