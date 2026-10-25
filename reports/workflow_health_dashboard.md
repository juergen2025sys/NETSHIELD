# Workflow Health Dashboard

**Stand:** 2026-10-25 21:45 CET (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 10
- **Lucken (>210min zwischen echten Runs):** 3
  - 2026-10-25 02:49 CEST (Europe/Berlin) -> 2026-10-25 05:28 CET (Europe/Berlin) (218 min)
  - 2026-10-25 05:43 CET (Europe/Berlin) -> 2026-10-25 10:28 CET (Europe/Berlin) (284 min)
  - 2026-10-25 13:11 CET (Europe/Berlin) -> 2026-10-25 17:00 CET (Europe/Berlin) (229 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 60
- **Skip-Runs:** 67
- **Fehlgeschlagene Runs:** 0
- **Lucken >210min:** 11
- **Groesste Lucke:** 2026-10-25 05:43 CET (Europe/Berlin) -> 2026-10-25 10:28 CET (Europe/Berlin) (284 min = 4h 44min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 287
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 36

Letzte Watchdog-Eingriffe:
- 2026-10-24 21:09 CEST (Europe/Berlin) (Run #40123993243, Laufzeit 21m 1s)
- 2026-10-25 02:30 CEST (Europe/Berlin) (Run #40146995706, Laufzeit 18m 16s)
- 2026-10-25 10:28 CET (Europe/Berlin) (Run #40180773655, Laufzeit 19m 9s)
- 2026-10-25 20:45 CET (Europe/Berlin) (Run #40227550694, Laufzeit 16m 36s)
- 2026-10-25 21:18 CET (Europe/Berlin) (Run #40230139707, Laufzeit 15m 35s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
