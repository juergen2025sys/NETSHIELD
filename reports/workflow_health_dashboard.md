# Workflow Health Dashboard

**Stand:** 2026-10-14 06:45 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 6 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 5
- **Lucken (>210min zwischen echten Runs):** 3
  - 2026-10-13 08:54 CEST (Europe/Berlin) -> 2026-10-13 12:51 CEST (Europe/Berlin) (236 min)
  - 2026-10-13 13:10 CEST (Europe/Berlin) -> 2026-10-13 17:06 CEST (Europe/Berlin) (235 min)
  - 2026-10-13 17:22 CEST (Europe/Berlin) -> 2026-10-13 21:24 CEST (Europe/Berlin) (242 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 54
- **Skip-Runs:** 51
- **Fehlgeschlagene Runs:** 0
- **Lucken >210min:** 10
- **Groesste Lucke:** 2026-10-11 08:53 CEST (Europe/Berlin) -> 2026-10-11 14:37 CEST (Europe/Berlin) (344 min = 5h 44min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 206
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 35

Letzte Watchdog-Eingriffe:
- 2026-10-12 21:10 CEST (Europe/Berlin) (Run #38295838581, Laufzeit 20m 1s)
- 2026-10-13 02:36 CEST (Europe/Berlin) (Run #38328101173, Laufzeit 15m 44s)
- 2026-10-13 05:44 CEST (Europe/Berlin) (Run #38343123069, Laufzeit 17m 52s)
- 2026-10-13 17:06 CEST (Europe/Berlin) (Run #38419127975, Laufzeit 16m 20s)
- 2026-10-13 23:31 CEST (Europe/Berlin) (Run #38471285852, Laufzeit 19m 4s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
