# Workflow Health Dashboard

**Stand:** 2026-10-13 16:04 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 8 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 4
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-10-13 08:54 CEST (Europe/Berlin) -> 2026-10-13 12:51 CEST (Europe/Berlin) (236 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 57
- **Skip-Runs:** 53
- **Fehlgeschlagene Runs:** 1
- **Lucken >210min:** 10
- **Groesste Lucke:** 2026-10-11 08:53 CEST (Europe/Berlin) -> 2026-10-11 14:37 CEST (Europe/Berlin) (344 min = 5h 44min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 208
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 41

Letzte Watchdog-Eingriffe:
- 2026-10-12 11:49 CEST (Europe/Berlin) (Run #38232341108, Laufzeit 19m 48s)
- 2026-10-12 17:53 CEST (Europe/Berlin) (Run #38273524465, Laufzeit 20m 26s)
- 2026-10-12 21:10 CEST (Europe/Berlin) (Run #38295838581, Laufzeit 20m 1s)
- 2026-10-13 02:36 CEST (Europe/Berlin) (Run #38328101173, Laufzeit 15m 44s)
- 2026-10-13 05:44 CEST (Europe/Berlin) (Run #38343123069, Laufzeit 17m 52s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-10-06 21:34 CEST (Europe/Berlin) - failure - Run #37519985347 (13m 50s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
