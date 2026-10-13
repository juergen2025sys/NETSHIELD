# Workflow Health Dashboard

**Stand:** 2026-10-13 02:34 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 5 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 7
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-10-12 02:39 CEST (Europe/Berlin) -> 2026-10-12 08:19 CEST (Europe/Berlin) (340 min)
  - 2026-10-12 12:09 CEST (Europe/Berlin) -> 2026-10-12 17:53 CEST (Europe/Berlin) (344 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 57
- **Skip-Runs:** 52
- **Fehlgeschlagene Runs:** 2
- **Lucken >210min:** 9
- **Groesste Lucke:** 2026-10-11 08:53 CEST (Europe/Berlin) -> 2026-10-11 14:37 CEST (Europe/Berlin) (344 min = 5h 44min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 208
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 43

Letzte Watchdog-Eingriffe:
- 2026-10-12 00:10 CEST (Europe/Berlin) (Run #38179386975, Laufzeit 17m 7s)
- 2026-10-12 08:19 CEST (Europe/Berlin) (Run #38211999045, Laufzeit 20m 10s)
- 2026-10-12 11:49 CEST (Europe/Berlin) (Run #38232341108, Laufzeit 19m 48s)
- 2026-10-12 17:53 CEST (Europe/Berlin) (Run #38273524465, Laufzeit 20m 26s)
- 2026-10-12 21:10 CEST (Europe/Berlin) (Run #38295838581, Laufzeit 20m 1s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-10-06 08:08 CEST (Europe/Berlin) - failure - Run #37422154292 (20m 8s)
- 2026-10-06 21:34 CEST (Europe/Berlin) - failure - Run #37519985347 (13m 50s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
