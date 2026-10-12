# Workflow Health Dashboard

**Stand:** 2026-10-12 07:48 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 6 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 9
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-10-11 08:53 CEST (Europe/Berlin) -> 2026-10-11 14:37 CEST (Europe/Berlin) (344 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 61
- **Skip-Runs:** 55
- **Fehlgeschlagene Runs:** 2
- **Lucken >210min:** 7
- **Groesste Lucke:** 2026-10-11 08:53 CEST (Europe/Berlin) -> 2026-10-11 14:37 CEST (Europe/Berlin) (344 min = 5h 44min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 210
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 48

Letzte Watchdog-Eingriffe:
- 2026-10-10 20:41 CEST (Europe/Berlin) (Run #38076762903, Laufzeit 19m 16s)
- 2026-10-11 08:33 CEST (Europe/Berlin) (Run #38118435692, Laufzeit 19m 50s)
- 2026-10-11 17:52 CEST (Europe/Berlin) (Run #38153122053, Laufzeit 19m 57s)
- 2026-10-11 20:30 CEST (Europe/Berlin) (Run #38164066444, Laufzeit 16m 39s)
- 2026-10-12 00:10 CEST (Europe/Berlin) (Run #38179386975, Laufzeit 17m 7s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-10-06 08:08 CEST (Europe/Berlin) - failure - Run #37422154292 (20m 8s)
- 2026-10-06 21:34 CEST (Europe/Berlin) - failure - Run #37519985347 (13m 50s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
