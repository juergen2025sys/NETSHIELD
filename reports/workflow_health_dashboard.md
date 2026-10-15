# Workflow Health Dashboard

**Stand:** 2026-10-15 18:52 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 8 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 10
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-10-15 14:08 CEST (Europe/Berlin) -> 2026-10-15 17:50 CEST (Europe/Berlin) (221 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 51
- **Skip-Runs:** 52
- **Fehlgeschlagene Runs:** 0
- **Lucken >210min:** 11
- **Groesste Lucke:** 2026-10-11 08:53 CEST (Europe/Berlin) -> 2026-10-11 14:37 CEST (Europe/Berlin) (344 min = 5h 44min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 223
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 29

Letzte Watchdog-Eingriffe:
- 2026-10-14 20:48 CEST (Europe/Berlin) (Run #38618232927, Laufzeit 18m 45s)
- 2026-10-15 02:46 CEST (Europe/Berlin) (Run #38661954107, Laufzeit 19m 25s)
- 2026-10-15 08:29 CEST (Europe/Berlin) (Run #38692715592, Laufzeit 18m 8s)
- 2026-10-15 11:28 CEST (Europe/Berlin) (Run #38713168916, Laufzeit 19m 8s)
- 2026-10-15 17:50 CEST (Europe/Berlin) (Run #38763878076, Laufzeit 19m 27s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
