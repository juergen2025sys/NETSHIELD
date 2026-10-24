# Workflow Health Dashboard

**Stand:** 2026-10-24 12:50 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 8 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 10
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-10-24 02:21 CEST (Europe/Berlin) -> 2026-10-24 06:24 CEST (Europe/Berlin) (242 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 61
- **Skip-Runs:** 68
- **Fehlgeschlagene Runs:** 0
- **Lucken >210min:** 8
- **Groesste Lucke:** 2026-10-20 02:29 CEST (Europe/Berlin) -> 2026-10-20 07:12 CEST (Europe/Berlin) (283 min = 4h 43min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 293
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 38

Letzte Watchdog-Eingriffe:
- 2026-10-23 11:43 CEST (Europe/Berlin) (Run #39933980375, Laufzeit 19m 1s)
- 2026-10-23 17:30 CEST (Europe/Berlin) (Run #39978887381, Laufzeit 19m 27s)
- 2026-10-23 20:36 CEST (Europe/Berlin) (Run #40004695001, Laufzeit 19m 44s)
- 2026-10-24 08:27 CEST (Europe/Berlin) (Run #40070308730, Laufzeit 20m 15s)
- 2026-10-24 11:49 CEST (Europe/Berlin) (Run #40083473999, Laufzeit 19m 35s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
