# Workflow Health Dashboard

**Stand:** 2026-10-22 19:05 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 8 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 10
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-10-22 08:55 CEST (Europe/Berlin) -> 2026-10-22 12:45 CEST (Europe/Berlin) (230 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 63
- **Skip-Runs:** 68
- **Fehlgeschlagene Runs:** 0
- **Lucken >210min:** 7
- **Groesste Lucke:** 2026-10-20 02:29 CEST (Europe/Berlin) -> 2026-10-20 07:12 CEST (Europe/Berlin) (283 min = 4h 43min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 300
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 39

Letzte Watchdog-Eingriffe:
- 2026-10-22 02:43 CEST (Europe/Berlin) (Run #39701372796, Laufzeit 17m 9s)
- 2026-10-22 08:40 CEST (Europe/Berlin) (Run #39735424142, Laufzeit 14m 37s)
- 2026-10-22 12:45 CEST (Europe/Berlin) (Run #39765534974, Laufzeit 18m 11s)
- 2026-10-22 14:32 CEST (Europe/Berlin) (Run #39779183940, Laufzeit 12m 45s)
- 2026-10-22 17:45 CEST (Europe/Berlin) (Run #39807850439, Laufzeit 20m 15s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
