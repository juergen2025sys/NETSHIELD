# Workflow Health Dashboard

**Stand:** 2026-10-02 14:24 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 13 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 5
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-10-02 03:19 CEST (Europe/Berlin) -> 2026-10-02 07:29 CEST (Europe/Berlin) (250 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 89
- **Skip-Runs:** 55
- **Fehlgeschlagene Runs:** 1
- **Lucken >210min:** 8
- **Groesste Lucke:** 2026-09-27 08:51 CEST (Europe/Berlin) -> 2026-09-27 13:54 CEST (Europe/Berlin) (302 min = 5h 2min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 245
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 66

Letzte Watchdog-Eingriffe:
- 2026-10-01 21:29 CEST (Europe/Berlin) (Run #36914665069, Laufzeit 26m 16s)
- 2026-10-01 22:39 CEST (Europe/Berlin) (Run #36923140113, Laufzeit 19m 46s)
- 2026-10-02 07:29 CEST (Europe/Berlin) (Run #36969193381, Laufzeit 20m 43s)
- 2026-10-02 08:23 CEST (Europe/Berlin) (Run #36973325545, Laufzeit 20m 48s)
- 2026-10-02 13:14 CEST (Europe/Berlin) (Run #36999915864, Laufzeit 19m 34s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-09-26 14:28 CEST (Europe/Berlin) - cancelled - Run #36242007151 (4m 18s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
