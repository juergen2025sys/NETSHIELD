# Workflow Health Dashboard

**Stand:** 2026-10-06 20:19 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 12 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 7
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 92
- **Skip-Runs:** 56
- **Fehlgeschlagene Runs:** 1
- **Lucken >210min:** 3
- **Groesste Lucke:** 2026-10-02 03:19 CEST (Europe/Berlin) -> 2026-10-02 07:29 CEST (Europe/Berlin) (250 min = 4h 10min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 231
- **Watchdog-Fehler:** 1
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 74

Letzte Watchdog-Eingriffe:
- 2026-10-06 12:50 CEST (Europe/Berlin) (Run #37452439952, Laufzeit 18m 14s)
- 2026-10-06 16:10 CEST (Europe/Berlin) (Run #37476687434, Laufzeit 20m 39s)
- 2026-10-06 17:05 CEST (Europe/Berlin) (Run #37484421757, Laufzeit 16m 19s)
- 2026-10-06 18:00 CEST (Europe/Berlin) (Run #37492229446, Laufzeit 19m 14s)
- 2026-10-06 19:01 CEST (Europe/Berlin) (Run #37500273738, Laufzeit 24m 50s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-10-06 08:08 CEST (Europe/Berlin) - failure - Run #37422154292 (20m 8s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
