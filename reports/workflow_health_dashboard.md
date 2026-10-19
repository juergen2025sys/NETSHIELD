# Workflow Health Dashboard

**Stand:** 2026-10-19 14:59 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 8
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-10-19 02:52 CEST (Europe/Berlin) -> 2026-10-19 06:27 CEST (Europe/Berlin) (214 min)
  - 2026-10-19 08:57 CEST (Europe/Berlin) -> 2026-10-19 12:42 CEST (Europe/Berlin) (225 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 60
- **Skip-Runs:** 59
- **Fehlgeschlagene Runs:** 0
- **Lucken >210min:** 8
- **Groesste Lucke:** 2026-10-13 17:22 CEST (Europe/Berlin) -> 2026-10-13 21:24 CEST (Europe/Berlin) (242 min = 4h 2min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 283
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 34

Letzte Watchdog-Eingriffe:
- 2026-10-18 15:22 CEST (Europe/Berlin) (Run #39131272416, Laufzeit 13m 51s)
- 2026-10-18 21:02 CEST (Europe/Berlin) (Run #39156895967, Laufzeit 18m 58s)
- 2026-10-19 02:31 CEST (Europe/Berlin) (Run #39181179365, Laufzeit 20m 55s)
- 2026-10-19 08:43 CEST (Europe/Berlin) (Run #39211544700, Laufzeit 14m 2s)
- 2026-10-19 12:42 CEST (Europe/Berlin) (Run #39239356244, Laufzeit 16m 25s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
