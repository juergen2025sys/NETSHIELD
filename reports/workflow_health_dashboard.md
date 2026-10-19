# Workflow Health Dashboard

**Stand:** 2026-10-20 00:17 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 9
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-10-19 02:52 CEST (Europe/Berlin) -> 2026-10-19 06:27 CEST (Europe/Berlin) (214 min)
  - 2026-10-19 08:57 CEST (Europe/Berlin) -> 2026-10-19 12:42 CEST (Europe/Berlin) (225 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 61
- **Skip-Runs:** 62
- **Fehlgeschlagene Runs:** 0
- **Lucken >210min:** 8
- **Groesste Lucke:** 2026-10-13 17:22 CEST (Europe/Berlin) -> 2026-10-13 21:24 CEST (Europe/Berlin) (242 min = 4h 2min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 289
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 35

Letzte Watchdog-Eingriffe:
- 2026-10-19 08:43 CEST (Europe/Berlin) (Run #39211544700, Laufzeit 14m 2s)
- 2026-10-19 12:42 CEST (Europe/Berlin) (Run #39239356244, Laufzeit 16m 25s)
- 2026-10-19 18:35 CEST (Europe/Berlin) (Run #39286687814, Laufzeit 20m 17s)
- 2026-10-19 21:28 CEST (Europe/Berlin) (Run #39311260737, Laufzeit 17m 20s)
- 2026-10-19 23:39 CEST (Europe/Berlin) (Run #39329217874, Laufzeit 15m 38s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
