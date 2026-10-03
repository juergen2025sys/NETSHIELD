# Workflow Health Dashboard

**Stand:** 2026-10-03 23:10 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 10
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-10-03 03:04 CEST (Europe/Berlin) -> 2026-10-03 07:07 CEST (Europe/Berlin) (242 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 90
- **Skip-Runs:** 56
- **Fehlgeschlagene Runs:** 0
- **Lucken >210min:** 8
- **Groesste Lucke:** 2026-09-27 08:51 CEST (Europe/Berlin) -> 2026-09-27 13:54 CEST (Europe/Berlin) (302 min = 5h 2min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 240
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 66

Letzte Watchdog-Eingriffe:
- 2026-10-03 12:23 CEST (Europe/Berlin) (Run #37116242730, Laufzeit 16m 40s)
- 2026-10-03 14:49 CEST (Europe/Berlin) (Run #37124098105, Laufzeit 20m 37s)
- 2026-10-03 16:46 CEST (Europe/Berlin) (Run #37130812936, Laufzeit 21m 7s)
- 2026-10-03 20:18 CEST (Europe/Berlin) (Run #37143685916, Laufzeit 20m 3s)
- 2026-10-03 21:35 CEST (Europe/Berlin) (Run #37148443347, Laufzeit 14m 55s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
