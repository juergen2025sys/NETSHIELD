# Workflow Health Dashboard

**Stand:** 2026-09-14 14:36 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 10
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-09-14 02:54 CEST (Europe/Berlin) -> 2026-09-14 06:43 CEST (Europe/Berlin) (229 min)
  - 2026-09-14 09:02 CEST (Europe/Berlin) -> 2026-09-14 13:03 CEST (Europe/Berlin) (241 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 74
- **Skip-Runs:** 85
- **Fehlgeschlagene Runs:** 4
- **Lucken >210min:** 7
- **Groesste Lucke:** 2026-09-14 09:02 CEST (Europe/Berlin) -> 2026-09-14 13:03 CEST (Europe/Berlin) (241 min = 4h 1min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 327
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 61

Letzte Watchdog-Eingriffe:
- 2026-09-13 20:39 CEST (Europe/Berlin) (Run #34775308225, Laufzeit 14m 43s)
- 2026-09-13 23:27 CEST (Europe/Berlin) (Run #34783871393, Laufzeit 19m 30s)
- 2026-09-14 02:28 CEST (Europe/Berlin) (Run #34792817371, Laufzeit 25m 28s)
- 2026-09-14 08:42 CEST (Europe/Berlin) (Run #34814569816, Laufzeit 20m 23s)
- 2026-09-14 13:03 CEST (Europe/Berlin) (Run #34836259996, Laufzeit 20m 57s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-09-11 08:39 CEST (Europe/Berlin) - cancelled - Run #34570885903 (4m 2s)
- 2026-09-12 10:54 CEST (Europe/Berlin) - failure - Run #34684445124 (34m 43s)
- 2026-09-12 11:30 CEST (Europe/Berlin) - cancelled - Run #34686028170 (7m 15s)
- 2026-09-12 11:38 CEST (Europe/Berlin) - failure - Run #34686370369 (1m 22s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
