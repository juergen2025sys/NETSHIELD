# Workflow Health Dashboard

**Stand:** 2026-09-13 18:11 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 11 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 12
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 72
- **Skip-Runs:** 84
- **Fehlgeschlagene Runs:** 4
- **Lucken >210min:** 5
- **Groesste Lucke:** 2026-09-10 14:12 CEST (Europe/Berlin) -> 2026-09-10 17:55 CEST (Europe/Berlin) (223 min = 3h 43min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 334
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 61

Letzte Watchdog-Eingriffe:
- 2026-09-13 08:44 CEST (Europe/Berlin) (Run #34743501067, Laufzeit 15m 30s)
- 2026-09-13 10:14 CEST (Europe/Berlin) (Run #34747178849, Laufzeit 19m 57s)
- 2026-09-13 12:29 CEST (Europe/Berlin) (Run #34751986417, Laufzeit 19m 31s)
- 2026-09-13 14:29 CEST (Europe/Berlin) (Run #34757218579, Laufzeit 19m 37s)
- 2026-09-13 18:01 CEST (Europe/Berlin) (Run #34767304040, Laufzeit 9s)

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
