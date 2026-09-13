# Workflow Health Dashboard

**Stand:** 2026-09-13 06:39 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 10 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 13
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 70
- **Skip-Runs:** 83
- **Fehlgeschlagene Runs:** 5
- **Lucken >210min:** 5
- **Groesste Lucke:** 2026-09-10 14:12 CEST (Europe/Berlin) -> 2026-09-10 17:55 CEST (Europe/Berlin) (223 min = 3h 43min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 337
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 57

Letzte Watchdog-Eingriffe:
- 2026-09-12 20:34 CEST (Europe/Berlin) (Run #34711632318, Laufzeit 23m 26s)
- 2026-09-12 21:23 CEST (Europe/Berlin) (Run #34714051348, Laufzeit 15m 19s)
- 2026-09-12 21:59 CEST (Europe/Berlin) (Run #34715745745, Laufzeit 22m 41s)
- 2026-09-12 23:33 CEST (Europe/Berlin) (Run #34720271504, Laufzeit 17m 34s)
- 2026-09-13 03:10 CEST (Europe/Berlin) (Run #34729851747, Laufzeit 22m 39s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-09-06 17:22 CEST (Europe/Berlin) - failure - Run #34042104282 (19m 11s)
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
