# Workflow Health Dashboard

**Stand:** 2026-09-12 12:39 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 10 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 15
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-09-12 02:50 CEST (Europe/Berlin) -> 2026-09-12 06:23 CEST (Europe/Berlin) (213 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 70
- **Skip-Runs:** 84
- **Fehlgeschlagene Runs:** 5
- **Lucken >210min:** 6
- **Groesste Lucke:** 2026-09-06 06:42 CEST (Europe/Berlin) -> 2026-09-06 10:50 CEST (Europe/Berlin) (247 min = 4h 7min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 325
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 54

Letzte Watchdog-Eingriffe:
- 2026-09-12 08:27 CEST (Europe/Berlin) (Run #34678193920, Laufzeit 20m 51s)
- 2026-09-12 10:54 CEST (Europe/Berlin) (Run #34684445124, Laufzeit 34m 43s)
- 2026-09-12 11:30 CEST (Europe/Berlin) (Run #34686028170, Laufzeit 7m 15s)
- 2026-09-12 11:38 CEST (Europe/Berlin) (Run #34686370369, Laufzeit 1m 22s)
- 2026-09-12 11:49 CEST (Europe/Berlin) (Run #34686827690, Laufzeit 18m 22s)

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
