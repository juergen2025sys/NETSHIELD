# Workflow Health Dashboard

**Stand:** 2026-09-16 06:43 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 9
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 69
- **Skip-Runs:** 82
- **Fehlgeschlagene Runs:** 4
- **Lucken >210min:** 7
- **Groesste Lucke:** 2026-09-15 02:08 CEST (Europe/Berlin) -> 2026-09-15 06:43 CEST (Europe/Berlin) (274 min = 4h 34min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 326
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 56

Letzte Watchdog-Eingriffe:
- 2026-09-15 08:36 CEST (Europe/Berlin) (Run #34937698625, Laufzeit 16m 17s)
- 2026-09-15 11:39 CEST (Europe/Berlin) (Run #34953716838, Laufzeit 17m 23s)
- 2026-09-15 17:29 CEST (Europe/Berlin) (Run #34988746582, Laufzeit 20m 53s)
- 2026-09-15 20:01 CEST (Europe/Berlin) (Run #35004887103, Laufzeit 16m 39s)
- 2026-09-16 02:30 CEST (Europe/Berlin) (Run #35040323732, Laufzeit 16m 30s)

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
