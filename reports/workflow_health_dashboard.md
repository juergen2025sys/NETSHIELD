# Workflow Health Dashboard

**Stand:** 2026-09-18 06:35 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 10 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 8
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-09-17 16:59 CEST (Europe/Berlin) -> 2026-09-17 21:02 CEST (Europe/Berlin) (242 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 69
- **Skip-Runs:** 75
- **Fehlgeschlagene Runs:** 6
- **Lucken >210min:** 9
- **Groesste Lucke:** 2026-09-15 02:08 CEST (Europe/Berlin) -> 2026-09-15 06:43 CEST (Europe/Berlin) (274 min = 4h 34min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 317
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 55

Letzte Watchdog-Eingriffe:
- 2026-09-17 11:55 CEST (Europe/Berlin) (Run #35207763035, Laufzeit 20m 12s)
- 2026-09-17 16:40 CEST (Europe/Berlin) (Run #35235138105, Laufzeit 19m 30s)
- 2026-09-17 20:26 CEST (Europe/Berlin) (Run #35258785082, Laufzeit 28m 26s)
- 2026-09-17 21:02 CEST (Europe/Berlin) (Run #35262480471, Laufzeit 29m 22s)
- 2026-09-18 02:36 CEST (Europe/Berlin) (Run #35291911045, Laufzeit 19m 43s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-09-11 08:39 CEST (Europe/Berlin) - cancelled - Run #34570885903 (4m 2s)
- 2026-09-12 10:54 CEST (Europe/Berlin) - failure - Run #34684445124 (34m 43s)
- 2026-09-12 11:30 CEST (Europe/Berlin) - cancelled - Run #34686028170 (7m 15s)
- 2026-09-12 11:38 CEST (Europe/Berlin) - failure - Run #34686370369 (1m 22s)
- 2026-09-17 18:50 CEST (Europe/Berlin) - cancelled - Run #35249032902 (88m 18s)
- 2026-09-17 20:26 CEST (Europe/Berlin) - cancelled - Run #35258785082 (28m 26s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
