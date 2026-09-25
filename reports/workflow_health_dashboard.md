# Workflow Health Dashboard

**Stand:** 2026-09-25 06:49 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 10 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 10
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 71
- **Skip-Runs:** 75
- **Fehlgeschlagene Runs:** 4
- **Lucken >210min:** 6
- **Groesste Lucke:** 2026-09-23 02:10 CEST (Europe/Berlin) -> 2026-09-23 06:35 CEST (Europe/Berlin) (265 min = 4h 25min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 306
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 57

Letzte Watchdog-Eingriffe:
- 2026-09-24 14:58 CEST (Europe/Berlin) (Run #36002512490, Laufzeit 21m 0s)
- 2026-09-24 17:25 CEST (Europe/Berlin) (Run #36020068196, Laufzeit 20m 8s)
- 2026-09-24 18:35 CEST (Europe/Berlin) (Run #36028451893, Laufzeit 16m 54s)
- 2026-09-24 20:02 CEST (Europe/Berlin) (Run #36038426655, Laufzeit 22m 15s)
- 2026-09-25 02:56 CEST (Europe/Berlin) (Run #36079792717, Laufzeit 20m 40s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-09-18 20:39 CEST (Europe/Berlin) - cancelled - Run #35381409864 (9m 20s)
- 2026-09-19 11:44 CEST (Europe/Berlin) - failure - Run #35435507912 (13m 38s)
- 2026-09-21 02:31 CEST (Europe/Berlin) - cancelled - Run #35547981772 (5m 42s)
- 2026-09-23 19:43 CEST (Europe/Berlin) - cancelled - Run #35897617505 (2m 6s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
