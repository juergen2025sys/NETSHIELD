# Workflow Health Dashboard

**Stand:** 2026-08-23 20:45 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 11 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 20
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 60
- **Skip-Runs:** 157
- **Fehlgeschlagene Runs:** 6
- **Lucken >210min:** 1
- **Groesste Lucke:** 2026-08-19 06:13 CEST (Europe/Berlin) -> 2026-08-19 17:02 CEST (Europe/Berlin) (649 min = 10h 49min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 752
- **Watchdog-Fehler:** 1
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 56

Letzte Watchdog-Eingriffe:
- 2026-08-23 12:08 CEST (Europe/Berlin) (Run #32632927397, Laufzeit 20m 55s)
- 2026-08-23 14:40 CEST (Europe/Berlin) (Run #32640043581, Laufzeit 1s)
- 2026-08-23 15:00 CEST (Europe/Berlin) (Run #32641049205, Laufzeit 1s)
- 2026-08-23 15:23 CEST (Europe/Berlin) (Run #32642029249, Laufzeit 20m 35s)
- 2026-08-23 16:56 CEST (Europe/Berlin) (Run #32646961489, Laufzeit 20m 21s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-08-23 14:40 CEST (Europe/Berlin) - action_required - Run #32640043581 (1s)
- 2026-08-23 14:55 CEST (Europe/Berlin) - action_required - Run #32640807973 (0s)
- 2026-08-23 15:00 CEST (Europe/Berlin) - action_required - Run #32641049205 (1s)
- 2026-08-23 15:08 CEST (Europe/Berlin) - action_required - Run #32641464890 (0s)
- 2026-08-23 17:30 CEST (Europe/Berlin) - action_required - Run #32648775481 (0s)
- 2026-08-23 17:44 CEST (Europe/Berlin) - action_required - Run #32649488888 (0s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
