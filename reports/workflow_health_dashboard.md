# Workflow Health Dashboard

**Stand:** 2026-10-09 08:00 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 7 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 8
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 75
- **Skip-Runs:** 60
- **Fehlgeschlagene Runs:** 2
- **Lucken >210min:** 5
- **Groesste Lucke:** 2026-10-03 03:04 CEST (Europe/Berlin) -> 2026-10-03 07:07 CEST (Europe/Berlin) (242 min = 4h 2min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 222
- **Watchdog-Fehler:** 1
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 63

Letzte Watchdog-Eingriffe:
- 2026-10-08 11:30 CEST (Europe/Berlin) (Run #37757113010, Laufzeit 20m 38s)
- 2026-10-08 15:20 CEST (Europe/Berlin) (Run #37783612246, Laufzeit 21m 19s)
- 2026-10-08 18:27 CEST (Europe/Berlin) (Run #37808965862, Laufzeit 20m 39s)
- 2026-10-08 23:28 CEST (Europe/Berlin) (Run #37846968467, Laufzeit 19m 15s)
- 2026-10-09 02:29 CEST (Europe/Berlin) (Run #37865045616, Laufzeit 18m 18s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-10-06 08:08 CEST (Europe/Berlin) - failure - Run #37422154292 (20m 8s)
- 2026-10-06 21:34 CEST (Europe/Berlin) - failure - Run #37519985347 (13m 50s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
