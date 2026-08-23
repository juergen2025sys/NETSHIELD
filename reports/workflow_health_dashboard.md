# Workflow Health Dashboard

**Stand:** 2026-08-23 03:57 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 23
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 60
- **Skip-Runs:** 158
- **Fehlgeschlagene Runs:** 4
- **Lucken >210min:** 1
- **Groesste Lucke:** 2026-08-19 06:13 CEST (Europe/Berlin) -> 2026-08-19 17:02 CEST (Europe/Berlin) (649 min = 10h 49min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 758
- **Watchdog-Fehler:** 1
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 55

Letzte Watchdog-Eingriffe:
- 2026-08-22 17:32 CEST (Europe/Berlin) (Run #32582022345, Laufzeit 21m 18s)
- 2026-08-22 17:54 CEST (Europe/Berlin) (Run #32583095710, Laufzeit 24m 54s)
- 2026-08-22 20:46 CEST (Europe/Berlin) (Run #32591734553, Laufzeit 15m 33s)
- 2026-08-22 23:33 CEST (Europe/Berlin) (Run #32599939844, Laufzeit 16m 10s)
- 2026-08-23 02:30 CEST (Europe/Berlin) (Run #32608058453, Laufzeit 20m 21s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-08-16 04:03 CEST (Europe/Berlin) - action_required - Run #31920993786 (0s)
- 2026-08-16 19:36 CEST (Europe/Berlin) - failure - Run #31962089791 (3m 41s)
- 2026-08-16 19:43 CEST (Europe/Berlin) - cancelled - Run #31962436032 (3m 38s)
- 2026-08-16 19:47 CEST (Europe/Berlin) - cancelled - Run #31962640642 (40s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
