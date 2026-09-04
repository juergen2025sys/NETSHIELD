# Workflow Health Dashboard

**Stand:** 2026-09-04 13:10 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 11
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 67
- **Skip-Runs:** 69
- **Fehlgeschlagene Runs:** 6
- **Lucken >210min:** 5
- **Groesste Lucke:** 2026-08-31 02:47 CEST (Europe/Berlin) -> 2026-08-31 07:20 CEST (Europe/Berlin) (272 min = 4h 32min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 191
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 51

Letzte Watchdog-Eingriffe:
- 2026-09-03 20:53 CEST (Europe/Berlin) (Run #33793182301, Laufzeit 8m 11s)
- 2026-09-03 21:03 CEST (Europe/Berlin) (Run #33794214108, Laufzeit 20m 35s)
- 2026-09-04 03:07 CEST (Europe/Berlin) (Run #33824512008, Laufzeit 20m 24s)
- 2026-09-04 08:32 CEST (Europe/Berlin) (Run #33844771158, Laufzeit 22m 33s)
- 2026-09-04 11:52 CEST (Europe/Berlin) (Run #33860464687, Laufzeit 19m 17s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-08-28 14:14 CEST (Europe/Berlin) - cancelled - Run #33170286806 (3m 58s)
- 2026-08-31 22:53 CEST (Europe/Berlin) - cancelled - Run #33438466768 (6m 40s)
- 2026-08-31 23:05 CEST (Europe/Berlin) - cancelled - Run #33439515318 (9m 45s)
- 2026-09-01 20:22 CEST (Europe/Berlin) - cancelled - Run #33543228443 (17m 24s)
- 2026-09-02 18:28 CEST (Europe/Berlin) - action_required - Run #33655138414 (0s)
- 2026-09-03 20:53 CEST (Europe/Berlin) - cancelled - Run #33793182301 (8m 11s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
