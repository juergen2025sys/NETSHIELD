# Workflow Health Dashboard

**Stand:** 2026-09-01 13:33 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 10 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 10
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-09-01 02:53 CEST (Europe/Berlin) -> 2026-09-01 06:59 CEST (Europe/Berlin) (246 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 64
- **Skip-Runs:** 71
- **Fehlgeschlagene Runs:** 9
- **Lucken >210min:** 10
- **Groesste Lucke:** 2026-08-27 05:52 CEST (Europe/Berlin) -> 2026-08-27 13:14 CEST (Europe/Berlin) (441 min = 7h 21min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 221
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 55

Letzte Watchdog-Eingriffe:
- 2026-08-31 22:53 CEST (Europe/Berlin) (Run #33438466768, Laufzeit 6m 40s)
- 2026-08-31 23:22 CEST (Europe/Berlin) (Run #33441029337, Laufzeit 21m 8s)
- 2026-09-01 06:59 CEST (Europe/Berlin) (Run #33471906248, Laufzeit 23m 37s)
- 2026-09-01 09:10 CEST (Europe/Berlin) (Run #33480834501, Laufzeit 27m 41s)
- 2026-09-01 12:01 CEST (Europe/Berlin) (Run #33495228007, Laufzeit 26m 53s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-08-25 21:57 CEST (Europe/Berlin) - cancelled - Run #32892515314 (6m 18s)
- 2026-08-26 17:39 CEST (Europe/Berlin) - cancelled - Run #32985778662 (4415m 46s)
- 2026-08-26 20:39 CEST (Europe/Berlin) - cancelled - Run #33000839712 (17m 54s)
- 2026-08-27 02:38 CEST (Europe/Berlin) - cancelled - Run #33027509309 (18m 55s)
- 2026-08-28 02:36 CEST (Europe/Berlin) - failure - Run #33130252717 (24m 5s)
- 2026-08-28 06:04 CEST (Europe/Berlin) - cancelled - Run #33140716872 (8s)
- 2026-08-28 14:14 CEST (Europe/Berlin) - cancelled - Run #33170286806 (3m 58s)
- 2026-08-31 22:53 CEST (Europe/Berlin) - cancelled - Run #33438466768 (6m 40s)
- 2026-08-31 23:05 CEST (Europe/Berlin) - cancelled - Run #33439515318 (9m 45s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
