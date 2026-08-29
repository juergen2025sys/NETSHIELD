# Workflow Health Dashboard

**Stand:** 2026-08-29 18:40 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 10 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 6
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-08-28 20:44 CEST (Europe/Berlin) -> 2026-08-29 00:41 CEST (Europe/Berlin) (236 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 66
- **Skip-Runs:** 95
- **Fehlgeschlagene Runs:** 37
- **Lucken >210min:** 9
- **Groesste Lucke:** 2026-08-24 06:31 CEST (Europe/Berlin) -> 2026-08-24 16:55 CEST (Europe/Berlin) (623 min = 10h 23min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 441
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 81

Letzte Watchdog-Eingriffe:
- 2026-08-29 05:44 CEST (Europe/Berlin) (Run #33232138351, Laufzeit 23m 44s)
- 2026-08-29 11:11 CEST (Europe/Berlin) (Run #33244884557, Laufzeit 24m 21s)
- 2026-08-29 11:50 CEST (Europe/Berlin) (Run #33246396733, Laufzeit 21m 8s)
- 2026-08-29 15:09 CEST (Europe/Berlin) (Run #33254280854, Laufzeit 23m 55s)
- 2026-08-29 17:46 CEST (Europe/Berlin) (Run #33261141236, Laufzeit 22m 5s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-08-24 15:06 CEST (Europe/Berlin) - failure - Run #32730692923 (22m 40s)
- 2026-08-24 15:28 CEST (Europe/Berlin) - failure - Run #32732915360 (21m 9s)
- 2026-08-24 16:21 CEST (Europe/Berlin) - failure - Run #32738229357 (22m 33s)
- 2026-08-24 20:55 CEST (Europe/Berlin) - cancelled - Run #32765205722 (2m 45s)
- 2026-08-25 21:57 CEST (Europe/Berlin) - cancelled - Run #32892515314 (6m 18s)
- 2026-08-26 20:39 CEST (Europe/Berlin) - cancelled - Run #33000839712 (17m 54s)
- 2026-08-27 02:38 CEST (Europe/Berlin) - cancelled - Run #33027509309 (18m 55s)
- 2026-08-28 02:36 CEST (Europe/Berlin) - failure - Run #33130252717 (24m 5s)
- 2026-08-28 06:04 CEST (Europe/Berlin) - cancelled - Run #33140716872 (8s)
- 2026-08-28 14:14 CEST (Europe/Berlin) - cancelled - Run #33170286806 (3m 58s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
