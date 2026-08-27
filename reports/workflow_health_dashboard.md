# Workflow Health Dashboard

**Stand:** 2026-08-28 00:13 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 6 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 3
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-08-27 05:52 CEST (Europe/Berlin) -> 2026-08-27 13:14 CEST (Europe/Berlin) (441 min)
  - 2026-08-27 16:25 CEST (Europe/Berlin) -> 2026-08-27 21:01 CEST (Europe/Berlin) (276 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 65
- **Skip-Runs:** 127
- **Fehlgeschlagene Runs:** 34
- **Lucken >210min:** 5
- **Groesste Lucke:** 2026-08-24 06:31 CEST (Europe/Berlin) -> 2026-08-24 16:55 CEST (Europe/Berlin) (623 min = 10h 23min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 607
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 81

Letzte Watchdog-Eingriffe:
- 2026-08-26 23:36 CEST (Europe/Berlin) (Run #33016142680, Laufzeit 22m 27s)
- 2026-08-27 02:59 CEST (Europe/Berlin) (Run #33028615898, Laufzeit 44m 43s)
- 2026-08-27 05:32 CEST (Europe/Berlin) (Run #33036693046, Laufzeit 19m 30s)
- 2026-08-27 13:14 CEST (Europe/Berlin) (Run #33066483578, Laufzeit 29m 19s)
- 2026-08-27 21:01 CEST (Europe/Berlin) (Run #33106403019, Laufzeit 22m 34s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-08-24 13:02 CEST (Europe/Berlin) - failure - Run #32719835832 (19m 7s)
- 2026-08-24 13:40 CEST (Europe/Berlin) - failure - Run #32723053807 (21m 47s)
- 2026-08-24 14:40 CEST (Europe/Berlin) - failure - Run #32728317463 (20m 47s)
- 2026-08-24 15:06 CEST (Europe/Berlin) - failure - Run #32730692923 (22m 40s)
- 2026-08-24 15:28 CEST (Europe/Berlin) - failure - Run #32732915360 (21m 9s)
- 2026-08-24 16:21 CEST (Europe/Berlin) - failure - Run #32738229357 (22m 33s)
- 2026-08-24 20:55 CEST (Europe/Berlin) - cancelled - Run #32765205722 (2m 45s)
- 2026-08-25 21:57 CEST (Europe/Berlin) - cancelled - Run #32892515314 (6m 18s)
- 2026-08-26 20:39 CEST (Europe/Berlin) - cancelled - Run #33000839712 (17m 54s)
- 2026-08-27 02:38 CEST (Europe/Berlin) - cancelled - Run #33027509309 (18m 55s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
