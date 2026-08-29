# Workflow Health Dashboard

**Stand:** 2026-08-29 08:59 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 4
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-08-28 10:59 CEST (Europe/Berlin) -> 2026-08-28 14:30 CEST (Europe/Berlin) (211 min)
  - 2026-08-28 20:44 CEST (Europe/Berlin) -> 2026-08-29 00:41 CEST (Europe/Berlin) (236 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 65
- **Skip-Runs:** 102
- **Fehlgeschlagene Runs:** 37
- **Lucken >210min:** 9
- **Groesste Lucke:** 2026-08-24 06:31 CEST (Europe/Berlin) -> 2026-08-24 16:55 CEST (Europe/Berlin) (623 min = 10h 23min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 486
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 81

Letzte Watchdog-Eingriffe:
- 2026-08-28 16:21 CEST (Europe/Berlin) (Run #33179752342, Laufzeit 24m 33s)
- 2026-08-28 19:41 CEST (Europe/Berlin) (Run #33195851703, Laufzeit 26m 26s)
- 2026-08-28 20:18 CEST (Europe/Berlin) (Run #33198652856, Laufzeit 26m 30s)
- 2026-08-29 03:24 CEST (Europe/Berlin) (Run #33226334270, Laufzeit 23m 48s)
- 2026-08-29 05:44 CEST (Europe/Berlin) (Run #33232138351, Laufzeit 23m 44s)

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
