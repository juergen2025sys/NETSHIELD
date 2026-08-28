# Workflow Health Dashboard

**Stand:** 2026-08-28 13:17 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 5 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 4
- **Lucken (>210min zwischen echten Runs):** 3
  - 2026-08-27 16:25 CEST (Europe/Berlin) -> 2026-08-27 21:01 CEST (Europe/Berlin) (276 min)
  - 2026-08-28 00:54 CEST (Europe/Berlin) -> 2026-08-28 06:06 CEST (Europe/Berlin) (312 min)
  - 2026-08-28 06:29 CEST (Europe/Berlin) -> 2026-08-28 10:36 CEST (Europe/Berlin) (246 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 64
- **Skip-Runs:** 117
- **Fehlgeschlagene Runs:** 36
- **Lucken >210min:** 7
- **Groesste Lucke:** 2026-08-24 06:31 CEST (Europe/Berlin) -> 2026-08-24 16:55 CEST (Europe/Berlin) (623 min = 10h 23min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 562
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 81

Letzte Watchdog-Eingriffe:
- 2026-08-27 21:01 CEST (Europe/Berlin) (Run #33106403019, Laufzeit 22m 34s)
- 2026-08-28 00:30 CEST (Europe/Berlin) (Run #33122750981, Laufzeit 24m 22s)
- 2026-08-28 06:04 CEST (Europe/Berlin) (Run #33140716872, Laufzeit 8s)
- 2026-08-28 06:06 CEST (Europe/Berlin) (Run #33140840089, Laufzeit 23m 11s)
- 2026-08-28 10:36 CEST (Europe/Berlin) (Run #33156016013, Laufzeit 22m 34s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-08-24 14:40 CEST (Europe/Berlin) - failure - Run #32728317463 (20m 47s)
- 2026-08-24 15:06 CEST (Europe/Berlin) - failure - Run #32730692923 (22m 40s)
- 2026-08-24 15:28 CEST (Europe/Berlin) - failure - Run #32732915360 (21m 9s)
- 2026-08-24 16:21 CEST (Europe/Berlin) - failure - Run #32738229357 (22m 33s)
- 2026-08-24 20:55 CEST (Europe/Berlin) - cancelled - Run #32765205722 (2m 45s)
- 2026-08-25 21:57 CEST (Europe/Berlin) - cancelled - Run #32892515314 (6m 18s)
- 2026-08-26 20:39 CEST (Europe/Berlin) - cancelled - Run #33000839712 (17m 54s)
- 2026-08-27 02:38 CEST (Europe/Berlin) - cancelled - Run #33027509309 (18m 55s)
- 2026-08-28 02:36 CEST (Europe/Berlin) - failure - Run #33130252717 (24m 5s)
- 2026-08-28 06:04 CEST (Europe/Berlin) - cancelled - Run #33140716872 (8s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
