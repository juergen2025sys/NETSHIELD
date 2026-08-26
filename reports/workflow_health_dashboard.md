# Workflow Health Dashboard

**Stand:** 2026-08-26 15:12 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 8 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 22
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 63
- **Skip-Runs:** 153
- **Fehlgeschlagene Runs:** 32
- **Lucken >210min:** 3
- **Groesste Lucke:** 2026-08-24 06:31 CEST (Europe/Berlin) -> 2026-08-24 16:55 CEST (Europe/Berlin) (623 min = 10h 23min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 722
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 81

Letzte Watchdog-Eingriffe:
- 2026-08-25 23:00 CEST (Europe/Berlin) (Run #32898610229, Laufzeit 18m 37s)
- 2026-08-26 02:44 CEST (Europe/Berlin) (Run #32916309192, Laufzeit 23m 48s)
- 2026-08-26 05:34 CEST (Europe/Berlin) (Run #32926933446, Laufzeit 19m 40s)
- 2026-08-26 08:40 CEST (Europe/Berlin) (Run #32939196912, Laufzeit 25m 32s)
- 2026-08-26 11:35 CEST (Europe/Berlin) (Run #32953817188, Laufzeit 20m 38s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-08-24 11:56 CEST (Europe/Berlin) - failure - Run #32714214409 (22m 14s)
- 2026-08-24 12:21 CEST (Europe/Berlin) - failure - Run #32716367844 (16m 49s)
- 2026-08-24 13:02 CEST (Europe/Berlin) - failure - Run #32719835832 (19m 7s)
- 2026-08-24 13:40 CEST (Europe/Berlin) - failure - Run #32723053807 (21m 47s)
- 2026-08-24 14:40 CEST (Europe/Berlin) - failure - Run #32728317463 (20m 47s)
- 2026-08-24 15:06 CEST (Europe/Berlin) - failure - Run #32730692923 (22m 40s)
- 2026-08-24 15:28 CEST (Europe/Berlin) - failure - Run #32732915360 (21m 9s)
- 2026-08-24 16:21 CEST (Europe/Berlin) - failure - Run #32738229357 (22m 33s)
- 2026-08-24 20:55 CEST (Europe/Berlin) - cancelled - Run #32765205722 (2m 45s)
- 2026-08-25 21:57 CEST (Europe/Berlin) - cancelled - Run #32892515314 (6m 18s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
