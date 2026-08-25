# Workflow Health Dashboard

**Stand:** 2026-08-25 03:48 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 8 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 17
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-08-24 06:31 CEST (Europe/Berlin) -> 2026-08-24 16:55 CEST (Europe/Berlin) (623 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 61
- **Skip-Runs:** 152
- **Fehlgeschlagene Runs:** 31
- **Lucken >210min:** 4
- **Groesste Lucke:** 2026-08-19 06:13 CEST (Europe/Berlin) -> 2026-08-19 17:02 CEST (Europe/Berlin) (649 min = 10h 49min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 738
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 77

Letzte Watchdog-Eingriffe:
- 2026-08-24 20:55 CEST (Europe/Berlin) (Run #32765205722, Laufzeit 2m 45s)
- 2026-08-24 21:54 CEST (Europe/Berlin) (Run #32770799276, Laufzeit 21m 13s)
- 2026-08-24 22:32 CEST (Europe/Berlin) (Run #32774443106, Laufzeit 20m 46s)
- 2026-08-24 23:47 CEST (Europe/Berlin) (Run #32781367145, Laufzeit 21m 52s)
- 2026-08-25 02:40 CEST (Europe/Berlin) (Run #32794591154, Laufzeit 22m 17s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-08-24 11:28 CEST (Europe/Berlin) - failure - Run #32711764116 (16m 46s)
- 2026-08-24 11:56 CEST (Europe/Berlin) - failure - Run #32714214409 (22m 14s)
- 2026-08-24 12:21 CEST (Europe/Berlin) - failure - Run #32716367844 (16m 49s)
- 2026-08-24 13:02 CEST (Europe/Berlin) - failure - Run #32719835832 (19m 7s)
- 2026-08-24 13:40 CEST (Europe/Berlin) - failure - Run #32723053807 (21m 47s)
- 2026-08-24 14:40 CEST (Europe/Berlin) - failure - Run #32728317463 (20m 47s)
- 2026-08-24 15:06 CEST (Europe/Berlin) - failure - Run #32730692923 (22m 40s)
- 2026-08-24 15:28 CEST (Europe/Berlin) - failure - Run #32732915360 (21m 9s)
- 2026-08-24 16:21 CEST (Europe/Berlin) - failure - Run #32738229357 (22m 33s)
- 2026-08-24 20:55 CEST (Europe/Berlin) - cancelled - Run #32765205722 (2m 45s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
