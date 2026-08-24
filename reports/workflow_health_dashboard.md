# Workflow Health Dashboard

**Stand:** 2026-08-24 15:10 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 7 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 15
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-08-23 17:16 CEST (Europe/Berlin) -> 2026-08-23 21:09 CEST (Europe/Berlin) (232 min)
  - 2026-08-24 00:56 CEST (Europe/Berlin) -> 2026-08-24 06:10 CEST (Europe/Berlin) (314 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 59
- **Skip-Runs:** 153
- **Fehlgeschlagene Runs:** 27
- **Lucken >210min:** 3
- **Groesste Lucke:** 2026-08-19 06:13 CEST (Europe/Berlin) -> 2026-08-19 17:02 CEST (Europe/Berlin) (649 min = 10h 49min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 748
- **Watchdog-Fehler:** 1
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 73

Letzte Watchdog-Eingriffe:
- 2026-08-24 11:28 CEST (Europe/Berlin) (Run #32711764116, Laufzeit 16m 46s)
- 2026-08-24 12:21 CEST (Europe/Berlin) (Run #32716367844, Laufzeit 16m 49s)
- 2026-08-24 13:02 CEST (Europe/Berlin) (Run #32719835832, Laufzeit 19m 7s)
- 2026-08-24 13:40 CEST (Europe/Berlin) (Run #32723053807, Laufzeit 21m 47s)
- 2026-08-24 14:40 CEST (Europe/Berlin) (Run #32728317463, Laufzeit 20m 47s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-08-24 09:13 CEST (Europe/Berlin) - failure - Run #32700573644 (20m 53s)
- 2026-08-24 09:34 CEST (Europe/Berlin) - failure - Run #32702135044 (20m 55s)
- 2026-08-24 10:08 CEST (Europe/Berlin) - failure - Run #32704826874 (20m 51s)
- 2026-08-24 11:00 CEST (Europe/Berlin) - failure - Run #32709227437 (20m 46s)
- 2026-08-24 11:28 CEST (Europe/Berlin) - failure - Run #32711764116 (16m 46s)
- 2026-08-24 11:56 CEST (Europe/Berlin) - failure - Run #32714214409 (22m 14s)
- 2026-08-24 12:21 CEST (Europe/Berlin) - failure - Run #32716367844 (16m 49s)
- 2026-08-24 13:02 CEST (Europe/Berlin) - failure - Run #32719835832 (19m 7s)
- 2026-08-24 13:40 CEST (Europe/Berlin) - failure - Run #32723053807 (21m 47s)
- 2026-08-24 14:40 CEST (Europe/Berlin) - failure - Run #32728317463 (20m 47s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
