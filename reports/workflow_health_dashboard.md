# Workflow Health Dashboard

**Stand:** 2026-09-11 06:30 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 8 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 13
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-09-10 14:12 CEST (Europe/Berlin) -> 2026-09-10 17:55 CEST (Europe/Berlin) (223 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 68
- **Skip-Runs:** 82
- **Fehlgeschlagene Runs:** 2
- **Lucken >210min:** 7
- **Groesste Lucke:** 2026-09-06 06:42 CEST (Europe/Berlin) -> 2026-09-06 10:50 CEST (Europe/Berlin) (247 min = 4h 7min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 315
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 48

Letzte Watchdog-Eingriffe:
- 2026-09-10 17:55 CEST (Europe/Berlin) (Run #34498825301, Laufzeit 18m 53s)
- 2026-09-10 20:38 CEST (Europe/Berlin) (Run #34515551063, Laufzeit 20m 36s)
- 2026-09-10 21:37 CEST (Europe/Berlin) (Run #34521557495, Laufzeit 23m 4s)
- 2026-09-10 23:46 CEST (Europe/Berlin) (Run #34533957227, Laufzeit 18m 58s)
- 2026-09-11 02:36 CEST (Europe/Berlin) (Run #34547225700, Laufzeit 22m 40s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-09-04 15:51 CEST (Europe/Berlin) - cancelled - Run #33880368309 (2m 13s)
- 2026-09-06 17:22 CEST (Europe/Berlin) - failure - Run #34042104282 (19m 11s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
