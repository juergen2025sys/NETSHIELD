# Workflow Health Dashboard

**Stand:** 2026-09-10 22:48 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 10 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 12
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-09-10 02:55 CEST (Europe/Berlin) -> 2026-09-10 06:26 CEST (Europe/Berlin) (210 min)
  - 2026-09-10 14:12 CEST (Europe/Berlin) -> 2026-09-10 17:55 CEST (Europe/Berlin) (223 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 70
- **Skip-Runs:** 81
- **Fehlgeschlagene Runs:** 2
- **Lucken >210min:** 7
- **Groesste Lucke:** 2026-09-06 06:42 CEST (Europe/Berlin) -> 2026-09-06 10:50 CEST (Europe/Berlin) (247 min = 4h 7min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 311
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 47

Letzte Watchdog-Eingriffe:
- 2026-09-10 08:46 CEST (Europe/Berlin) (Run #34446772045, Laufzeit 16m 1s)
- 2026-09-10 11:40 CEST (Europe/Berlin) (Run #34461932891, Laufzeit 20m 50s)
- 2026-09-10 17:55 CEST (Europe/Berlin) (Run #34498825301, Laufzeit 18m 53s)
- 2026-09-10 20:38 CEST (Europe/Berlin) (Run #34515551063, Laufzeit 20m 36s)
- 2026-09-10 21:37 CEST (Europe/Berlin) (Run #34521557495, Laufzeit 23m 4s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-09-04 15:51 CEST (Europe/Berlin) - cancelled - Run #33880368309 (2m 13s)
- 2026-09-06 17:22 CEST (Europe/Berlin) - failure - Run #34042104282 (19m 11s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
