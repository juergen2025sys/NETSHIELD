# Workflow Health Dashboard

**Stand:** 2026-11-01 22:57 CET (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 8 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 6
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-11-01 01:20 CET (Europe/Berlin) -> 2026-11-01 06:49 CET (Europe/Berlin) (328 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 61
- **Skip-Runs:** 50
- **Fehlgeschlagene Runs:** 1
- **Lucken >210min:** 9
- **Groesste Lucke:** 2026-11-01 01:20 CET (Europe/Berlin) -> 2026-11-01 06:49 CET (Europe/Berlin) (328 min = 5h 28min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 232
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 38

Letzte Watchdog-Eingriffe:
- 2026-11-01 07:48 CET (Europe/Berlin) (Run #41282311598, Laufzeit 19m 19s)
- 2026-11-01 08:45 CET (Europe/Berlin) (Run #41286076961, Laufzeit 79m 33s)
- 2026-11-01 10:30 CET (Europe/Berlin) (Run #41293398908, Laufzeit 19m 18s)
- 2026-11-01 16:32 CET (Europe/Berlin) (Run #41321734775, Laufzeit 16m 59s)
- 2026-11-01 19:38 CET (Europe/Berlin) (Run #41337667212, Laufzeit 19m 37s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-10-26 01:43 CET (Europe/Berlin) - cancelled - Run #40250723975 (3m 10s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
