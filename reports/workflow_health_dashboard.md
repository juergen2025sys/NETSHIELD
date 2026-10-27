# Workflow Health Dashboard

**Stand:** 2026-10-27 05:55 CET (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 8 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 8
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-10-26 08:03 CET (Europe/Berlin) -> 2026-10-26 12:00 CET (Europe/Berlin) (237 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 60
- **Skip-Runs:** 68
- **Fehlgeschlagene Runs:** 1
- **Lucken >210min:** 9
- **Groesste Lucke:** 2026-10-25 05:43 CET (Europe/Berlin) -> 2026-10-25 10:28 CET (Europe/Berlin) (284 min = 4h 44min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 286
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 38

Letzte Watchdog-Eingriffe:
- 2026-10-26 07:48 CET (Europe/Berlin) (Run #40282022792, Laufzeit 14m 26s)
- 2026-10-26 12:00 CET (Europe/Berlin) (Run #40311829663, Laufzeit 17m 57s)
- 2026-10-26 16:35 CET (Europe/Berlin) (Run #40350869643, Laufzeit 33m 19s)
- 2026-10-26 19:44 CET (Europe/Berlin) (Run #40380389047, Laufzeit 20m 7s)
- 2026-10-26 22:42 CET (Europe/Berlin) (Run #40406585995, Laufzeit 19m 31s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-10-26 01:43 CET (Europe/Berlin) - cancelled - Run #40250723975 (3m 10s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
