# Workflow Health Dashboard

**Stand:** 2026-11-21 20:06 CET (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 7
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-11-21 07:47 CET (Europe/Berlin) -> 2026-11-21 11:53 CET (Europe/Berlin) (245 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 58
- **Skip-Runs:** 47
- **Fehlgeschlagene Runs:** 1
- **Lucken >210min:** 10
- **Groesste Lucke:** 2026-11-17 04:59 CET (Europe/Berlin) -> 2026-11-17 10:13 CET (Europe/Berlin) (313 min = 5h 13min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 304
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 49

Letzte Watchdog-Eingriffe:
- 2026-11-21 07:30 CET (Europe/Berlin) (Run #44875896728, Laufzeit 17m 8s)
- 2026-11-21 11:53 CET (Europe/Berlin) (Run #44896498396, Laufzeit 14m 45s)
- 2026-11-21 12:45 CET (Europe/Berlin) (Run #44900582069, Laufzeit 14m 22s)
- 2026-11-21 13:26 CET (Europe/Berlin) (Run #44903878824, Laufzeit 20m 19s)
- 2026-11-21 16:42 CET (Europe/Berlin) (Run #44920577707, Laufzeit 11m 56s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-11-21 11:52 CET (Europe/Berlin) - cancelled - Run #44896391381 (2m 3s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
