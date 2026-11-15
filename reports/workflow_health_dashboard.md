# Workflow Health Dashboard

**Stand:** 2026-11-15 19:45 CET (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 7 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 8
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-11-15 02:28 CET (Europe/Berlin) -> 2026-11-15 07:11 CET (Europe/Berlin) (283 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 56
- **Skip-Runs:** 48
- **Fehlgeschlagene Runs:** 0
- **Lucken >210min:** 10
- **Groesste Lucke:** 2026-11-11 10:51 CET (Europe/Berlin) -> 2026-11-11 16:12 CET (Europe/Berlin) (320 min = 5h 20min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 418
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 41

Letzte Watchdog-Eingriffe:
- 2026-11-14 22:30 CET (Europe/Berlin) (Run #43643143478, Laufzeit 14m 58s)
- 2026-11-15 02:14 CET (Europe/Berlin) (Run #43662159175, Laufzeit 13m 26s)
- 2026-11-15 10:49 CET (Europe/Berlin) (Run #43701105389, Laufzeit 15m 18s)
- 2026-11-15 14:27 CET (Europe/Berlin) (Run #43719064362, Laufzeit 20m 42s)
- 2026-11-15 16:49 CET (Europe/Berlin) (Run #43732047577, Laufzeit 21m 28s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
