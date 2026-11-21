# Workflow Health Dashboard

**Stand:** 2026-11-21 07:56 CET (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 11 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 8
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 58
- **Skip-Runs:** 49
- **Fehlgeschlagene Runs:** 0
- **Lucken >210min:** 10
- **Groesste Lucke:** 2026-11-17 04:59 CET (Europe/Berlin) -> 2026-11-17 10:13 CET (Europe/Berlin) (313 min = 5h 13min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 320
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 47

Letzte Watchdog-Eingriffe:
- 2026-11-20 19:57 CET (Europe/Berlin) (Run #44797570225, Laufzeit 23m 17s)
- 2026-11-20 22:29 CET (Europe/Berlin) (Run #44820754165, Laufzeit 14m 26s)
- 2026-11-21 01:49 CET (Europe/Berlin) (Run #44846373581, Laufzeit 12m 40s)
- 2026-11-21 02:02 CET (Europe/Berlin) (Run #44847710982, Laufzeit 19m 22s)
- 2026-11-21 07:30 CET (Europe/Berlin) (Run #44875896728, Laufzeit 17m 8s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
