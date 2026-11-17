# Workflow Health Dashboard

**Stand:** 2026-11-17 21:48 CET (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 7 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 4
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-11-17 04:59 CET (Europe/Berlin) -> 2026-11-17 10:13 CET (Europe/Berlin) (313 min)
  - 2026-11-17 10:29 CET (Europe/Berlin) -> 2026-11-17 14:30 CET (Europe/Berlin) (240 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 56
- **Skip-Runs:** 48
- **Fehlgeschlagene Runs:** 0
- **Lucken >210min:** 11
- **Groesste Lucke:** 2026-11-11 10:51 CET (Europe/Berlin) -> 2026-11-11 16:12 CET (Europe/Berlin) (320 min = 5h 20min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 381
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 44

Letzte Watchdog-Eingriffe:
- 2026-11-16 23:25 CET (Europe/Berlin) (Run #43969988245, Laufzeit 18m 32s)
- 2026-11-17 01:35 CET (Europe/Berlin) (Run #43988786687, Laufzeit 19m 2s)
- 2026-11-17 10:13 CET (Europe/Berlin) (Run #44053541760, Laufzeit 16m 30s)
- 2026-11-17 14:30 CET (Europe/Berlin) (Run #44093376607, Laufzeit 19m 43s)
- 2026-11-17 19:49 CET (Europe/Berlin) (Run #44151902193, Laufzeit 20m 2s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
