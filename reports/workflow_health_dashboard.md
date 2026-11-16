# Workflow Health Dashboard

**Stand:** 2026-11-16 22:56 CET (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 6 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 8
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-11-16 02:12 CET (Europe/Berlin) -> 2026-11-16 07:08 CET (Europe/Berlin) (296 min)
  - 2026-11-16 07:22 CET (Europe/Berlin) -> 2026-11-16 11:08 CET (Europe/Berlin) (226 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 56
- **Skip-Runs:** 52
- **Fehlgeschlagene Runs:** 0
- **Lucken >210min:** 9
- **Groesste Lucke:** 2026-11-11 10:51 CET (Europe/Berlin) -> 2026-11-11 16:12 CET (Europe/Berlin) (320 min = 5h 20min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 399
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 45

Letzte Watchdog-Eingriffe:
- 2026-11-16 01:55 CET (Europe/Berlin) (Run #43783260610, Laufzeit 16m 8s)
- 2026-11-16 11:08 CET (Europe/Berlin) (Run #43846096421, Laufzeit 14m 32s)
- 2026-11-16 14:14 CET (Europe/Berlin) (Run #43873853996, Laufzeit 16m 27s)
- 2026-11-16 17:21 CET (Europe/Berlin) (Run #43906540357, Laufzeit 16m 2s)
- 2026-11-16 19:37 CET (Europe/Berlin) (Run #43930765303, Laufzeit 19m 7s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
