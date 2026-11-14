# Workflow Health Dashboard

**Stand:** 2026-11-14 07:09 CET (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 8 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 9
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-11-14 01:51 CET (Europe/Berlin) -> 2026-11-14 05:42 CET (Europe/Berlin) (231 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 57
- **Skip-Runs:** 45
- **Fehlgeschlagene Runs:** 0
- **Lucken >210min:** 10
- **Groesste Lucke:** 2026-11-08 01:44 CET (Europe/Berlin) -> 2026-11-08 07:25 CET (Europe/Berlin) (341 min = 5h 41min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 416
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 39

Letzte Watchdog-Eingriffe:
- 2026-11-13 16:36 CET (Europe/Berlin) (Run #43454258218, Laufzeit 15m 17s)
- 2026-11-13 19:34 CET (Europe/Berlin) (Run #43483998064, Laufzeit 19m 12s)
- 2026-11-13 22:41 CET (Europe/Berlin) (Run #43512904615, Laufzeit 12m 40s)
- 2026-11-14 01:35 CET (Europe/Berlin) (Run #43535235707, Laufzeit 15m 31s)
- 2026-11-14 05:42 CET (Europe/Berlin) (Run #43558012360, Laufzeit 19m 8s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
