# Workflow Health Dashboard

**Stand:** 2026-11-04 15:28 CET (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 7 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 7
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-11-03 16:51 CET (Europe/Berlin) -> 2026-11-03 20:40 CET (Europe/Berlin) (228 min)
  - 2026-11-04 07:20 CET (Europe/Berlin) -> 2026-11-04 10:59 CET (Europe/Berlin) (218 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 57
- **Skip-Runs:** 43
- **Fehlgeschlagene Runs:** 0
- **Lucken >210min:** 9
- **Groesste Lucke:** 2026-11-03 10:47 CET (Europe/Berlin) -> 2026-11-03 16:31 CET (Europe/Berlin) (343 min = 5h 43min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 206
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 34

Letzte Watchdog-Eingriffe:
- 2026-11-03 16:31 CET (Europe/Berlin) (Run #41664777866, Laufzeit 20m 4s)
- 2026-11-03 23:27 CET (Europe/Berlin) (Run #41731026614, Laufzeit 16m 26s)
- 2026-11-04 02:20 CET (Europe/Berlin) (Run #41753337438, Laufzeit 19m 14s)
- 2026-11-04 04:12 CET (Europe/Berlin) (Run #41765686410, Laufzeit 15m 29s)
- 2026-11-04 10:59 CET (Europe/Berlin) (Run #41811180496, Laufzeit 16m 32s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
