# Workflow Health Dashboard

**Stand:** 2026-11-05 07:33 CET (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 7 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 6
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-11-04 11:15 CET (Europe/Berlin) -> 2026-11-04 15:18 CET (Europe/Berlin) (243 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 58
- **Skip-Runs:** 42
- **Fehlgeschlagene Runs:** 0
- **Lucken >210min:** 9
- **Groesste Lucke:** 2026-11-03 10:47 CET (Europe/Berlin) -> 2026-11-03 16:31 CET (Europe/Berlin) (343 min = 5h 43min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 202
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 34

Letzte Watchdog-Eingriffe:
- 2026-11-04 10:59 CET (Europe/Berlin) (Run #41811180496, Laufzeit 16m 32s)
- 2026-11-04 16:41 CET (Europe/Berlin) (Run #41860405712, Laufzeit 37m 4s)
- 2026-11-04 19:38 CET (Europe/Berlin) (Run #41889080566, Laufzeit 19m 24s)
- 2026-11-05 01:33 CET (Europe/Berlin) (Run #41942258367, Laufzeit 19m 21s)
- 2026-11-05 04:46 CET (Europe/Berlin) (Run #41963701687, Laufzeit 15m 48s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
