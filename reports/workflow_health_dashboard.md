# Workflow Health Dashboard

**Stand:** 2026-11-27 09:13 CET (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 4
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-11-27 01:17 CET (Europe/Berlin) -> 2026-11-27 05:21 CET (Europe/Berlin) (243 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 62
- **Skip-Runs:** 43
- **Fehlgeschlagene Runs:** 2
- **Lucken >210min:** 7
- **Groesste Lucke:** 2026-11-22 01:52 CET (Europe/Berlin) -> 2026-11-22 08:34 CET (Europe/Berlin) (401 min = 6h 41min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 266
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 53

Letzte Watchdog-Eingriffe:
- 2026-11-26 16:55 CET (Europe/Berlin) (Run #45853782855, Laufzeit 16m 32s)
- 2026-11-26 19:56 CET (Europe/Berlin) (Run #45879836024, Laufzeit 19m 20s)
- 2026-11-26 20:59 CET (Europe/Berlin) (Run #45887732152, Laufzeit 16m 1s)
- 2026-11-26 22:38 CET (Europe/Berlin) (Run #45899556927, Laufzeit 16m 36s)
- 2026-11-27 05:21 CET (Europe/Berlin) (Run #45939440159, Laufzeit 16m 0s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-11-21 11:52 CET (Europe/Berlin) - cancelled - Run #44896391381 (2m 3s)
- 2026-11-25 16:58 CET (Europe/Berlin) - failure - Run #45650104889 (18m 18s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
