# Workflow Health Dashboard

**Stand:** 2026-11-09 23:15 CET (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 7 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 2
- **Lucken (>210min zwischen echten Runs):** 3
  - 2026-11-09 02:21 CET (Europe/Berlin) -> 2026-11-09 07:01 CET (Europe/Berlin) (279 min)
  - 2026-11-09 13:15 CET (Europe/Berlin) -> 2026-11-09 16:59 CET (Europe/Berlin) (224 min)
  - 2026-11-09 17:12 CET (Europe/Berlin) -> 2026-11-09 21:03 CET (Europe/Berlin) (230 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 52
- **Skip-Runs:** 42
- **Fehlgeschlagene Runs:** 1
- **Lucken >210min:** 14
- **Groesste Lucke:** 2026-11-03 10:47 CET (Europe/Berlin) -> 2026-11-03 16:31 CET (Europe/Berlin) (343 min = 5h 43min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 306
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 32

Letzte Watchdog-Eingriffe:
- 2026-11-08 16:57 CET (Europe/Berlin) (Run #42497430459, Laufzeit 19m 37s)
- 2026-11-08 19:27 CET (Europe/Berlin) (Run #42510078134, Laufzeit 13m 20s)
- 2026-11-09 10:41 CET (Europe/Berlin) (Run #42595311549, Laufzeit 19m 38s)
- 2026-11-09 21:03 CET (Europe/Berlin) (Run #42689256061, Laufzeit 16m 15s)
- 2026-11-09 22:33 CET (Europe/Berlin) (Run #42703673558, Laufzeit 13m 0s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-11-05 16:51 CET (Europe/Berlin) - failure - Run #42059237139 (16m 18s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
