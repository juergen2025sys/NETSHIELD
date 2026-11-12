# Workflow Health Dashboard

**Stand:** 2026-11-13 00:31 CET (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 8 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 7
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-11-12 05:04 CET (Europe/Berlin) -> 2026-11-12 09:19 CET (Europe/Berlin) (254 min)
  - 2026-11-12 19:58 CET (Europe/Berlin) -> 2026-11-12 23:30 CET (Europe/Berlin) (212 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 55
- **Skip-Runs:** 43
- **Fehlgeschlagene Runs:** 0
- **Lucken >210min:** 12
- **Groesste Lucke:** 2026-11-08 01:44 CET (Europe/Berlin) -> 2026-11-08 07:25 CET (Europe/Berlin) (341 min = 5h 41min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 403
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 34

Letzte Watchdog-Eingriffe:
- 2026-11-12 09:19 CET (Europe/Berlin) (Run #43182007626, Laufzeit 19m 27s)
- 2026-11-12 13:28 CET (Europe/Berlin) (Run #43218257378, Laufzeit 18m 51s)
- 2026-11-12 17:05 CET (Europe/Berlin) (Run #43254853657, Laufzeit 21m 56s)
- 2026-11-12 19:40 CET (Europe/Berlin) (Run #43282375123, Laufzeit 17m 27s)
- 2026-11-12 23:30 CET (Europe/Berlin) (Run #43320571315, Laufzeit 16m 22s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
