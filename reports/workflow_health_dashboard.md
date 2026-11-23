# Workflow Health Dashboard

**Stand:** 2026-11-24 00:47 CET (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 8 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 5
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-11-23 04:43 CET (Europe/Berlin) -> 2026-11-23 08:46 CET (Europe/Berlin) (242 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 60
- **Skip-Runs:** 45
- **Fehlgeschlagene Runs:** 1
- **Lucken >210min:** 9
- **Groesste Lucke:** 2026-11-22 01:52 CET (Europe/Berlin) -> 2026-11-22 08:34 CET (Europe/Berlin) (401 min = 6h 41min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 282
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 49

Letzte Watchdog-Eingriffe:
- 2026-11-23 08:46 CET (Europe/Berlin) (Run #45133508933, Laufzeit 17m 23s)
- 2026-11-23 10:46 CET (Europe/Berlin) (Run #45150042366, Laufzeit 27m 53s)
- 2026-11-23 16:30 CET (Europe/Berlin) (Run #45206036529, Laufzeit 19m 33s)
- 2026-11-23 19:43 CET (Europe/Berlin) (Run #45241351605, Laufzeit 19m 7s)
- 2026-11-23 22:46 CET (Europe/Berlin) (Run #45273022858, Laufzeit 13m 30s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-11-21 11:52 CET (Europe/Berlin) - cancelled - Run #44896391381 (2m 3s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
