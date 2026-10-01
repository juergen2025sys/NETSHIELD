# Workflow Health Dashboard

**Stand:** 2026-10-01 15:03 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 17 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 8
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 86
- **Skip-Runs:** 58
- **Fehlgeschlagene Runs:** 1
- **Lucken >210min:** 7
- **Groesste Lucke:** 2026-09-27 08:51 CEST (Europe/Berlin) -> 2026-09-27 13:54 CEST (Europe/Berlin) (302 min = 5h 2min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 251
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 64

Letzte Watchdog-Eingriffe:
- 2026-10-01 04:29 CEST (Europe/Berlin) (Run #36806093871, Laufzeit 17m 6s)
- 2026-10-01 08:21 CEST (Europe/Berlin) (Run #36824318128, Laufzeit 16m 57s)
- 2026-10-01 09:56 CEST (Europe/Berlin) (Run #36833241118, Laufzeit 16m 26s)
- 2026-10-01 10:55 CEST (Europe/Berlin) (Run #36839395788, Laufzeit 15m 32s)
- 2026-10-01 11:29 CEST (Europe/Berlin) (Run #36843066813, Laufzeit 17m 16s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-09-26 14:28 CEST (Europe/Berlin) - cancelled - Run #36242007151 (4m 18s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
