# Workflow Health Report

**Stand:** 2026-07-11 19:20 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 14 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 13
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 73
- **Skip-Runs:** 78
- **Fehlgeschlagene Runs:** 25
- **Lucken >210min:** 8
- **Groesste Lucke:** 2026-07-06 04:52 UTC -> 2026-07-06 09:36 UTC (283 min = 4h 43min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 229
- **Watchdog-Fehler:** 1
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 49

Letzte Watchdog-Eingriffe:
- 2026-07-11 15:30 UTC (Run #29158038737, Laufzeit 31m 9s)
- 2026-07-11 16:24 UTC (Run #29159728457, Laufzeit 30m 40s)
- 2026-07-11 17:49 UTC (Run #29162331530, Laufzeit 28m 4s)
- 2026-07-11 18:29 UTC (Run #29163533962, Laufzeit 21m 30s)
- 2026-07-11 18:58 UTC (Run #29164435960, Laufzeit 6s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-07-09 10:02 UTC - cancelled - Run #29010232095 (11m 48s)
- 2026-07-09 10:13 UTC - cancelled - Run #29010904160 (7m 10s)
- 2026-07-09 15:46 UTC - cancelled - Run #29030850459 (15m 58s)
- 2026-07-09 20:15 UTC - cancelled - Run #29047246766 (13m 7s)
- 2026-07-10 04:30 UTC - cancelled - Run #29069219499 (2m 2s)
- 2026-07-10 10:04 UTC - cancelled - Run #29085123153 (23m 45s)
- 2026-07-10 15:09 UTC - cancelled - Run #29102593780 (4m 35s)
- 2026-07-11 03:50 UTC - cancelled - Run #29138634273 (6m 20s)
- 2026-07-11 03:56 UTC - cancelled - Run #29138800798 (5m 32s)
- 2026-07-11 16:35 UTC - cancelled - Run #29160072826 (19m 45s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
