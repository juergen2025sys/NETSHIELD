# Workflow Health Report

**Stand:** 2026-07-13 03:50 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 15
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 76
- **Skip-Runs:** 74
- **Fehlgeschlagene Runs:** 26
- **Lucken >210min:** 6
- **Groesste Lucke:** 2026-07-06 04:52 UTC -> 2026-07-06 09:36 UTC (283 min = 4h 43min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 237
- **Watchdog-Fehler:** 1
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 47

Letzte Watchdog-Eingriffe:
- 2026-07-12 10:08 UTC (Run #29188621810, Laufzeit 26m 3s)
- 2026-07-12 15:33 UTC (Run #29198430208, Laufzeit 26m 29s)
- 2026-07-12 18:32 UTC (Run #29204080619, Laufzeit 25m 20s)
- 2026-07-12 21:30 UTC (Run #29209741143, Laufzeit 26m 39s)
- 2026-07-13 01:04 UTC (Run #29216624662, Laufzeit 26m 39s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-07-10 04:30 UTC - cancelled - Run #29069219499 (2m 2s)
- 2026-07-10 10:04 UTC - cancelled - Run #29085123153 (23m 45s)
- 2026-07-10 15:09 UTC - cancelled - Run #29102593780 (4m 35s)
- 2026-07-11 03:50 UTC - cancelled - Run #29138634273 (6m 20s)
- 2026-07-11 03:56 UTC - cancelled - Run #29138800798 (5m 32s)
- 2026-07-11 16:35 UTC - cancelled - Run #29160072826 (19m 45s)
- 2026-07-11 19:18 UTC - cancelled - Run #29165034942 (6m 46s)
- 2026-07-11 22:11 UTC - cancelled - Run #29170094891 (13m 42s)
- 2026-07-12 04:05 UTC - cancelled - Run #29179197636 (3m 48s)
- 2026-07-12 14:01 UTC - cancelled - Run #29195476506 (6m 8s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
