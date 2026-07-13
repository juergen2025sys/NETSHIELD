# Workflow Health Report

**Stand:** 2026-07-13 14:55 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 9
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 76
- **Skip-Runs:** 71
- **Fehlgeschlagene Runs:** 29
- **Lucken >210min:** 4
- **Groesste Lucke:** 2026-07-08 22:07 UTC -> 2026-07-09 02:22 UTC (255 min = 4h 15min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 238
- **Watchdog-Fehler:** 1
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 47

Letzte Watchdog-Eingriffe:
- 2026-07-12 18:32 UTC (Run #29204080619, Laufzeit 25m 20s)
- 2026-07-12 21:30 UTC (Run #29209741143, Laufzeit 26m 39s)
- 2026-07-13 01:04 UTC (Run #29216624662, Laufzeit 26m 39s)
- 2026-07-13 06:42 UTC (Run #29229764684, Laufzeit 26m 4s)
- 2026-07-13 12:27 UTC (Run #29249930200, Laufzeit 28m 39s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-07-11 03:50 UTC - cancelled - Run #29138634273 (6m 20s)
- 2026-07-11 03:56 UTC - cancelled - Run #29138800798 (5m 32s)
- 2026-07-11 16:35 UTC - cancelled - Run #29160072826 (19m 45s)
- 2026-07-11 19:18 UTC - cancelled - Run #29165034942 (6m 46s)
- 2026-07-11 22:11 UTC - cancelled - Run #29170094891 (13m 42s)
- 2026-07-12 04:05 UTC - cancelled - Run #29179197636 (3m 48s)
- 2026-07-12 14:01 UTC - cancelled - Run #29195476506 (6m 8s)
- 2026-07-13 04:07 UTC - cancelled - Run #29223174853 (7m 46s)
- 2026-07-13 09:51 UTC - cancelled - Run #29240663334 (7m 18s)
- 2026-07-13 09:58 UTC - cancelled - Run #29241095609 (6m 43s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
