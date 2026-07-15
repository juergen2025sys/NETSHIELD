# Workflow Health Report

**Stand:** 2026-07-15 08:31 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 10 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 15
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 75
- **Skip-Runs:** 75
- **Fehlgeschlagene Runs:** 33
- **Lucken >210min:** 3
- **Groesste Lucke:** 2026-07-08 22:07 UTC -> 2026-07-09 02:22 UTC (255 min = 4h 15min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 255
- **Watchdog-Fehler:** 1
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 47

Letzte Watchdog-Eingriffe:
- 2026-07-14 15:49 UTC (Run #29347025667, Laufzeit 26m 26s)
- 2026-07-14 18:38 UTC (Run #29358707363, Laufzeit 26m 51s)
- 2026-07-14 21:34 UTC (Run #29370051089, Laufzeit 27m 19s)
- 2026-07-15 00:50 UTC (Run #29380102938, Laufzeit 21m 5s)
- 2026-07-15 06:28 UTC (Run #29394303603, Laufzeit 26m 45s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-07-13 09:58 UTC - cancelled - Run #29241095609 (6m 43s)
- 2026-07-13 15:18 UTC - cancelled - Run #29261704321 (1m 25s)
- 2026-07-13 17:27 UTC - cancelled - Run #29270496816 (14m 11s)
- 2026-07-13 17:41 UTC - cancelled - Run #29271444839 (1m 20s)
- 2026-07-13 18:53 UTC - cancelled - Run #29276271106 (6m 5s)
- 2026-07-13 22:24 UTC - cancelled - Run #29289782575 (5m 21s)
- 2026-07-14 03:42 UTC - cancelled - Run #29304156090 (5m 29s)
- 2026-07-14 03:47 UTC - cancelled - Run #29304375919 (25s)
- 2026-07-15 03:43 UTC - cancelled - Run #29387212358 (5m 16s)
- 2026-07-15 03:48 UTC - cancelled - Run #29387421351 (5s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
