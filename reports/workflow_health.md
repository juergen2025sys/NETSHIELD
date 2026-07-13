# Workflow Health Report

**Stand:** 2026-07-13 19:42 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 10 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 6
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 77
- **Skip-Runs:** 70
- **Fehlgeschlagene Runs:** 33
- **Lucken >210min:** 4
- **Groesste Lucke:** 2026-07-08 22:07 UTC -> 2026-07-09 02:22 UTC (255 min = 4h 15min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 241
- **Watchdog-Fehler:** 1
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 47

Letzte Watchdog-Eingriffe:
- 2026-07-13 01:04 UTC (Run #29216624662, Laufzeit 26m 39s)
- 2026-07-13 06:42 UTC (Run #29229764684, Laufzeit 26m 4s)
- 2026-07-13 12:27 UTC (Run #29249930200, Laufzeit 28m 39s)
- 2026-07-13 18:53 UTC (Run #29276271106, Laufzeit 6m 5s)
- 2026-07-13 18:59 UTC (Run #29276678385, Laufzeit 22m 12s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-07-11 22:11 UTC - cancelled - Run #29170094891 (13m 42s)
- 2026-07-12 04:05 UTC - cancelled - Run #29179197636 (3m 48s)
- 2026-07-12 14:01 UTC - cancelled - Run #29195476506 (6m 8s)
- 2026-07-13 04:07 UTC - cancelled - Run #29223174853 (7m 46s)
- 2026-07-13 09:51 UTC - cancelled - Run #29240663334 (7m 18s)
- 2026-07-13 09:58 UTC - cancelled - Run #29241095609 (6m 43s)
- 2026-07-13 15:18 UTC - cancelled - Run #29261704321 (1m 25s)
- 2026-07-13 17:27 UTC - cancelled - Run #29270496816 (14m 11s)
- 2026-07-13 17:41 UTC - cancelled - Run #29271444839 (1m 20s)
- 2026-07-13 18:53 UTC - cancelled - Run #29276271106 (6m 5s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
