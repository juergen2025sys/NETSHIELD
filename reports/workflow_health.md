# Workflow Health Report

**Stand:** 2026-07-09 04:07 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 12 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 7
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-07-08 22:07 UTC -> 2026-07-09 02:22 UTC (255 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 69
- **Skip-Runs:** 84
- **Fehlgeschlagene Runs:** 29
- **Lucken >210min:** 7
- **Groesste Lucke:** 2026-07-06 04:52 UTC -> 2026-07-06 09:36 UTC (283 min = 4h 43min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 228
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 50

Letzte Watchdog-Eingriffe:
- 2026-07-08 15:42 UTC (Run #28955632902, Laufzeit 10m 40s)
- 2026-07-08 16:50 UTC (Run #28960157544, Laufzeit 21m 2s)
- 2026-07-08 18:45 UTC (Run #28967279175, Laufzeit 26m 0s)
- 2026-07-08 21:41 UTC (Run #28977726658, Laufzeit 26m 9s)
- 2026-07-09 02:22 UTC (Run #28989590974, Laufzeit 26m 30s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-07-07 15:22 UTC - cancelled - Run #28877800454 (11m 49s)
- 2026-07-08 03:52 UTC - cancelled - Run #28916179136 (6m 4s)
- 2026-07-08 03:58 UTC - cancelled - Run #28916396450 (3m 7s)
- 2026-07-08 09:04 UTC - cancelled - Run #28930839109 (6m 44s)
- 2026-07-08 11:30 UTC - cancelled - Run #28939226442 (17m 28s)
- 2026-07-08 15:42 UTC - cancelled - Run #28955632902 (10m 40s)
- 2026-07-08 16:55 UTC - cancelled - Run #28960455660 (14m 32s)
- 2026-07-08 17:09 UTC - cancelled - Run #28961343599 (1m 48s)
- 2026-07-08 19:47 UTC - cancelled - Run #28971005419 (12m 58s)
- 2026-07-08 20:00 UTC - cancelled - Run #28971774762 (8m 52s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
