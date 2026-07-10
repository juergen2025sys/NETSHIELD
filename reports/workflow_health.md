# Workflow Health Report

**Stand:** 2026-07-10 19:47 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 10 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 12
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-07-10 04:32 UTC -> 2026-07-10 08:35 UTC (243 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 69
- **Skip-Runs:** 76
- **Fehlgeschlagene Runs:** 32
- **Lucken >210min:** 8
- **Groesste Lucke:** 2026-07-06 04:52 UTC -> 2026-07-06 09:36 UTC (283 min = 4h 43min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 223
- **Watchdog-Fehler:** 1
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 49

Letzte Watchdog-Eingriffe:
- 2026-07-10 08:35 UTC (Run #29080275505, Laufzeit 27m 53s)
- 2026-07-10 10:00 UTC (Run #29084926338, Laufzeit 27m 18s)
- 2026-07-10 12:41 UTC (Run #29093405699, Laufzeit 27m 29s)
- 2026-07-10 15:54 UTC (Run #29105394507, Laufzeit 29m 18s)
- 2026-07-10 18:45 UTC (Run #29115678660, Laufzeit 24m 4s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-07-08 17:09 UTC - cancelled - Run #28961343599 (1m 48s)
- 2026-07-08 19:47 UTC - cancelled - Run #28971005419 (12m 58s)
- 2026-07-08 20:00 UTC - cancelled - Run #28971774762 (8m 52s)
- 2026-07-09 10:02 UTC - cancelled - Run #29010232095 (11m 48s)
- 2026-07-09 10:13 UTC - cancelled - Run #29010904160 (7m 10s)
- 2026-07-09 15:46 UTC - cancelled - Run #29030850459 (15m 58s)
- 2026-07-09 20:15 UTC - cancelled - Run #29047246766 (13m 7s)
- 2026-07-10 04:30 UTC - cancelled - Run #29069219499 (2m 2s)
- 2026-07-10 10:04 UTC - cancelled - Run #29085123153 (23m 45s)
- 2026-07-10 15:09 UTC - cancelled - Run #29102593780 (4m 35s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
