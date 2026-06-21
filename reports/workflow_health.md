# Workflow Health Report

**Stand:** 2026-06-21 19:57 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 10 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 8
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 68
- **Skip-Runs:** 58
- **Fehlgeschlagene Runs:** 18
- **Lucken >210min:** 9
- **Groesste Lucke:** 2026-06-18 21:49 UTC -> 2026-06-19 02:06 UTC (256 min = 4h 16min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 166
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 38

Letzte Watchdog-Eingriffe:
- 2026-06-21 01:40 UTC (Run #27889939805, Laufzeit 17m 33s)
- 2026-06-21 07:03 UTC (Run #27896729193, Laufzeit 17m 35s)
- 2026-06-21 12:28 UTC (Run #27904341204, Laufzeit 21m 10s)
- 2026-06-21 16:11 UTC (Run #27910061065, Laufzeit 21m 58s)
- 2026-06-21 19:00 UTC (Run #27914330882, Laufzeit 21m 35s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-06-19 15:46 UTC - cancelled - Run #27835395108 (6m 38s)
- 2026-06-19 15:53 UTC - cancelled - Run #27835705718 (5m 12s)
- 2026-06-20 09:47 UTC - cancelled - Run #27867466283 (4m 47s)
- 2026-06-20 09:52 UTC - cancelled - Run #27867575286 (3m 50s)
- 2026-06-20 16:59 UTC - cancelled - Run #27877877927 (10s)
- 2026-06-20 22:39 UTC - cancelled - Run #27886052818 (32s)
- 2026-06-21 05:23 UTC - cancelled - Run #27894618936 (6m 28s)
- 2026-06-21 05:30 UTC - cancelled - Run #27894749132 (23s)
- 2026-06-21 10:08 UTC - cancelled - Run #27901008331 (12m 44s)
- 2026-06-21 10:21 UTC - cancelled - Run #27901299194 (2m 4s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
