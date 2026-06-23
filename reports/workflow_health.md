# Workflow Health Report

**Stand:** 2026-06-23 04:16 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 8 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 6
- **Lucken (>210min zwischen echten Runs):** 3
  - 2026-06-22 07:59 UTC -> 2026-06-22 12:21 UTC (262 min)
  - 2026-06-22 12:43 UTC -> 2026-06-22 17:19 UTC (275 min)
  - 2026-06-22 21:49 UTC -> 2026-06-23 01:23 UTC (213 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 65
- **Skip-Runs:** 58
- **Fehlgeschlagene Runs:** 19
- **Lucken >210min:** 11
- **Groesste Lucke:** 2026-06-22 12:43 UTC -> 2026-06-22 17:19 UTC (275 min = 4h 35min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 166
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 35

Letzte Watchdog-Eingriffe:
- 2026-06-21 21:42 UTC (Run #27918383199, Laufzeit 21m 28s)
- 2026-06-22 01:41 UTC (Run #27924417458, Laufzeit 22m 7s)
- 2026-06-22 07:38 UTC (Run #27937110491, Laufzeit 21m 25s)
- 2026-06-22 18:56 UTC (Run #27976565439, Laufzeit 21m 47s)
- 2026-06-23 01:23 UTC (Run #27995639203, Laufzeit 19m 53s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-06-20 09:47 UTC - cancelled - Run #27867466283 (4m 47s)
- 2026-06-20 09:52 UTC - cancelled - Run #27867575286 (3m 50s)
- 2026-06-20 16:59 UTC - cancelled - Run #27877877927 (10s)
- 2026-06-20 22:39 UTC - cancelled - Run #27886052818 (32s)
- 2026-06-21 05:23 UTC - cancelled - Run #27894618936 (6m 28s)
- 2026-06-21 05:30 UTC - cancelled - Run #27894749132 (23s)
- 2026-06-21 10:08 UTC - cancelled - Run #27901008331 (12m 44s)
- 2026-06-21 10:21 UTC - cancelled - Run #27901299194 (2m 4s)
- 2026-06-22 05:39 UTC - cancelled - Run #27932008625 (4m 31s)
- 2026-06-22 12:29 UTC - cancelled - Run #27952708468 (8m 0s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
