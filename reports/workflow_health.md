# Workflow Health Report

**Stand:** 2026-07-10 09:50 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 9
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-07-09 10:20 UTC -> 2026-07-09 14:05 UTC (224 min)
  - 2026-07-10 04:32 UTC -> 2026-07-10 08:35 UTC (243 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 68
- **Skip-Runs:** 78
- **Fehlgeschlagene Runs:** 30
- **Lucken >210min:** 8
- **Groesste Lucke:** 2026-07-06 04:52 UTC -> 2026-07-06 09:36 UTC (283 min = 4h 43min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 223
- **Watchdog-Fehler:** 1
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 49

Letzte Watchdog-Eingriffe:
- 2026-07-09 15:45 UTC (Run #29030767827, Laufzeit 27m 22s)
- 2026-07-09 19:08 UTC (Run #29043269130, Laufzeit 27m 21s)
- 2026-07-09 21:44 UTC (Run #29052383803, Laufzeit 24m 18s)
- 2026-07-10 01:08 UTC (Run #29061703274, Laufzeit 27m 24s)
- 2026-07-10 08:35 UTC (Run #29080275505, Laufzeit 27m 53s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-07-08 15:42 UTC - cancelled - Run #28955632902 (10m 40s)
- 2026-07-08 16:55 UTC - cancelled - Run #28960455660 (14m 32s)
- 2026-07-08 17:09 UTC - cancelled - Run #28961343599 (1m 48s)
- 2026-07-08 19:47 UTC - cancelled - Run #28971005419 (12m 58s)
- 2026-07-08 20:00 UTC - cancelled - Run #28971774762 (8m 52s)
- 2026-07-09 10:02 UTC - cancelled - Run #29010232095 (11m 48s)
- 2026-07-09 10:13 UTC - cancelled - Run #29010904160 (7m 10s)
- 2026-07-09 15:46 UTC - cancelled - Run #29030850459 (15m 58s)
- 2026-07-09 20:15 UTC - cancelled - Run #29047246766 (13m 7s)
- 2026-07-10 04:30 UTC - cancelled - Run #29069219499 (2m 2s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
