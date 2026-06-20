# Workflow Health Report

**Stand:** 2026-06-20 14:26 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 9
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-06-19 22:01 UTC -> 2026-06-20 01:51 UTC (230 min)
  - 2026-06-20 04:52 UTC -> 2026-06-20 08:32 UTC (220 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 68
- **Skip-Runs:** 64
- **Fehlgeschlagene Runs:** 14
- **Lucken >210min:** 10
- **Groesste Lucke:** 2026-06-18 21:49 UTC -> 2026-06-19 02:06 UTC (256 min = 4h 16min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 166
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 40

Letzte Watchdog-Eingriffe:
- 2026-06-19 21:39 UTC (Run #27849641264, Laufzeit 21m 40s)
- 2026-06-20 01:51 UTC (Run #27856640640, Laufzeit 21m 18s)
- 2026-06-20 08:32 UTC (Run #27865740571, Laufzeit 21m 44s)
- 2026-06-20 09:35 UTC (Run #27867188487, Laufzeit 20m 41s)
- 2026-06-20 13:07 UTC (Run #27872112753, Laufzeit 20m 56s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-06-17 05:22 UTC - cancelled - Run #27667680318 (2m 52s)
- 2026-06-17 11:20 UTC - cancelled - Run #27685234412 (2m 36s)
- 2026-06-18 05:13 UTC - cancelled - Run #27738275736 (1m 45s)
- 2026-06-19 05:32 UTC - cancelled - Run #27807503538 (7m 0s)
- 2026-06-19 11:01 UTC - cancelled - Run #27821830743 (5m 26s)
- 2026-06-19 11:07 UTC - cancelled - Run #27822080589 (3m 20s)
- 2026-06-19 15:46 UTC - cancelled - Run #27835395108 (6m 38s)
- 2026-06-19 15:53 UTC - cancelled - Run #27835705718 (5m 12s)
- 2026-06-20 09:47 UTC - cancelled - Run #27867466283 (4m 47s)
- 2026-06-20 09:52 UTC - cancelled - Run #27867575286 (3m 50s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
