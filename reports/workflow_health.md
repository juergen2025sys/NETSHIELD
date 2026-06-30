# Workflow Health Report

**Stand:** 2026-06-30 14:39 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 10
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-06-30 04:45 UTC -> 2026-06-30 08:42 UTC (236 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 66
- **Skip-Runs:** 85
- **Fehlgeschlagene Runs:** 26
- **Lucken >210min:** 7
- **Groesste Lucke:** 2026-06-26 22:10 UTC -> 2026-06-27 04:11 UTC (360 min = 6h 0min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 204
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 52

Letzte Watchdog-Eingriffe:
- 2026-06-30 01:35 UTC (Run #28414282830, Laufzeit 26m 8s)
- 2026-06-30 08:42 UTC (Run #28431715218, Laufzeit 26m 47s)
- 2026-06-30 08:51 UTC (Run #28432223520, Laufzeit 17m 32s)
- 2026-06-30 10:01 UTC (Run #28436199414, Laufzeit 26m 30s)
- 2026-06-30 13:28 UTC (Run #28447976296, Laufzeit 25m 51s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-06-28 09:39 UTC - cancelled - Run #28318150687 (8m 2s)
- 2026-06-28 09:47 UTC - cancelled - Run #28318337571 (9m 15s)
- 2026-06-28 14:08 UTC - cancelled - Run #28324832167 (13m 1s)
- 2026-06-29 05:09 UTC - cancelled - Run #28350009143 (9m 4s)
- 2026-06-29 05:18 UTC - cancelled - Run #28350351710 (1m 52s)
- 2026-06-29 16:22 UTC - cancelled - Run #28386783548 (1m 40s)
- 2026-06-30 04:41 UTC - cancelled - Run #28420781665 (4m 18s)
- 2026-06-30 08:51 UTC - cancelled - Run #28432223520 (17m 32s)
- 2026-06-30 10:05 UTC - cancelled - Run #28436452450 (13m 7s)
- 2026-06-30 10:18 UTC - cancelled - Run #28437192936 (9m 2s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
