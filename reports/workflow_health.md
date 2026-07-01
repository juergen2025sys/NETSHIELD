# Workflow Health Report

**Stand:** 2026-07-01 14:54 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 11 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 12
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 66
- **Skip-Runs:** 86
- **Fehlgeschlagene Runs:** 26
- **Lucken >210min:** 6
- **Groesste Lucke:** 2026-06-26 22:10 UTC -> 2026-06-27 04:11 UTC (360 min = 6h 0min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 205
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 52

Letzte Watchdog-Eingriffe:
- 2026-06-30 19:17 UTC (Run #28469851108, Laufzeit 23m 11s)
- 2026-06-30 21:51 UTC (Run #28478206676, Laufzeit 24m 47s)
- 2026-07-01 01:33 UTC (Run #28487351947, Laufzeit 24m 17s)
- 2026-07-01 06:45 UTC (Run #28498959277, Laufzeit 23m 0s)
- 2026-07-01 13:40 UTC (Run #28521915129, Laufzeit 22m 55s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-06-28 14:08 UTC - cancelled - Run #28324832167 (13m 1s)
- 2026-06-29 05:09 UTC - cancelled - Run #28350009143 (9m 4s)
- 2026-06-29 05:18 UTC - cancelled - Run #28350351710 (1m 52s)
- 2026-06-29 16:22 UTC - cancelled - Run #28386783548 (1m 40s)
- 2026-06-30 04:41 UTC - cancelled - Run #28420781665 (4m 18s)
- 2026-06-30 08:51 UTC - cancelled - Run #28432223520 (17m 32s)
- 2026-06-30 10:05 UTC - cancelled - Run #28436452450 (13m 7s)
- 2026-06-30 10:18 UTC - cancelled - Run #28437192936 (9m 2s)
- 2026-07-01 05:02 UTC - cancelled - Run #28494739293 (8m 41s)
- 2026-07-01 10:27 UTC - cancelled - Run #28510941905 (3m 46s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
