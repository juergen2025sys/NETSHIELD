# Workflow Health Report

**Stand:** 2026-07-03 04:02 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 10 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 12
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 66
- **Skip-Runs:** 85
- **Fehlgeschlagene Runs:** 28
- **Lucken >210min:** 5
- **Groesste Lucke:** 2026-06-26 22:10 UTC -> 2026-06-27 04:11 UTC (360 min = 6h 0min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 209
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 53

Letzte Watchdog-Eingriffe:
- 2026-07-02 12:28 UTC (Run #28589978567, Laufzeit 23m 59s)
- 2026-07-02 16:24 UTC (Run #28605384329, Laufzeit 24m 13s)
- 2026-07-02 18:48 UTC (Run #28613939735, Laufzeit 26m 19s)
- 2026-07-02 21:55 UTC (Run #28624071825, Laufzeit 24m 10s)
- 2026-07-03 01:09 UTC (Run #28631755053, Laufzeit 23m 57s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-06-29 16:22 UTC - cancelled - Run #28386783548 (1m 40s)
- 2026-06-30 04:41 UTC - cancelled - Run #28420781665 (4m 18s)
- 2026-06-30 08:51 UTC - cancelled - Run #28432223520 (17m 32s)
- 2026-06-30 10:05 UTC - cancelled - Run #28436452450 (13m 7s)
- 2026-06-30 10:18 UTC - cancelled - Run #28437192936 (9m 2s)
- 2026-07-01 05:02 UTC - cancelled - Run #28494739293 (8m 41s)
- 2026-07-01 10:27 UTC - cancelled - Run #28510941905 (3m 46s)
- 2026-07-02 04:38 UTC - cancelled - Run #28565782430 (32s)
- 2026-07-02 09:47 UTC - cancelled - Run #28580950603 (19m 52s)
- 2026-07-02 22:14 UTC - cancelled - Run #28624977377 (5m 13s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
