# Workflow Health Report

**Stand:** 2026-07-04 03:56 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 8 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 15
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-07-03 04:25 UTC -> 2026-07-03 08:28 UTC (242 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 66
- **Skip-Runs:** 87
- **Fehlgeschlagene Runs:** 28
- **Lucken >210min:** 5
- **Groesste Lucke:** 2026-06-27 13:10 UTC -> 2026-06-27 18:22 UTC (311 min = 5h 11min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 213
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 54

Letzte Watchdog-Eingriffe:
- 2026-07-03 11:15 UTC (Run #28656969292, Laufzeit 24m 2s)
- 2026-07-03 13:17 UTC (Run #28663104046, Laufzeit 27m 45s)
- 2026-07-03 15:31 UTC (Run #28670001265, Laufzeit 19m 12s)
- 2026-07-03 18:36 UTC (Run #28677859935, Laufzeit 24m 1s)
- 2026-07-04 01:08 UTC (Run #28690278495, Laufzeit 17m 39s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-06-30 08:51 UTC - cancelled - Run #28432223520 (17m 32s)
- 2026-06-30 10:05 UTC - cancelled - Run #28436452450 (13m 7s)
- 2026-06-30 10:18 UTC - cancelled - Run #28437192936 (9m 2s)
- 2026-07-01 05:02 UTC - cancelled - Run #28494739293 (8m 41s)
- 2026-07-01 10:27 UTC - cancelled - Run #28510941905 (3m 46s)
- 2026-07-02 04:38 UTC - cancelled - Run #28565782430 (32s)
- 2026-07-02 09:47 UTC - cancelled - Run #28580950603 (19m 52s)
- 2026-07-02 22:14 UTC - cancelled - Run #28624977377 (5m 13s)
- 2026-07-03 04:23 UTC - cancelled - Run #28638277091 (2m 21s)
- 2026-07-03 22:31 UTC - cancelled - Run #28686124835 (2m 35s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
