# Workflow Health Report

**Stand:** 2026-07-04 13:54 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 10 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 15
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 68
- **Skip-Runs:** 85
- **Fehlgeschlagene Runs:** 31
- **Lucken >210min:** 4
- **Groesste Lucke:** 2026-06-28 21:59 UTC -> 2026-06-29 02:05 UTC (245 min = 4h 5min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 215
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 56

Letzte Watchdog-Eingriffe:
- 2026-07-04 04:51 UTC (Run #28695408333, Laufzeit 22m 39s)
- 2026-07-04 07:34 UTC (Run #28699280452, Laufzeit 32m 44s)
- 2026-07-04 09:49 UTC (Run #28702429934, Laufzeit 32m 22s)
- 2026-07-04 10:45 UTC (Run #28703718369, Laufzeit 32m 20s)
- 2026-07-04 12:44 UTC (Run #28706614906, Laufzeit 31m 13s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-07-01 10:27 UTC - cancelled - Run #28510941905 (3m 46s)
- 2026-07-02 04:38 UTC - cancelled - Run #28565782430 (32s)
- 2026-07-02 09:47 UTC - cancelled - Run #28580950603 (19m 52s)
- 2026-07-02 22:14 UTC - cancelled - Run #28624977377 (5m 13s)
- 2026-07-03 04:23 UTC - cancelled - Run #28638277091 (2m 21s)
- 2026-07-03 22:31 UTC - cancelled - Run #28686124835 (2m 35s)
- 2026-07-04 04:09 UTC - cancelled - Run #28694464140 (8m 19s)
- 2026-07-04 10:58 UTC - cancelled - Run #28704019076 (6m 16s)
- 2026-07-04 11:04 UTC - cancelled - Run #28704191296 (7m 17s)
- 2026-07-04 11:11 UTC - cancelled - Run #28704365176 (5m 50s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
