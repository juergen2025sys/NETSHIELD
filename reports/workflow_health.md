# Workflow Health Report

**Stand:** 2026-07-22 08:41 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 14
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 71
- **Skip-Runs:** 94
- **Fehlgeschlagene Runs:** 22
- **Lucken >210min:** 2
- **Groesste Lucke:** 2026-07-19 22:03 UTC -> 2026-07-20 03:54 UTC (351 min = 5h 51min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 275
- **Watchdog-Fehler:** 3
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 42

Letzte Watchdog-Eingriffe:
- 2026-07-21 16:12 UTC (Run #29847517916, Laufzeit 25m 6s)
- 2026-07-21 18:40 UTC (Run #29858233776, Laufzeit 23m 20s)
- 2026-07-21 21:31 UTC (Run #29870267030, Laufzeit 27m 53s)
- 2026-07-22 00:57 UTC (Run #29881740414, Laufzeit 27m 7s)
- 2026-07-22 06:42 UTC (Run #29897631481, Laufzeit 23m 23s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-07-20 04:11 UTC - cancelled - Run #29716287390 (10m 27s)
- 2026-07-20 09:40 UTC - cancelled - Run #29732296990 (5m 15s)
- 2026-07-20 09:45 UTC - cancelled - Run #29732613925 (12m 50s)
- 2026-07-20 22:28 UTC - cancelled - Run #29784047205 (6m 28s)
- 2026-07-21 03:53 UTC - cancelled - Run #29799736439 (1m 12s)
- 2026-07-21 09:07 UTC - cancelled - Run #29816981453 (46s)
- 2026-07-21 14:47 UTC - cancelled - Run #29840835057 (10m 20s)
- 2026-07-21 16:37 UTC - cancelled - Run #29849396576 (6s)
- 2026-07-22 03:55 UTC - cancelled - Run #29889685667 (5m 35s)
- 2026-07-22 04:00 UTC - cancelled - Run #29889926127 (2m 2s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
