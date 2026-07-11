# Workflow Health Report

**Stand:** 2026-07-11 13:47 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 12 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 14
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 70
- **Skip-Runs:** 78
- **Fehlgeschlagene Runs:** 29
- **Lucken >210min:** 8
- **Groesste Lucke:** 2026-07-06 04:52 UTC -> 2026-07-06 09:36 UTC (283 min = 4h 43min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 226
- **Watchdog-Fehler:** 1
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 48

Letzte Watchdog-Eingriffe:
- 2026-07-10 21:35 UTC (Run #29125167610, Laufzeit 29m 31s)
- 2026-07-11 00:58 UTC (Run #29133738244, Laufzeit 25m 49s)
- 2026-07-11 06:31 UTC (Run #29142955336, Laufzeit 30m 27s)
- 2026-07-11 09:53 UTC (Run #29148472672, Laufzeit 24m 13s)
- 2026-07-11 12:37 UTC (Run #29152948624, Laufzeit 29m 56s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-07-08 20:00 UTC - cancelled - Run #28971774762 (8m 52s)
- 2026-07-09 10:02 UTC - cancelled - Run #29010232095 (11m 48s)
- 2026-07-09 10:13 UTC - cancelled - Run #29010904160 (7m 10s)
- 2026-07-09 15:46 UTC - cancelled - Run #29030850459 (15m 58s)
- 2026-07-09 20:15 UTC - cancelled - Run #29047246766 (13m 7s)
- 2026-07-10 04:30 UTC - cancelled - Run #29069219499 (2m 2s)
- 2026-07-10 10:04 UTC - cancelled - Run #29085123153 (23m 45s)
- 2026-07-10 15:09 UTC - cancelled - Run #29102593780 (4m 35s)
- 2026-07-11 03:50 UTC - cancelled - Run #29138634273 (6m 20s)
- 2026-07-11 03:56 UTC - cancelled - Run #29138800798 (5m 32s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
