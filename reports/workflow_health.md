# Workflow Health Report

**Stand:** 2026-06-25 14:50 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 10 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 13
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-06-25 04:44 UTC -> 2026-06-25 08:35 UTC (231 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 68
- **Skip-Runs:** 66
- **Fehlgeschlagene Runs:** 18
- **Lucken >210min:** 11
- **Groesste Lucke:** 2026-06-22 12:43 UTC -> 2026-06-22 17:19 UTC (275 min = 4h 35min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 181
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 39

Letzte Watchdog-Eingriffe:
- 2026-06-24 21:45 UTC (Run #28131691786, Laufzeit 21m 10s)
- 2026-06-25 01:27 UTC (Run #28140705667, Laufzeit 21m 2s)
- 2026-06-25 08:35 UTC (Run #28157623864, Laufzeit 21m 49s)
- 2026-06-25 09:41 UTC (Run #28161254017, Laufzeit 21m 55s)
- 2026-06-25 13:26 UTC (Run #28173513514, Laufzeit 21m 34s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-06-20 22:39 UTC - cancelled - Run #27886052818 (32s)
- 2026-06-21 05:23 UTC - cancelled - Run #27894618936 (6m 28s)
- 2026-06-21 05:30 UTC - cancelled - Run #27894749132 (23s)
- 2026-06-21 10:08 UTC - cancelled - Run #27901008331 (12m 44s)
- 2026-06-21 10:21 UTC - cancelled - Run #27901299194 (2m 4s)
- 2026-06-22 05:39 UTC - cancelled - Run #27932008625 (4m 31s)
- 2026-06-22 12:29 UTC - cancelled - Run #27952708468 (8m 0s)
- 2026-06-23 15:29 UTC - cancelled - Run #28037108035 (9m 15s)
- 2026-06-24 10:01 UTC - cancelled - Run #28090675387 (19m 15s)
- 2026-06-25 09:50 UTC - cancelled - Run #28161741883 (7m 21s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
