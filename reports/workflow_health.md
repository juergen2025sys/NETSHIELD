# Workflow Health Report

**Stand:** 2026-06-27 04:12 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 8 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 13
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 67
- **Skip-Runs:** 76
- **Fehlgeschlagene Runs:** 15
- **Lucken >210min:** 9
- **Groesste Lucke:** 2026-06-22 12:43 UTC -> 2026-06-22 17:19 UTC (275 min = 4h 35min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 187
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 39

Letzte Watchdog-Eingriffe:
- 2026-06-26 06:35 UTC (Run #28221624318, Laufzeit 22m 55s)
- 2026-06-26 13:21 UTC (Run #28240759869, Laufzeit 21m 47s)
- 2026-06-26 15:41 UTC (Run #28248636595, Laufzeit 23m 33s)
- 2026-06-26 19:00 UTC (Run #28259162977, Laufzeit 22m 6s)
- 2026-06-26 21:48 UTC (Run #28267168115, Laufzeit 22m 38s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-06-21 05:30 UTC - cancelled - Run #27894749132 (23s)
- 2026-06-21 10:08 UTC - cancelled - Run #27901008331 (12m 44s)
- 2026-06-21 10:21 UTC - cancelled - Run #27901299194 (2m 4s)
- 2026-06-22 05:39 UTC - cancelled - Run #27932008625 (4m 31s)
- 2026-06-22 12:29 UTC - cancelled - Run #27952708468 (8m 0s)
- 2026-06-23 15:29 UTC - cancelled - Run #28037108035 (9m 15s)
- 2026-06-24 10:01 UTC - cancelled - Run #28090675387 (19m 15s)
- 2026-06-25 09:50 UTC - cancelled - Run #28161741883 (7m 21s)
- 2026-06-26 09:56 UTC - cancelled - Run #28230898725 (4m 27s)
- 2026-06-26 10:01 UTC - cancelled - Run #28231115831 (8m 33s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
