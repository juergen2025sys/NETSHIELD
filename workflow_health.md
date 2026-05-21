# Workflow Health Report

**Stand:** 2026-05-21 04:22 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 7 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 7
- **Geschluckte Cron-Slots:** 24
  - Zeiten: 06:07, 06:27, 06:47, 09:07, 09:27, 09:47, 12:07, 12:27, 12:47, 15:07 ... (+14 weitere)
- **Lucken (>210min zwischen echten Runs):** 3
  - 2026-05-20 04:54 UTC -> 2026-05-20 09:51 UTC (296 min)
  - 2026-05-20 10:14 UTC -> 2026-05-20 15:14 UTC (300 min)
  - 2026-05-20 15:37 UTC -> 2026-05-20 20:28 UTC (290 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 50
- **Skip-Runs:** 8
- **Fehlgeschlagene Runs:** 2
- **Geschluckte Cron-Slots:** 168
- **Lucken >210min:** 16
- **Groesste Lucke:** 2026-05-18 04:25 UTC -> 2026-05-18 10:12 UTC (347 min = 5h 47min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 3
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 3

Letzte Watchdog-Eingriffe:
- 2026-05-17 17:38 UTC (Run #25997997717, Laufzeit 22m 0s)
- 2026-05-18 18:41 UTC (Run #26053163903, Laufzeit 21m 4s)
- 2026-05-20 15:14 UTC (Run #26171808458, Laufzeit 22m 46s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-05-19 20:11 UTC - cancelled - Run #26122470879 (8m 0s)
- 2026-05-20 09:58 UTC - cancelled - Run #26155300581 (4m 12s)

## Geschluckte Slots (7d)

Insgesamt 168 - zu viele fuer Einzel-Auflistung. Verteilung nach Stunde:

- 00:xx UTC -> 21x
- 03:xx UTC -> 21x
- 06:xx UTC -> 21x
- 09:xx UTC -> 21x
- 12:xx UTC -> 21x
- 15:xx UTC -> 21x
- 18:xx UTC -> 21x
- 21:xx UTC -> 21x

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
