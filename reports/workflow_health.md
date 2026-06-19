# Workflow Health Report

**Stand:** 2026-06-19 05:19 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 10
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-06-18 10:15 UTC -> 2026-06-18 13:47 UTC (212 min)
  - 2026-06-18 21:49 UTC -> 2026-06-19 02:06 UTC (256 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 68
- **Skip-Runs:** 63
- **Fehlgeschlagene Runs:** 13
- **Lucken >210min:** 10
- **Groesste Lucke:** 2026-06-18 21:49 UTC -> 2026-06-19 02:06 UTC (256 min = 4h 16min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 166
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 39

Letzte Watchdog-Eingriffe:
- 2026-06-18 09:53 UTC (Run #27751448644, Laufzeit 21m 28s)
- 2026-06-18 13:47 UTC (Run #27764028709, Laufzeit 17m 18s)
- 2026-06-18 18:36 UTC (Run #27781269586, Laufzeit 22m 5s)
- 2026-06-18 21:28 UTC (Run #27790418359, Laufzeit 21m 16s)
- 2026-06-19 02:06 UTC (Run #27800995108, Laufzeit 20m 45s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-06-13 04:57 UTC - cancelled - Run #27457175275 (6m 15s)
- 2026-06-13 09:41 UTC - cancelled - Run #27463188704 (4m 42s)
- 2026-06-13 09:46 UTC - cancelled - Run #27463289167 (4m 28s)
- 2026-06-13 16:54 UTC - cancelled - Run #27473054418 (8m 26s)
- 2026-06-14 10:01 UTC - cancelled - Run #27495391072 (7m 4s)
- 2026-06-15 12:47 UTC - cancelled - Run #27547250930 (6m 38s)
- 2026-06-16 21:27 UTC - cancelled - Run #27649317806 (7m 7s)
- 2026-06-17 05:22 UTC - cancelled - Run #27667680318 (2m 52s)
- 2026-06-17 11:20 UTC - cancelled - Run #27685234412 (2m 36s)
- 2026-06-18 05:13 UTC - cancelled - Run #27738275736 (1m 45s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
