# Workflow Health Report

**Stand:** 2026-06-08 04:58 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 12
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-06-07 21:54 UTC -> 2026-06-08 01:35 UTC (220 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 63
- **Skip-Runs:** 55
- **Fehlgeschlagene Runs:** 30
- **Lucken >210min:** 14
- **Groesste Lucke:** 2026-06-04 22:16 UTC -> 2026-06-05 04:41 UTC (385 min = 6h 25min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 169
- **Watchdog-Fehler:** 2
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 40

Letzte Watchdog-Eingriffe:
- 2026-06-07 12:54 UTC (Run #27093164240, Laufzeit 23m 0s)
- 2026-06-07 15:59 UTC (Run #27097548937, Laufzeit 28m 44s)
- 2026-06-07 18:44 UTC (Run #27101435802, Laufzeit 21m 16s)
- 2026-06-07 21:33 UTC (Run #27105458146, Laufzeit 20m 43s)
- 2026-06-08 01:35 UTC (Run #27111182199, Laufzeit 21m 25s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-06-05 04:54 UTC - cancelled - Run #26996197515 (9m 2s)
- 2026-06-05 10:36 UTC - cancelled - Run #27010031379 (21m 25s)
- 2026-06-05 15:39 UTC - cancelled - Run #27024548471 (14m 42s)
- 2026-06-06 04:14 UTC - cancelled - Run #27052289692 (13m 26s)
- 2026-06-06 14:15 UTC - cancelled - Run #27064609705 (5m 14s)
- 2026-06-06 14:20 UTC - cancelled - Run #27064723617 (5m 10s)
- 2026-06-07 05:04 UTC - cancelled - Run #27083345206 (7m 42s)
- 2026-06-07 09:44 UTC - cancelled - Run #27088980124 (6m 55s)
- 2026-06-07 09:51 UTC - cancelled - Run #27089123760 (4m 17s)
- 2026-06-07 16:25 UTC - cancelled - Run #27098172676 (2m 57s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
