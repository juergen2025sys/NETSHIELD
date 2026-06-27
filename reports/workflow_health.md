# Workflow Health Report

**Stand:** 2026-06-27 19:41 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 6 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 17
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-06-26 22:10 UTC -> 2026-06-27 04:11 UTC (360 min)
  - 2026-06-27 13:10 UTC -> 2026-06-27 18:22 UTC (311 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 65
- **Skip-Runs:** 81
- **Fehlgeschlagene Runs:** 20
- **Lucken >210min:** 10
- **Groesste Lucke:** 2026-06-26 22:10 UTC -> 2026-06-27 04:11 UTC (360 min = 6h 0min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 191
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 43

Letzte Watchdog-Eingriffe:
- 2026-06-27 15:44 UTC (Run #28293899076, Laufzeit 21m 32s)
- 2026-06-27 17:16 UTC (Run #28296218861, Laufzeit 21m 42s)
- 2026-06-27 17:44 UTC (Run #28296920740, Laufzeit 25m 10s)
- 2026-06-27 18:19 UTC (Run #28297742919, Laufzeit 5m 39s)
- 2026-06-27 18:22 UTC (Run #28297825561, Laufzeit 25m 36s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-06-26 09:56 UTC - cancelled - Run #28230898725 (4m 27s)
- 2026-06-26 10:01 UTC - cancelled - Run #28231115831 (8m 33s)
- 2026-06-27 04:31 UTC - cancelled - Run #28278659543 (3m 5s)
- 2026-06-27 15:44 UTC - failure - Run #28293899076 (21m 32s)
- 2026-06-27 16:15 UTC - failure - Run #28294685528 (20m 44s)
- 2026-06-27 16:36 UTC - failure - Run #28295213067 (21m 55s)
- 2026-06-27 16:47 UTC - cancelled - Run #28295493653 (29m 13s)
- 2026-06-27 17:16 UTC - failure - Run #28296218861 (21m 42s)
- 2026-06-27 17:44 UTC - failure - Run #28296920740 (25m 10s)
- 2026-06-27 18:19 UTC - cancelled - Run #28297742919 (5m 39s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
