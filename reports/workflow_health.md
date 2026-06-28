# Workflow Health Report

**Stand:** 2026-06-28 19:42 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 12 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 9
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 67
- **Skip-Runs:** 82
- **Fehlgeschlagene Runs:** 21
- **Lucken >210min:** 10
- **Groesste Lucke:** 2026-06-26 22:10 UTC -> 2026-06-27 04:11 UTC (360 min = 6h 0min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 195
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 47

Letzte Watchdog-Eingriffe:
- 2026-06-28 06:43 UTC (Run #28314142399, Laufzeit 22m 52s)
- 2026-06-28 10:12 UTC (Run #28318918116, Laufzeit 24m 22s)
- 2026-06-28 12:50 UTC (Run #28322785482, Laufzeit 27m 22s)
- 2026-06-28 15:48 UTC (Run #28327569591, Laufzeit 25m 53s)
- 2026-06-28 19:07 UTC (Run #28332867476, Laufzeit 26m 4s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-06-27 16:47 UTC - cancelled - Run #28295493653 (29m 13s)
- 2026-06-27 17:16 UTC - failure - Run #28296218861 (21m 42s)
- 2026-06-27 17:44 UTC - failure - Run #28296920740 (25m 10s)
- 2026-06-27 18:19 UTC - cancelled - Run #28297742919 (5m 39s)
- 2026-06-27 22:33 UTC - cancelled - Run #28303855597 (36s)
- 2026-06-28 04:45 UTC - cancelled - Run #28311663257 (12m 26s)
- 2026-06-28 09:26 UTC - cancelled - Run #28317847750 (4m 50s)
- 2026-06-28 09:39 UTC - cancelled - Run #28318150687 (8m 2s)
- 2026-06-28 09:47 UTC - cancelled - Run #28318337571 (9m 15s)
- 2026-06-28 14:08 UTC - cancelled - Run #28324832167 (13m 1s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
