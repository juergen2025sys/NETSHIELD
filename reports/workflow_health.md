# Workflow Health Report

**Stand:** 2026-06-29 16:05 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 7 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 13
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-06-28 21:59 UTC -> 2026-06-29 02:05 UTC (245 min)
  - 2026-06-29 10:34 UTC -> 2026-06-29 14:34 UTC (240 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 67
- **Skip-Runs:** 84
- **Fehlgeschlagene Runs:** 21
- **Lucken >210min:** 9
- **Groesste Lucke:** 2026-06-26 22:10 UTC -> 2026-06-27 04:11 UTC (360 min = 6h 0min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 198
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 49

Letzte Watchdog-Eingriffe:
- 2026-06-28 21:33 UTC (Run #28336720530, Laufzeit 25m 37s)
- 2026-06-29 02:05 UTC (Run #28344130483, Laufzeit 25m 55s)
- 2026-06-29 07:02 UTC (Run #28354509663, Laufzeit 26m 49s)
- 2026-06-29 10:08 UTC (Run #28364456519, Laufzeit 26m 20s)
- 2026-06-29 14:34 UTC (Run #28379846103, Laufzeit 26m 9s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-06-27 17:44 UTC - failure - Run #28296920740 (25m 10s)
- 2026-06-27 18:19 UTC - cancelled - Run #28297742919 (5m 39s)
- 2026-06-27 22:33 UTC - cancelled - Run #28303855597 (36s)
- 2026-06-28 04:45 UTC - cancelled - Run #28311663257 (12m 26s)
- 2026-06-28 09:26 UTC - cancelled - Run #28317847750 (4m 50s)
- 2026-06-28 09:39 UTC - cancelled - Run #28318150687 (8m 2s)
- 2026-06-28 09:47 UTC - cancelled - Run #28318337571 (9m 15s)
- 2026-06-28 14:08 UTC - cancelled - Run #28324832167 (13m 1s)
- 2026-06-29 05:09 UTC - cancelled - Run #28350009143 (9m 4s)
- 2026-06-29 05:18 UTC - cancelled - Run #28350351710 (1m 52s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
