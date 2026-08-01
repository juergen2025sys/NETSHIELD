# Workflow Health Report

**Stand:** 2026-08-01 08:32 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 15 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 13
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 92
- **Skip-Runs:** 97
- **Fehlgeschlagene Runs:** 1
- **Lucken >210min:** 3
- **Groesste Lucke:** 2026-07-29 21:58 UTC -> 2026-07-30 03:16 UTC (317 min = 5h 17min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 253
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 47

Letzte Watchdog-Eingriffe:
- 2026-07-31 21:30 UTC (Run #30666796709, Laufzeit 29m 0s)
- 2026-08-01 01:09 UTC (Run #30677262505, Laufzeit 28m 12s)
- 2026-08-01 03:51 UTC (Run #30682788322, Laufzeit 72m 20s)
- 2026-08-01 04:54 UTC (Run #30684814132, Laufzeit 1s)
- 2026-08-01 06:46 UTC (Run #30688287408, Laufzeit 29m 2s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-08-01 04:54 UTC - action_required - Run #30684814132 (1s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
