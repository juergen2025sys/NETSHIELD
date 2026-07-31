# Workflow Health Report

**Stand:** 2026-07-31 09:14 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 14 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 12
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-07-30 10:04 UTC -> 2026-07-30 14:25 UTC (260 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 93
- **Skip-Runs:** 97
- **Fehlgeschlagene Runs:** 0
- **Lucken >210min:** 3
- **Groesste Lucke:** 2026-07-29 21:58 UTC -> 2026-07-30 03:16 UTC (317 min = 5h 17min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 256
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 47

Letzte Watchdog-Eingriffe:
- 2026-07-30 16:12 UTC (Run #30560376329, Laufzeit 27m 48s)
- 2026-07-30 18:45 UTC (Run #30571842401, Laufzeit 27m 59s)
- 2026-07-30 21:47 UTC (Run #30584740161, Laufzeit 27m 22s)
- 2026-07-31 01:04 UTC (Run #30595368200, Laufzeit 28m 37s)
- 2026-07-31 07:42 UTC (Run #30613747331, Laufzeit 29m 6s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
