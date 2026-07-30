# Workflow Health Report

**Stand:** 2026-07-30 19:45 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 13 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 13
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-07-29 21:58 UTC -> 2026-07-30 03:16 UTC (317 min)
  - 2026-07-30 10:04 UTC -> 2026-07-30 14:25 UTC (260 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 91
- **Skip-Runs:** 98
- **Fehlgeschlagene Runs:** 3
- **Lucken >210min:** 3
- **Groesste Lucke:** 2026-07-29 21:58 UTC -> 2026-07-30 03:16 UTC (317 min = 5h 17min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 257
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 47

Letzte Watchdog-Eingriffe:
- 2026-07-29 18:33 UTC (Run #30480435317, Laufzeit 22m 57s)
- 2026-07-29 21:30 UTC (Run #30492599384, Laufzeit 28m 59s)
- 2026-07-30 09:42 UTC (Run #30531779957, Laufzeit 21m 58s)
- 2026-07-30 16:12 UTC (Run #30560376329, Laufzeit 27m 48s)
- 2026-07-30 18:45 UTC (Run #30571842401, Laufzeit 27m 59s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-07-24 03:51 UTC - cancelled - Run #30065288057 (5m 52s)
- 2026-07-24 03:57 UTC - cancelled - Run #30065532941 (3m 8s)
- 2026-07-24 09:09 UTC - cancelled - Run #30081544444 (16m 49s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
