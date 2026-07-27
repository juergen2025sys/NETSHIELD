# Workflow Health Report

**Stand:** 2026-07-27 15:07 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 12 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 10
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-07-27 10:32 UTC -> 2026-07-27 14:04 UTC (212 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 85
- **Skip-Runs:** 86
- **Fehlgeschlagene Runs:** 19
- **Lucken >210min:** 1
- **Groesste Lucke:** 2026-07-27 10:32 UTC -> 2026-07-27 14:04 UTC (212 min = 3h 32min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 256
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 48

Letzte Watchdog-Eingriffe:
- 2026-07-26 18:39 UTC (Run #30215169763, Laufzeit 26m 7s)
- 2026-07-26 21:27 UTC (Run #30221103935, Laufzeit 27m 30s)
- 2026-07-27 01:15 UTC (Run #30229392176, Laufzeit 27m 59s)
- 2026-07-27 07:51 UTC (Run #30247647833, Laufzeit 22m 7s)
- 2026-07-27 14:04 UTC (Run #30273304176, Laufzeit 21m 58s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-07-22 22:31 UTC - cancelled - Run #29963169938 (8m 26s)
- 2026-07-23 01:00 UTC - cancelled - Run #29970638495 (25m 49s)
- 2026-07-23 03:51 UTC - cancelled - Run #29978057512 (7m 20s)
- 2026-07-23 03:58 UTC - cancelled - Run #29978360643 (5m 33s)
- 2026-07-23 09:04 UTC - cancelled - Run #29993795143 (4m 39s)
- 2026-07-23 11:22 UTC - cancelled - Run #30002894051 (9m 53s)
- 2026-07-23 11:32 UTC - cancelled - Run #30003522690 (12m 14s)
- 2026-07-24 03:51 UTC - cancelled - Run #30065288057 (5m 52s)
- 2026-07-24 03:57 UTC - cancelled - Run #30065532941 (3m 8s)
- 2026-07-24 09:09 UTC - cancelled - Run #30081544444 (16m 49s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
