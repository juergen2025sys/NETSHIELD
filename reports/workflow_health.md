# Workflow Health Report

**Stand:** 2026-06-24 04:20 UTC
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_report.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 10 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 11
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-06-23 04:40 UTC -> 2026-06-23 08:42 UTC (242 min)
  - 2026-06-23 10:03 UTC -> 2026-06-23 13:47 UTC (224 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 67
- **Skip-Runs:** 62
- **Fehlgeschlagene Runs:** 19
- **Lucken >210min:** 11
- **Groesste Lucke:** 2026-06-22 12:43 UTC -> 2026-06-22 17:19 UTC (275 min = 4h 35min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 173
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 38

Letzte Watchdog-Eingriffe:
- 2026-06-23 13:47 UTC (Run #28030991733, Laufzeit 21m 22s)
- 2026-06-23 15:28 UTC (Run #28037048724, Laufzeit 21m 11s)
- 2026-06-23 19:20 UTC (Run #28050968202, Laufzeit 13m 50s)
- 2026-06-23 21:51 UTC (Run #28059542423, Laufzeit 22m 30s)
- 2026-06-24 01:25 UTC (Run #28068718388, Laufzeit 21m 46s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-06-20 09:52 UTC - cancelled - Run #27867575286 (3m 50s)
- 2026-06-20 16:59 UTC - cancelled - Run #27877877927 (10s)
- 2026-06-20 22:39 UTC - cancelled - Run #27886052818 (32s)
- 2026-06-21 05:23 UTC - cancelled - Run #27894618936 (6m 28s)
- 2026-06-21 05:30 UTC - cancelled - Run #27894749132 (23s)
- 2026-06-21 10:08 UTC - cancelled - Run #27901008331 (12m 44s)
- 2026-06-21 10:21 UTC - cancelled - Run #27901299194 (2m 4s)
- 2026-06-22 05:39 UTC - cancelled - Run #27932008625 (4m 31s)
- 2026-06-22 12:29 UTC - cancelled - Run #27952708468 (8m 0s)
- 2026-06-23 15:29 UTC - cancelled - Run #28037108035 (9m 15s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
