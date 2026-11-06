# Workflow Health Dashboard

**Stand:** 2026-11-06 20:17 CET (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 7 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 7
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-11-06 01:43 CET (Europe/Berlin) -> 2026-11-06 07:22 CET (Europe/Berlin) (339 min)
  - 2026-11-06 11:10 CET (Europe/Berlin) -> 2026-11-06 16:16 CET (Europe/Berlin) (306 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 57
- **Skip-Runs:** 43
- **Fehlgeschlagene Runs:** 1
- **Lucken >210min:** 11
- **Groesste Lucke:** 2026-11-03 10:47 CET (Europe/Berlin) -> 2026-11-03 16:31 CET (Europe/Berlin) (343 min = 5h 43min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 200
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 37

Letzte Watchdog-Eingriffe:
- 2026-11-05 22:28 CET (Europe/Berlin) (Run #42112993749, Laufzeit 19m 31s)
- 2026-11-06 01:29 CET (Europe/Berlin) (Run #42137142687, Laufzeit 14m 0s)
- 2026-11-06 10:50 CET (Europe/Berlin) (Run #42198032118, Laufzeit 19m 53s)
- 2026-11-06 16:16 CET (Europe/Berlin) (Run #42241459892, Laufzeit 20m 33s)
- 2026-11-06 19:30 CET (Europe/Berlin) (Run #42271264334, Laufzeit 13m 59s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-11-05 16:51 CET (Europe/Berlin) - failure - Run #42059237139 (16m 18s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
