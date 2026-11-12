# Workflow Health Dashboard

**Stand:** 2026-11-12 16:03 CET (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 5
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-11-12 05:04 CET (Europe/Berlin) -> 2026-11-12 09:19 CET (Europe/Berlin) (254 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 55
- **Skip-Runs:** 43
- **Fehlgeschlagene Runs:** 1
- **Lucken >210min:** 11
- **Groesste Lucke:** 2026-11-08 01:44 CET (Europe/Berlin) -> 2026-11-08 07:25 CET (Europe/Berlin) (341 min = 5h 41min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 391
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 35

Letzte Watchdog-Eingriffe:
- 2026-11-11 16:12 CET (Europe/Berlin) (Run #43045973079, Laufzeit 15m 44s)
- 2026-11-11 23:19 CET (Europe/Berlin) (Run #43110764056, Laufzeit 19m 37s)
- 2026-11-12 04:45 CET (Europe/Berlin) (Run #43150270712, Laufzeit 19m 40s)
- 2026-11-12 09:19 CET (Europe/Berlin) (Run #43182007626, Laufzeit 19m 27s)
- 2026-11-12 13:28 CET (Europe/Berlin) (Run #43218257378, Laufzeit 18m 51s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-11-05 16:51 CET (Europe/Berlin) - failure - Run #42059237139 (16m 18s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
