# Workflow Health Dashboard

**Stand:** 2026-11-07 22:43 CET (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 8 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 7
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-11-07 02:10 CET (Europe/Berlin) -> 2026-11-07 06:46 CET (Europe/Berlin) (275 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 54
- **Skip-Runs:** 45
- **Fehlgeschlagene Runs:** 1
- **Lucken >210min:** 11
- **Groesste Lucke:** 2026-11-03 10:47 CET (Europe/Berlin) -> 2026-11-03 16:31 CET (Europe/Berlin) (343 min = 5h 43min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 241
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 36

Letzte Watchdog-Eingriffe:
- 2026-11-06 22:44 CET (Europe/Berlin) (Run #42299181805, Laufzeit 19m 24s)
- 2026-11-07 01:51 CET (Europe/Berlin) (Run #42320799118, Laufzeit 18m 47s)
- 2026-11-07 07:53 CET (Europe/Berlin) (Run #42348924949, Laufzeit 14m 45s)
- 2026-11-07 17:39 CET (Europe/Berlin) (Run #42392373394, Laufzeit 20m 1s)
- 2026-11-07 19:27 CET (Europe/Berlin) (Run #42401387718, Laufzeit 13m 20s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-11-05 16:51 CET (Europe/Berlin) - failure - Run #42059237139 (16m 18s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
