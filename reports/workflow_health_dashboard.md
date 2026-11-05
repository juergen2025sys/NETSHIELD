# Workflow Health Dashboard

**Stand:** 2026-11-05 20:52 CET (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 8 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 6
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-11-05 07:43 CET (Europe/Berlin) -> 2026-11-05 12:17 CET (Europe/Berlin) (274 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 58
- **Skip-Runs:** 39
- **Fehlgeschlagene Runs:** 1
- **Lucken >210min:** 10
- **Groesste Lucke:** 2026-11-03 10:47 CET (Europe/Berlin) -> 2026-11-03 16:31 CET (Europe/Berlin) (343 min = 5h 43min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 199
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 34

Letzte Watchdog-Eingriffe:
- 2026-11-05 04:46 CET (Europe/Berlin) (Run #41963701687, Laufzeit 15m 48s)
- 2026-11-05 13:57 CET (Europe/Berlin) (Run #42031513145, Laufzeit 15m 54s)
- 2026-11-05 16:51 CET (Europe/Berlin) (Run #42059237139, Laufzeit 16m 18s)
- 2026-11-05 17:35 CET (Europe/Berlin) (Run #42065994681, Laufzeit 19m 32s)
- 2026-11-05 19:54 CET (Europe/Berlin) (Run #42088822171, Laufzeit 15m 27s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-11-05 16:51 CET (Europe/Berlin) - failure - Run #42059237139 (16m 18s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
