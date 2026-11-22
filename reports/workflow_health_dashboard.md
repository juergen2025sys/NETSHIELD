# Workflow Health Dashboard

**Stand:** 2026-11-22 20:29 CET (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 7 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 7
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-11-22 01:52 CET (Europe/Berlin) -> 2026-11-22 08:34 CET (Europe/Berlin) (401 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 58
- **Skip-Runs:** 46
- **Fehlgeschlagene Runs:** 1
- **Lucken >210min:** 10
- **Groesste Lucke:** 2026-11-22 01:52 CET (Europe/Berlin) -> 2026-11-22 08:34 CET (Europe/Berlin) (401 min = 6h 41min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 283
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 48

Letzte Watchdog-Eingriffe:
- 2026-11-22 01:33 CET (Europe/Berlin) (Run #44967190741, Laufzeit 19m 30s)
- 2026-11-22 08:34 CET (Europe/Berlin) (Run #44998868357, Laufzeit 16m 17s)
- 2026-11-22 10:32 CET (Europe/Berlin) (Run #45008014911, Laufzeit 17m 18s)
- 2026-11-22 13:56 CET (Europe/Berlin) (Run #45024879502, Laufzeit 14m 37s)
- 2026-11-22 16:39 CET (Europe/Berlin) (Run #45039523843, Laufzeit 19m 11s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-11-21 11:52 CET (Europe/Berlin) - cancelled - Run #44896391381 (2m 3s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
