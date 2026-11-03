# Workflow Health Dashboard

**Stand:** 2026-11-03 15:02 CET (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 7 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 6
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-11-03 02:23 CET (Europe/Berlin) -> 2026-11-03 07:30 CET (Europe/Berlin) (307 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 59
- **Skip-Runs:** 46
- **Fehlgeschlagene Runs:** 0
- **Lucken >210min:** 8
- **Groesste Lucke:** 2026-11-01 01:20 CET (Europe/Berlin) -> 2026-11-01 06:49 CET (Europe/Berlin) (328 min = 5h 28min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 211
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 35

Letzte Watchdog-Eingriffe:
- 2026-11-02 18:31 CET (Europe/Berlin) (Run #41492010815, Laufzeit 14m 27s)
- 2026-11-02 19:43 CET (Europe/Berlin) (Run #41503220873, Laufzeit 16m 43s)
- 2026-11-02 22:55 CET (Europe/Berlin) (Run #41532752134, Laufzeit 25m 28s)
- 2026-11-03 02:05 CET (Europe/Berlin) (Run #41557428795, Laufzeit 17m 30s)
- 2026-11-03 10:28 CET (Europe/Berlin) (Run #41611243043, Laufzeit 19m 37s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
