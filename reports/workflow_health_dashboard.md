# Workflow Health Dashboard

**Stand:** 2026-11-03 01:54 CET (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 8 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 4
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-11-02 13:50 CET (Europe/Berlin) -> 2026-11-02 18:31 CET (Europe/Berlin) (281 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 60
- **Skip-Runs:** 44
- **Fehlgeschlagene Runs:** 0
- **Lucken >210min:** 8
- **Groesste Lucke:** 2026-11-01 01:20 CET (Europe/Berlin) -> 2026-11-01 06:49 CET (Europe/Berlin) (328 min = 5h 28min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 215
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 36

Letzte Watchdog-Eingriffe:
- 2026-11-02 11:11 CET (Europe/Berlin) (Run #41426785382, Laufzeit 19m 56s)
- 2026-11-02 13:32 CET (Europe/Berlin) (Run #41445510775, Laufzeit 17m 55s)
- 2026-11-02 18:31 CET (Europe/Berlin) (Run #41492010815, Laufzeit 14m 27s)
- 2026-11-02 19:43 CET (Europe/Berlin) (Run #41503220873, Laufzeit 16m 43s)
- 2026-11-02 22:55 CET (Europe/Berlin) (Run #41532752134, Laufzeit 25m 28s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
