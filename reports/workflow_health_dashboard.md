# Workflow Health Dashboard

**Stand:** 2026-11-04 00:14 CET (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 6 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 7
- **Lucken (>210min zwischen echten Runs):** 3
  - 2026-11-03 02:23 CET (Europe/Berlin) -> 2026-11-03 07:30 CET (Europe/Berlin) (307 min)
  - 2026-11-03 10:47 CET (Europe/Berlin) -> 2026-11-03 16:31 CET (Europe/Berlin) (343 min)
  - 2026-11-03 16:51 CET (Europe/Berlin) -> 2026-11-03 20:40 CET (Europe/Berlin) (228 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 59
- **Skip-Runs:** 44
- **Fehlgeschlagene Runs:** 0
- **Lucken >210min:** 10
- **Groesste Lucke:** 2026-11-03 10:47 CET (Europe/Berlin) -> 2026-11-03 16:31 CET (Europe/Berlin) (343 min = 5h 43min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 207
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 35

Letzte Watchdog-Eingriffe:
- 2026-11-02 22:55 CET (Europe/Berlin) (Run #41532752134, Laufzeit 25m 28s)
- 2026-11-03 02:05 CET (Europe/Berlin) (Run #41557428795, Laufzeit 17m 30s)
- 2026-11-03 10:28 CET (Europe/Berlin) (Run #41611243043, Laufzeit 19m 37s)
- 2026-11-03 16:31 CET (Europe/Berlin) (Run #41664777866, Laufzeit 20m 4s)
- 2026-11-03 23:27 CET (Europe/Berlin) (Run #41731026614, Laufzeit 16m 26s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
