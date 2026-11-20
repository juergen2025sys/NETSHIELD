# Workflow Health Dashboard

**Stand:** 2026-11-20 21:02 CET (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 10 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 9
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-11-20 04:57 CET (Europe/Berlin) -> 2026-11-20 09:32 CET (Europe/Berlin) (274 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 57
- **Skip-Runs:** 49
- **Fehlgeschlagene Runs:** 0
- **Lucken >210min:** 11
- **Groesste Lucke:** 2026-11-17 04:59 CET (Europe/Berlin) -> 2026-11-17 10:13 CET (Europe/Berlin) (313 min = 5h 13min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 328
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 47

Letzte Watchdog-Eingriffe:
- 2026-11-20 11:29 CET (Europe/Berlin) (Run #44719643090, Laufzeit 15m 29s)
- 2026-11-20 14:01 CET (Europe/Berlin) (Run #44740674766, Laufzeit 19m 7s)
- 2026-11-20 17:10 CET (Europe/Berlin) (Run #44770647594, Laufzeit 16m 33s)
- 2026-11-20 19:42 CET (Europe/Berlin) (Run #44795354637, Laufzeit 14m 7s)
- 2026-11-20 19:57 CET (Europe/Berlin) (Run #44797570225, Laufzeit 23m 17s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
