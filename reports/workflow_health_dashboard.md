# Workflow Health Dashboard

**Stand:** 2026-10-16 23:00 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 8
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-10-16 14:52 CEST (Europe/Berlin) -> 2026-10-16 18:31 CEST (Europe/Berlin) (218 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 53
- **Skip-Runs:** 52
- **Fehlgeschlagene Runs:** 0
- **Lucken >210min:** 11
- **Groesste Lucke:** 2026-10-11 08:53 CEST (Europe/Berlin) -> 2026-10-11 14:37 CEST (Europe/Berlin) (344 min = 5h 44min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 240
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 29

Letzte Watchdog-Eingriffe:
- 2026-10-16 02:43 CEST (Europe/Berlin) (Run #38831115935, Laufzeit 13m 46s)
- 2026-10-16 08:40 CEST (Europe/Berlin) (Run #38862536629, Laufzeit 17m 21s)
- 2026-10-16 11:31 CEST (Europe/Berlin) (Run #38881003232, Laufzeit 18m 28s)
- 2026-10-16 14:38 CEST (Europe/Berlin) (Run #38901941255, Laufzeit 14m 2s)
- 2026-10-16 20:31 CEST (Europe/Berlin) (Run #38947989012, Laufzeit 18m 50s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
