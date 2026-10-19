# Workflow Health Dashboard

**Stand:** 2026-10-19 06:30 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 10
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 59
- **Skip-Runs:** 60
- **Fehlgeschlagene Runs:** 0
- **Lucken >210min:** 7
- **Groesste Lucke:** 2026-10-12 12:09 CEST (Europe/Berlin) -> 2026-10-12 17:53 CEST (Europe/Berlin) (344 min = 5h 44min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 280
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 34

Letzte Watchdog-Eingriffe:
- 2026-10-18 08:43 CEST (Europe/Berlin) (Run #39105074526, Laufzeit 13m 41s)
- 2026-10-18 11:43 CEST (Europe/Berlin) (Run #39116492963, Laufzeit 19m 27s)
- 2026-10-18 15:22 CEST (Europe/Berlin) (Run #39131272416, Laufzeit 13m 51s)
- 2026-10-18 21:02 CEST (Europe/Berlin) (Run #39156895967, Laufzeit 18m 58s)
- 2026-10-19 02:31 CEST (Europe/Berlin) (Run #39181179365, Laufzeit 20m 55s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
