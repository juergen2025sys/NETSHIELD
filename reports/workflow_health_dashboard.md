# Workflow Health Dashboard

**Stand:** 2026-10-04 23:16 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 12 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 9
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 92
- **Skip-Runs:** 54
- **Fehlgeschlagene Runs:** 0
- **Lucken >210min:** 5
- **Groesste Lucke:** 2026-09-28 02:19 CEST (Europe/Berlin) -> 2026-09-28 07:11 CEST (Europe/Berlin) (292 min = 4h 52min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 236
- **Watchdog-Fehler:** 1
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 69

Letzte Watchdog-Eingriffe:
- 2026-10-04 14:49 CEST (Europe/Berlin) (Run #37203420858, Laufzeit 20m 50s)
- 2026-10-04 17:01 CEST (Europe/Berlin) (Run #37211420458, Laufzeit 16m 33s)
- 2026-10-04 17:29 CEST (Europe/Berlin) (Run #37213205649, Laufzeit 15m 58s)
- 2026-10-04 19:10 CEST (Europe/Berlin) (Run #37219476892, Laufzeit 20m 11s)
- 2026-10-04 20:27 CEST (Europe/Berlin) (Run #37224484258, Laufzeit 19m 35s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
