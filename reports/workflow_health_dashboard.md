# Workflow Health Dashboard

**Stand:** 2026-09-25 23:30 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 7
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 71
- **Skip-Runs:** 69
- **Fehlgeschlagene Runs:** 3
- **Lucken >210min:** 6
- **Groesste Lucke:** 2026-09-23 02:10 CEST (Europe/Berlin) -> 2026-09-23 06:35 CEST (Europe/Berlin) (265 min = 4h 25min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 299
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 52

Letzte Watchdog-Eingriffe:
- 2026-09-25 02:56 CEST (Europe/Berlin) (Run #36079792717, Laufzeit 20m 40s)
- 2026-09-25 08:17 CEST (Europe/Berlin) (Run #36102214397, Laufzeit 20m 8s)
- 2026-09-25 10:16 CEST (Europe/Berlin) (Run #36112015758, Laufzeit 17m 9s)
- 2026-09-25 16:06 CEST (Europe/Berlin) (Run #36145253449, Laufzeit 20m 20s)
- 2026-09-25 20:50 CEST (Europe/Berlin) (Run #36176011316, Laufzeit 20m 21s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-09-19 11:44 CEST (Europe/Berlin) - failure - Run #35435507912 (13m 38s)
- 2026-09-21 02:31 CEST (Europe/Berlin) - cancelled - Run #35547981772 (5m 42s)
- 2026-09-23 19:43 CEST (Europe/Berlin) - cancelled - Run #35897617505 (2m 6s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
