# Workflow Health Dashboard

**Stand:** 2026-09-26 13:17 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 11 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 9
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-09-26 02:48 CEST (Europe/Berlin) -> 2026-09-26 06:46 CEST (Europe/Berlin) (237 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 73
- **Skip-Runs:** 67
- **Fehlgeschlagene Runs:** 2
- **Lucken >210min:** 7
- **Groesste Lucke:** 2026-09-23 02:10 CEST (Europe/Berlin) -> 2026-09-23 06:35 CEST (Europe/Berlin) (265 min = 4h 25min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 296
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 52

Letzte Watchdog-Eingriffe:
- 2026-09-26 02:27 CEST (Europe/Berlin) (Run #36204942012, Laufzeit 20m 25s)
- 2026-09-26 08:36 CEST (Europe/Berlin) (Run #36224273466, Laufzeit 24m 4s)
- 2026-09-26 10:34 CEST (Europe/Berlin) (Run #36230199592, Laufzeit 20m 1s)
- 2026-09-26 12:15 CEST (Europe/Berlin) (Run #36235254299, Laufzeit 17m 50s)
- 2026-09-26 12:36 CEST (Europe/Berlin) (Run #36236278773, Laufzeit 18m 27s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-09-21 02:31 CEST (Europe/Berlin) - cancelled - Run #35547981772 (5m 42s)
- 2026-09-23 19:43 CEST (Europe/Berlin) - cancelled - Run #35897617505 (2m 6s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
