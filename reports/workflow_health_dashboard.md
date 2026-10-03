# Workflow Health Dashboard

**Stand:** 2026-10-03 07:10 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 13 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 7
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 92
- **Skip-Runs:** 56
- **Fehlgeschlagene Runs:** 1
- **Lucken >210min:** 7
- **Groesste Lucke:** 2026-09-27 08:51 CEST (Europe/Berlin) -> 2026-09-27 13:54 CEST (Europe/Berlin) (302 min = 5h 2min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 243
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 70

Letzte Watchdog-Eingriffe:
- 2026-10-02 17:45 CEST (Europe/Berlin) (Run #37029255668, Laufzeit 20m 9s)
- 2026-10-02 18:37 CEST (Europe/Berlin) (Run #37035234149, Laufzeit 21m 23s)
- 2026-10-02 20:37 CEST (Europe/Berlin) (Run #37048650338, Laufzeit 21m 23s)
- 2026-10-02 21:33 CEST (Europe/Berlin) (Run #37054919036, Laufzeit 21m 1s)
- 2026-10-02 22:12 CEST (Europe/Berlin) (Run #37059089593, Laufzeit 20m 43s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-09-26 14:28 CEST (Europe/Berlin) - cancelled - Run #36242007151 (4m 18s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
