# Workflow Health Dashboard

**Stand:** 2026-10-31 22:27 CET (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 7
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-10-31 07:21 CET (Europe/Berlin) -> 2026-10-31 10:57 CET (Europe/Berlin) (216 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 60
- **Skip-Runs:** 54
- **Fehlgeschlagene Runs:** 1
- **Lucken >210min:** 11
- **Groesste Lucke:** 2026-10-30 02:07 CET (Europe/Berlin) -> 2026-10-30 07:29 CET (Europe/Berlin) (321 min = 5h 21min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 246
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 36

Letzte Watchdog-Eingriffe:
- 2026-10-30 22:39 CET (Europe/Berlin) (Run #41132662237, Laufzeit 13m 6s)
- 2026-10-31 01:56 CET (Europe/Berlin) (Run #41152843791, Laufzeit 19m 59s)
- 2026-10-31 04:51 CET (Europe/Berlin) (Run #41166113904, Laufzeit 19m 29s)
- 2026-10-31 16:02 CET (Europe/Berlin) (Run #41212941945, Laufzeit 19m 22s)
- 2026-10-31 19:47 CET (Europe/Berlin) (Run #41231121841, Laufzeit 20m 13s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-10-26 01:43 CET (Europe/Berlin) - cancelled - Run #40250723975 (3m 10s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
