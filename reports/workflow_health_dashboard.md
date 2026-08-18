# Workflow Health Dashboard

**Stand:** 2026-08-18 09:00 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 8 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 22
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 68
- **Skip-Runs:** 150
- **Fehlgeschlagene Runs:** 12
- **Lucken >210min:** 4
- **Groesste Lucke:** 2026-08-13 00:17 CEST (Europe/Berlin) -> 2026-08-13 04:37 CEST (Europe/Berlin) (260 min = 4h 20min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 617
- **Watchdog-Fehler:** 1
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 62

Letzte Watchdog-Eingriffe:
- 2026-08-17 15:12 CEST (Europe/Berlin) (Run #32033784337, Laufzeit 20m 52s)
- 2026-08-17 20:38 CEST (Europe/Berlin) (Run #32055915410, Laufzeit 20m 10s)
- 2026-08-17 23:32 CEST (Europe/Berlin) (Run #32071637630, Laufzeit 16m 59s)
- 2026-08-18 02:34 CEST (Europe/Berlin) (Run #32085005004, Laufzeit 16m 40s)
- 2026-08-18 08:54 CEST (Europe/Berlin) (Run #32108969072, Laufzeit 12s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-08-13 20:30 CEST (Europe/Berlin) - cancelled - Run #31731085374 (8m 7s)
- 2026-08-15 08:27 CEST (Europe/Berlin) - failure - Run #31869475966 (21m 45s)
- 2026-08-15 17:37 CEST (Europe/Berlin) - failure - Run #31893259272 (21m 34s)
- 2026-08-15 19:35 CEST (Europe/Berlin) - cancelled - Run #31898703429 (40m 20s)
- 2026-08-15 23:28 CEST (Europe/Berlin) - failure - Run #31909546443 (24m 11s)
- 2026-08-16 03:51 CEST (Europe/Berlin) - action_required - Run #31920533372 (0s)
- 2026-08-16 04:03 CEST (Europe/Berlin) - action_required - Run #31920993786 (0s)
- 2026-08-16 19:36 CEST (Europe/Berlin) - failure - Run #31962089791 (3m 41s)
- 2026-08-16 19:43 CEST (Europe/Berlin) - cancelled - Run #31962436032 (3m 38s)
- 2026-08-16 19:47 CEST (Europe/Berlin) - cancelled - Run #31962640642 (40s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
