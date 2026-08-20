# Workflow Health Dashboard

**Stand:** 2026-08-20 20:55 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 24
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 69
- **Skip-Runs:** 154
- **Fehlgeschlagene Runs:** 9
- **Lucken >210min:** 1
- **Groesste Lucke:** 2026-08-19 06:13 CEST (Europe/Berlin) -> 2026-08-19 17:02 CEST (Europe/Berlin) (649 min = 10h 49min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 724
- **Watchdog-Fehler:** 1
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 64

Letzte Watchdog-Eingriffe:
- 2026-08-20 11:29 CEST (Europe/Berlin) (Run #32354167811, Laufzeit 18m 34s)
- 2026-08-20 14:49 CEST (Europe/Berlin) (Run #32370862384, Laufzeit 20m 34s)
- 2026-08-20 17:45 CEST (Europe/Berlin) (Run #32388065966, Laufzeit 46m 36s)
- 2026-08-20 17:51 CEST (Europe/Berlin) (Run #32388653403, Laufzeit 62m 4s)
- 2026-08-20 20:32 CEST (Europe/Berlin) (Run #32403803021, Laufzeit 21m 36s)

## Fehlgeschlagene Combined-Runs (7d)

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
