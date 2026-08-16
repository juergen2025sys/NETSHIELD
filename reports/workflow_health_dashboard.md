# Workflow Health Dashboard

**Stand:** 2026-08-16 08:55 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 10 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 20
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 78
- **Skip-Runs:** 135
- **Fehlgeschlagene Runs:** 16
- **Lucken >210min:** 4
- **Groesste Lucke:** 2026-08-13 00:17 CEST (Europe/Berlin) -> 2026-08-13 04:37 CEST (Europe/Berlin) (260 min = 4h 20min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 526
- **Watchdog-Fehler:** 1
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 61

Letzte Watchdog-Eingriffe:
- 2026-08-15 23:53 CEST (Europe/Berlin) (Run #31910681421, Laufzeit 64m 40s)
- 2026-08-16 02:16 CEST (Europe/Berlin) (Run #31916806609, Laufzeit 18m 49s)
- 2026-08-16 02:57 CEST (Europe/Berlin) (Run #31918436179, Laufzeit 25m 7s)
- 2026-08-16 05:50 CEST (Europe/Berlin) (Run #31925208669, Laufzeit 18m 29s)
- 2026-08-16 08:44 CEST (Europe/Berlin) (Run #31932126288, Laufzeit 13s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-08-10 18:05 CEST (Europe/Berlin) - action_required - Run #31407080526 (0s)
- 2026-08-12 05:10 CEST (Europe/Berlin) - failure - Run #31559262855 (10s)
- 2026-08-13 13:36 CEST (Europe/Berlin) - cancelled - Run #31696234312 (95m 18s)
- 2026-08-13 20:30 CEST (Europe/Berlin) - cancelled - Run #31731085374 (8m 7s)
- 2026-08-15 08:27 CEST (Europe/Berlin) - failure - Run #31869475966 (21m 45s)
- 2026-08-15 17:37 CEST (Europe/Berlin) - failure - Run #31893259272 (21m 34s)
- 2026-08-15 19:35 CEST (Europe/Berlin) - cancelled - Run #31898703429 (40m 20s)
- 2026-08-15 23:28 CEST (Europe/Berlin) - failure - Run #31909546443 (24m 11s)
- 2026-08-16 03:51 CEST (Europe/Berlin) - action_required - Run #31920533372 (0s)
- 2026-08-16 04:03 CEST (Europe/Berlin) - action_required - Run #31920993786 (0s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
