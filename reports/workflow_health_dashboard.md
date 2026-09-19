# Workflow Health Dashboard

**Stand:** 2026-09-19 06:31 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 10 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 14
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 70
- **Skip-Runs:** 75
- **Fehlgeschlagene Runs:** 6
- **Lucken >210min:** 9
- **Groesste Lucke:** 2026-09-15 02:08 CEST (Europe/Berlin) -> 2026-09-15 06:43 CEST (Europe/Berlin) (274 min = 4h 34min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 317
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 56

Letzte Watchdog-Eingriffe:
- 2026-09-18 20:39 CEST (Europe/Berlin) (Run #35381409864, Laufzeit 9m 20s)
- 2026-09-18 20:49 CEST (Europe/Berlin) (Run #35382385678, Laufzeit 19m 41s)
- 2026-09-18 21:51 CEST (Europe/Berlin) (Run #35388297046, Laufzeit 16m 31s)
- 2026-09-18 23:52 CEST (Europe/Berlin) (Run #35398929943, Laufzeit 21m 43s)
- 2026-09-19 02:41 CEST (Europe/Berlin) (Run #35410184636, Laufzeit 21m 56s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-09-12 10:54 CEST (Europe/Berlin) - failure - Run #34684445124 (34m 43s)
- 2026-09-12 11:30 CEST (Europe/Berlin) - cancelled - Run #34686028170 (7m 15s)
- 2026-09-12 11:38 CEST (Europe/Berlin) - failure - Run #34686370369 (1m 22s)
- 2026-09-17 18:50 CEST (Europe/Berlin) - cancelled - Run #35249032902 (88m 18s)
- 2026-09-17 20:26 CEST (Europe/Berlin) - cancelled - Run #35258785082 (28m 26s)
- 2026-09-18 20:39 CEST (Europe/Berlin) - cancelled - Run #35381409864 (9m 20s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
