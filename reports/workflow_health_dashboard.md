# Workflow Health Dashboard

**Stand:** 2026-09-19 12:51 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 11 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 15
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 71
- **Skip-Runs:** 75
- **Fehlgeschlagene Runs:** 4
- **Lucken >210min:** 9
- **Groesste Lucke:** 2026-09-15 02:08 CEST (Europe/Berlin) -> 2026-09-15 06:43 CEST (Europe/Berlin) (274 min = 4h 34min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 317
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 54

Letzte Watchdog-Eingriffe:
- 2026-09-18 23:52 CEST (Europe/Berlin) (Run #35398929943, Laufzeit 21m 43s)
- 2026-09-19 02:41 CEST (Europe/Berlin) (Run #35410184636, Laufzeit 21m 56s)
- 2026-09-19 08:34 CEST (Europe/Berlin) (Run #35426957881, Laufzeit 19m 54s)
- 2026-09-19 11:44 CEST (Europe/Berlin) (Run #35435507912, Laufzeit 13m 38s)
- 2026-09-19 12:17 CEST (Europe/Berlin) (Run #35436994298, Laufzeit 19m 6s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-09-17 18:50 CEST (Europe/Berlin) - cancelled - Run #35249032902 (88m 18s)
- 2026-09-17 20:26 CEST (Europe/Berlin) - cancelled - Run #35258785082 (28m 26s)
- 2026-09-18 20:39 CEST (Europe/Berlin) - cancelled - Run #35381409864 (9m 20s)
- 2026-09-19 11:44 CEST (Europe/Berlin) - failure - Run #35435507912 (13m 38s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
