# Workflow Health Dashboard

**Stand:** 2026-09-05 17:06 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 12
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-09-05 06:27 CEST (Europe/Berlin) -> 2026-09-05 10:26 CEST (Europe/Berlin) (238 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 65
- **Skip-Runs:** 76
- **Fehlgeschlagene Runs:** 6
- **Lucken >210min:** 6
- **Groesste Lucke:** 2026-08-31 02:47 CEST (Europe/Berlin) -> 2026-08-31 07:20 CEST (Europe/Berlin) (272 min = 4h 32min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 222
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 49

Letzte Watchdog-Eingriffe:
- 2026-09-05 00:00 CEST (Europe/Berlin) (Run #33923614529, Laufzeit 18m 24s)
- 2026-09-05 02:37 CEST (Europe/Berlin) (Run #33933612885, Laufzeit 13m 17s)
- 2026-09-05 10:26 CEST (Europe/Berlin) (Run #33955264092, Laufzeit 20m 36s)
- 2026-09-05 11:28 CEST (Europe/Berlin) (Run #33958091785, Laufzeit 19m 9s)
- 2026-09-05 15:03 CEST (Europe/Berlin) (Run #33967787197, Laufzeit 20m 16s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-08-31 22:53 CEST (Europe/Berlin) - cancelled - Run #33438466768 (6m 40s)
- 2026-08-31 23:05 CEST (Europe/Berlin) - cancelled - Run #33439515318 (9m 45s)
- 2026-09-01 20:22 CEST (Europe/Berlin) - cancelled - Run #33543228443 (17m 24s)
- 2026-09-02 18:28 CEST (Europe/Berlin) - action_required - Run #33655138414 (0s)
- 2026-09-03 20:53 CEST (Europe/Berlin) - cancelled - Run #33793182301 (8m 11s)
- 2026-09-04 15:51 CEST (Europe/Berlin) - cancelled - Run #33880368309 (2m 13s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
