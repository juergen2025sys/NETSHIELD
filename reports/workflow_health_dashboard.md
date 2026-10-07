# Workflow Health Dashboard

**Stand:** 2026-10-07 15:12 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 10 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 8
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-10-07 00:05 CEST (Europe/Berlin) -> 2026-10-07 03:44 CEST (Europe/Berlin) (219 min)
  - 2026-10-07 04:03 CEST (Europe/Berlin) -> 2026-10-07 07:43 CEST (Europe/Berlin) (219 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 85
- **Skip-Runs:** 55
- **Fehlgeschlagene Runs:** 2
- **Lucken >210min:** 5
- **Groesste Lucke:** 2026-10-02 03:19 CEST (Europe/Berlin) -> 2026-10-02 07:29 CEST (Europe/Berlin) (250 min = 4h 10min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 229
- **Watchdog-Fehler:** 1
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 70

Letzte Watchdog-Eingriffe:
- 2026-10-06 21:52 CEST (Europe/Berlin) (Run #37522199416, Laufzeit 17m 35s)
- 2026-10-06 23:49 CEST (Europe/Berlin) (Run #37536572184, Laufzeit 16m 15s)
- 2026-10-07 03:44 CEST (Europe/Berlin) (Run #37558623719, Laufzeit 18m 53s)
- 2026-10-07 10:02 CEST (Europe/Berlin) (Run #37591120689, Laufzeit 20m 53s)
- 2026-10-07 11:24 CEST (Europe/Berlin) (Run #37600355020, Laufzeit 19m 17s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-10-06 08:08 CEST (Europe/Berlin) - failure - Run #37422154292 (20m 8s)
- 2026-10-06 21:34 CEST (Europe/Berlin) - failure - Run #37519985347 (13m 50s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
