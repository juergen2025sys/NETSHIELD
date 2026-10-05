# Workflow Health Dashboard

**Stand:** 2026-10-05 16:27 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 12 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 8
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-10-05 03:41 CEST (Europe/Berlin) -> 2026-10-05 07:24 CEST (Europe/Berlin) (222 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 94
- **Skip-Runs:** 54
- **Fehlgeschlagene Runs:** 0
- **Lucken >210min:** 4
- **Groesste Lucke:** 2026-10-02 03:19 CEST (Europe/Berlin) -> 2026-10-02 07:29 CEST (Europe/Berlin) (250 min = 4h 10min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 235
- **Watchdog-Fehler:** 1
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 72

Letzte Watchdog-Eingriffe:
- 2026-10-05 03:21 CEST (Europe/Berlin) (Run #37251116273, Laufzeit 19m 58s)
- 2026-10-05 07:57 CEST (Europe/Berlin) (Run #37270043680, Laufzeit 15m 19s)
- 2026-10-05 09:49 CEST (Europe/Berlin) (Run #37279897406, Laufzeit 22m 11s)
- 2026-10-05 11:33 CEST (Europe/Berlin) (Run #37290850201, Laufzeit 20m 53s)
- 2026-10-05 15:11 CEST (Europe/Berlin) (Run #37314865915, Laufzeit 20m 10s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
