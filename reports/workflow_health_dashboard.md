# Workflow Health Dashboard

**Stand:** 2026-10-20 18:54 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 10
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-10-20 02:29 CEST (Europe/Berlin) -> 2026-10-20 07:12 CEST (Europe/Berlin) (283 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 62
- **Skip-Runs:** 66
- **Fehlgeschlagene Runs:** 0
- **Lucken >210min:** 6
- **Groesste Lucke:** 2026-10-20 02:29 CEST (Europe/Berlin) -> 2026-10-20 07:12 CEST (Europe/Berlin) (283 min = 4h 43min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 297
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 37

Letzte Watchdog-Eingriffe:
- 2026-10-20 07:12 CEST (Europe/Berlin) (Run #39373654864, Laufzeit 13m 22s)
- 2026-10-20 08:34 CEST (Europe/Berlin) (Run #39381148596, Laufzeit 19m 19s)
- 2026-10-20 12:18 CEST (Europe/Berlin) (Run #39406989878, Laufzeit 19m 22s)
- 2026-10-20 14:59 CEST (Europe/Berlin) (Run #39426603918, Laufzeit 19m 49s)
- 2026-10-20 17:17 CEST (Europe/Berlin) (Run #39447108719, Laufzeit 18m 49s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
