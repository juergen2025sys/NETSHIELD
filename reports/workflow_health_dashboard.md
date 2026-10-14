# Workflow Health Dashboard

**Stand:** 2026-10-14 23:36 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 7 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 9
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-10-14 02:44 CEST (Europe/Berlin) -> 2026-10-14 06:42 CEST (Europe/Berlin) (237 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 51
- **Skip-Runs:** 51
- **Fehlgeschlagene Runs:** 0
- **Lucken >210min:** 11
- **Groesste Lucke:** 2026-10-11 08:53 CEST (Europe/Berlin) -> 2026-10-11 14:37 CEST (Europe/Berlin) (344 min = 5h 44min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 215
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 32

Letzte Watchdog-Eingriffe:
- 2026-10-13 23:31 CEST (Europe/Berlin) (Run #38471285852, Laufzeit 19m 4s)
- 2026-10-14 09:56 CEST (Europe/Berlin) (Run #38531630987, Laufzeit 19m 54s)
- 2026-10-14 11:50 CEST (Europe/Berlin) (Run #38545265353, Laufzeit 17m 35s)
- 2026-10-14 17:36 CEST (Europe/Berlin) (Run #38590885461, Laufzeit 19m 8s)
- 2026-10-14 20:48 CEST (Europe/Berlin) (Run #38618232927, Laufzeit 18m 45s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
