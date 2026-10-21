# Workflow Health Dashboard

**Stand:** 2026-10-21 23:34 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 8 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 9
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-10-21 02:18 CEST (Europe/Berlin) -> 2026-10-21 06:30 CEST (Europe/Berlin) (251 min)
  - 2026-10-21 08:51 CEST (Europe/Berlin) -> 2026-10-21 12:38 CEST (Europe/Berlin) (227 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 62
- **Skip-Runs:** 67
- **Fehlgeschlagene Runs:** 0
- **Lucken >210min:** 7
- **Groesste Lucke:** 2026-10-20 02:29 CEST (Europe/Berlin) -> 2026-10-20 07:12 CEST (Europe/Berlin) (283 min = 4h 43min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 302
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 38

Letzte Watchdog-Eingriffe:
- 2026-10-21 08:32 CEST (Europe/Berlin) (Run #39556072841, Laufzeit 18m 29s)
- 2026-10-21 12:38 CEST (Europe/Berlin) (Run #39586068953, Laufzeit 13m 58s)
- 2026-10-21 14:31 CEST (Europe/Berlin) (Run #39600242836, Laufzeit 19m 16s)
- 2026-10-21 17:41 CEST (Europe/Berlin) (Run #39627906782, Laufzeit 20m 1s)
- 2026-10-21 20:46 CEST (Europe/Berlin) (Run #39655726813, Laufzeit 16m 17s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
