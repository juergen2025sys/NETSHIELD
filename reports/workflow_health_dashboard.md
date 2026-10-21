# Workflow Health Dashboard

**Stand:** 2026-10-21 13:40 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 9
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-10-21 02:18 CEST (Europe/Berlin) -> 2026-10-21 06:30 CEST (Europe/Berlin) (251 min)
  - 2026-10-21 08:51 CEST (Europe/Berlin) -> 2026-10-21 12:38 CEST (Europe/Berlin) (227 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 63
- **Skip-Runs:** 66
- **Fehlgeschlagene Runs:** 0
- **Lucken >210min:** 7
- **Groesste Lucke:** 2026-10-20 02:29 CEST (Europe/Berlin) -> 2026-10-20 07:12 CEST (Europe/Berlin) (283 min = 4h 43min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 301
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 37

Letzte Watchdog-Eingriffe:
- 2026-10-20 14:59 CEST (Europe/Berlin) (Run #39426603918, Laufzeit 19m 49s)
- 2026-10-20 17:17 CEST (Europe/Berlin) (Run #39447108719, Laufzeit 18m 49s)
- 2026-10-20 21:30 CEST (Europe/Berlin) (Run #39484113808, Laufzeit 16m 8s)
- 2026-10-21 08:32 CEST (Europe/Berlin) (Run #39556072841, Laufzeit 18m 29s)
- 2026-10-21 12:38 CEST (Europe/Berlin) (Run #39586068953, Laufzeit 13m 58s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
