# Workflow Health Dashboard

**Stand:** 2026-10-18 06:21 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 8 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 12
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 56
- **Skip-Runs:** 59
- **Fehlgeschlagene Runs:** 0
- **Lucken >210min:** 9
- **Groesste Lucke:** 2026-10-11 08:53 CEST (Europe/Berlin) -> 2026-10-11 14:37 CEST (Europe/Berlin) (344 min = 5h 44min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 262
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 33

Letzte Watchdog-Eingriffe:
- 2026-10-17 11:36 CEST (Europe/Berlin) (Run #39021784748, Laufzeit 18m 24s)
- 2026-10-17 14:29 CEST (Europe/Berlin) (Run #39032704771, Laufzeit 16m 47s)
- 2026-10-17 20:28 CEST (Europe/Berlin) (Run #39058240893, Laufzeit 19m 7s)
- 2026-10-17 23:47 CEST (Europe/Berlin) (Run #39072415217, Laufzeit 22m 32s)
- 2026-10-18 02:58 CEST (Europe/Berlin) (Run #39084730682, Laufzeit 13m 24s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
