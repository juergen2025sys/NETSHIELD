# Workflow Health Dashboard

**Stand:** 2026-09-23 18:50 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 10
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-09-23 02:10 CEST (Europe/Berlin) -> 2026-09-23 06:35 CEST (Europe/Berlin) (265 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 68
- **Skip-Runs:** 73
- **Fehlgeschlagene Runs:** 5
- **Lucken >210min:** 8
- **Groesste Lucke:** 2026-09-17 02:12 CEST (Europe/Berlin) -> 2026-09-17 06:43 CEST (Europe/Berlin) (271 min = 4h 31min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 307
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 50

Letzte Watchdog-Eingriffe:
- 2026-09-23 08:20 CEST (Europe/Berlin) (Run #35826334829, Laufzeit 15m 16s)
- 2026-09-23 11:37 CEST (Europe/Berlin) (Run #35844003894, Laufzeit 17m 14s)
- 2026-09-23 13:35 CEST (Europe/Berlin) (Run #35855466034, Laufzeit 19m 55s)
- 2026-09-23 14:27 CEST (Europe/Berlin) (Run #35860612379, Laufzeit 20m 22s)
- 2026-09-23 17:13 CEST (Europe/Berlin) (Run #35879937324, Laufzeit 24m 52s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-09-17 18:50 CEST (Europe/Berlin) - cancelled - Run #35249032902 (88m 18s)
- 2026-09-17 20:26 CEST (Europe/Berlin) - cancelled - Run #35258785082 (28m 26s)
- 2026-09-18 20:39 CEST (Europe/Berlin) - cancelled - Run #35381409864 (9m 20s)
- 2026-09-19 11:44 CEST (Europe/Berlin) - failure - Run #35435507912 (13m 38s)
- 2026-09-21 02:31 CEST (Europe/Berlin) - cancelled - Run #35547981772 (5m 42s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
