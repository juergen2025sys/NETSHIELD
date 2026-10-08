# Workflow Health Dashboard

**Stand:** 2026-10-08 07:53 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 11 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 10
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-10-08 02:12 CEST (Europe/Berlin) -> 2026-10-08 06:12 CEST (Europe/Berlin) (240 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 82
- **Skip-Runs:** 57
- **Fehlgeschlagene Runs:** 2
- **Lucken >210min:** 6
- **Groesste Lucke:** 2026-10-02 03:19 CEST (Europe/Berlin) -> 2026-10-02 07:29 CEST (Europe/Berlin) (250 min = 4h 10min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 227
- **Watchdog-Fehler:** 1
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 67

Letzte Watchdog-Eingriffe:
- 2026-10-07 21:26 CEST (Europe/Berlin) (Run #37674498558, Laufzeit 21m 0s)
- 2026-10-07 22:55 CEST (Europe/Berlin) (Run #37685693662, Laufzeit 20m 24s)
- 2026-10-08 00:12 CEST (Europe/Berlin) (Run #37694650991, Laufzeit 21m 4s)
- 2026-10-08 01:52 CEST (Europe/Berlin) (Run #37704674560, Laufzeit 20m 34s)
- 2026-10-08 06:12 CEST (Europe/Berlin) (Run #37726402664, Laufzeit 18m 14s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-10-06 08:08 CEST (Europe/Berlin) - failure - Run #37422154292 (20m 8s)
- 2026-10-06 21:34 CEST (Europe/Berlin) - failure - Run #37519985347 (13m 50s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
