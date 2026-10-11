# Workflow Health Dashboard

**Stand:** 2026-10-11 07:38 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 7 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 6
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 66
- **Skip-Runs:** 55
- **Fehlgeschlagene Runs:** 2
- **Lucken >210min:** 6
- **Groesste Lucke:** 2026-10-09 02:47 CEST (Europe/Berlin) -> 2026-10-09 08:00 CEST (Europe/Berlin) (312 min = 5h 12min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 214
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 52

Letzte Watchdog-Eingriffe:
- 2026-10-09 15:08 CEST (Europe/Berlin) (Run #37934752157, Laufzeit 13m 36s)
- 2026-10-09 18:26 CEST (Europe/Berlin) (Run #37959178691, Laufzeit 16m 54s)
- 2026-10-09 23:44 CEST (Europe/Berlin) (Run #37995245400, Laufzeit 12m 56s)
- 2026-10-10 18:00 CEST (Europe/Berlin) (Run #38065901955, Laufzeit 16m 6s)
- 2026-10-10 20:41 CEST (Europe/Berlin) (Run #38076762903, Laufzeit 19m 16s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-10-06 08:08 CEST (Europe/Berlin) - failure - Run #37422154292 (20m 8s)
- 2026-10-06 21:34 CEST (Europe/Berlin) - failure - Run #37519985347 (13m 50s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
