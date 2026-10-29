# Workflow Health Dashboard

**Stand:** 2026-10-29 06:38 CET (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 7 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 10
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-10-28 08:25 CET (Europe/Berlin) -> 2026-10-28 12:36 CET (Europe/Berlin) (251 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 58
- **Skip-Runs:** 65
- **Fehlgeschlagene Runs:** 1
- **Lucken >210min:** 11
- **Groesste Lucke:** 2026-10-25 05:43 CET (Europe/Berlin) -> 2026-10-25 10:28 CET (Europe/Berlin) (284 min = 4h 44min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 271
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 38

Letzte Watchdog-Eingriffe:
- 2026-10-28 12:36 CET (Europe/Berlin) (Run #40681291224, Laufzeit 14m 59s)
- 2026-10-28 14:38 CET (Europe/Berlin) (Run #40698337131, Laufzeit 20m 6s)
- 2026-10-28 16:58 CET (Europe/Berlin) (Run #40721320739, Laufzeit 19m 49s)
- 2026-10-28 20:12 CET (Europe/Berlin) (Run #40752148014, Laufzeit 13m 31s)
- 2026-10-28 22:46 CET (Europe/Berlin) (Run #40774642541, Laufzeit 13m 32s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-10-26 01:43 CET (Europe/Berlin) - cancelled - Run #40250723975 (3m 10s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
