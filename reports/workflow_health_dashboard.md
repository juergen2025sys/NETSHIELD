# Workflow Health Dashboard

**Stand:** 2026-10-29 13:52 CET (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 8 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 9
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-10-29 02:04 CET (Europe/Berlin) -> 2026-10-29 06:44 CET (Europe/Berlin) (279 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 58
- **Skip-Runs:** 64
- **Fehlgeschlagene Runs:** 1
- **Lucken >210min:** 11
- **Groesste Lucke:** 2026-10-25 05:43 CET (Europe/Berlin) -> 2026-10-25 10:28 CET (Europe/Berlin) (284 min = 4h 44min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 270
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 37

Letzte Watchdog-Eingriffe:
- 2026-10-28 16:58 CET (Europe/Berlin) (Run #40721320739, Laufzeit 19m 49s)
- 2026-10-28 20:12 CET (Europe/Berlin) (Run #40752148014, Laufzeit 13m 31s)
- 2026-10-28 22:46 CET (Europe/Berlin) (Run #40774642541, Laufzeit 13m 32s)
- 2026-10-29 06:44 CET (Europe/Berlin) (Run #40825079038, Laufzeit 13m 58s)
- 2026-10-29 07:59 CET (Europe/Berlin) (Run #40832582019, Laufzeit 19m 38s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-10-26 01:43 CET (Europe/Berlin) - cancelled - Run #40250723975 (3m 10s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
