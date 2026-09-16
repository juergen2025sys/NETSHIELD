# Workflow Health Dashboard

**Stand:** 2026-09-16 18:47 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 10 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 10
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-09-16 02:47 CEST (Europe/Berlin) -> 2026-09-16 06:39 CEST (Europe/Berlin) (231 min)
  - 2026-09-16 08:09 CEST (Europe/Berlin) -> 2026-09-16 12:01 CEST (Europe/Berlin) (231 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 69
- **Skip-Runs:** 82
- **Fehlgeschlagene Runs:** 4
- **Lucken >210min:** 9
- **Groesste Lucke:** 2026-09-15 02:08 CEST (Europe/Berlin) -> 2026-09-15 06:43 CEST (Europe/Berlin) (274 min = 4h 34min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 321
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 55

Letzte Watchdog-Eingriffe:
- 2026-09-16 02:30 CEST (Europe/Berlin) (Run #35040323732, Laufzeit 16m 30s)
- 2026-09-16 07:48 CEST (Europe/Berlin) (Run #35061022765, Laufzeit 20m 55s)
- 2026-09-16 12:01 CEST (Europe/Berlin) (Run #35082678060, Laufzeit 19m 35s)
- 2026-09-16 15:52 CEST (Europe/Berlin) (Run #35104696655, Laufzeit 19m 35s)
- 2026-09-16 16:50 CEST (Europe/Berlin) (Run #35111229125, Laufzeit 19m 33s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-09-11 08:39 CEST (Europe/Berlin) - cancelled - Run #34570885903 (4m 2s)
- 2026-09-12 10:54 CEST (Europe/Berlin) - failure - Run #34684445124 (34m 43s)
- 2026-09-12 11:30 CEST (Europe/Berlin) - cancelled - Run #34686028170 (7m 15s)
- 2026-09-12 11:38 CEST (Europe/Berlin) - failure - Run #34686370369 (1m 22s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
