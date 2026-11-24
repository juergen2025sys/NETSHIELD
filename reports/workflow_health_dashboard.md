# Workflow Health Dashboard

**Stand:** 2026-11-24 23:19 CET (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 8 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 6
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-11-24 07:46 CET (Europe/Berlin) -> 2026-11-24 11:56 CET (Europe/Berlin) (250 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 61
- **Skip-Runs:** 47
- **Fehlgeschlagene Runs:** 1
- **Lucken >210min:** 8
- **Groesste Lucke:** 2026-11-22 01:52 CET (Europe/Berlin) -> 2026-11-22 08:34 CET (Europe/Berlin) (401 min = 6h 41min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 276
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 52

Letzte Watchdog-Eingriffe:
- 2026-11-24 11:56 CET (Europe/Berlin) (Run #45379542534, Laufzeit 15m 16s)
- 2026-11-24 13:50 CET (Europe/Berlin) (Run #45397495308, Laufzeit 15m 52s)
- 2026-11-24 17:22 CET (Europe/Berlin) (Run #45436282440, Laufzeit 20m 3s)
- 2026-11-24 19:55 CET (Europe/Berlin) (Run #45464678095, Laufzeit 19m 42s)
- 2026-11-24 22:38 CET (Europe/Berlin) (Run #45493191744, Laufzeit 19m 9s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-11-21 11:52 CET (Europe/Berlin) - cancelled - Run #44896391381 (2m 3s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
