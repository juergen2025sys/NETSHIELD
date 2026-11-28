# Workflow Health Dashboard

**Stand:** 2026-11-28 08:37 CET (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 5
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 60
- **Skip-Runs:** 40
- **Fehlgeschlagene Runs:** 2
- **Lucken >210min:** 7
- **Groesste Lucke:** 2026-11-22 01:52 CET (Europe/Berlin) -> 2026-11-22 08:34 CET (Europe/Berlin) (401 min = 6h 41min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 262
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 49

Letzte Watchdog-Eingriffe:
- 2026-11-27 17:46 CET (Europe/Berlin) (Run #46036469087, Laufzeit 20m 21s)
- 2026-11-27 18:22 CET (Europe/Berlin) (Run #46041374014, Laufzeit 19m 49s)
- 2026-11-27 20:14 CET (Europe/Berlin) (Run #46055305979, Laufzeit 15m 8s)
- 2026-11-27 22:53 CET (Europe/Berlin) (Run #46073164421, Laufzeit 19m 16s)
- 2026-11-28 02:32 CET (Europe/Berlin) (Run #46093590574, Laufzeit 16m 43s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-11-21 11:52 CET (Europe/Berlin) - cancelled - Run #44896391381 (2m 3s)
- 2026-11-25 16:58 CET (Europe/Berlin) - failure - Run #45650104889 (18m 18s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
