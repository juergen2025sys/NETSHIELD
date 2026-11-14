# Workflow Health Dashboard

**Stand:** 2026-11-14 23:16 CET (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 8
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-11-14 01:51 CET (Europe/Berlin) -> 2026-11-14 05:42 CET (Europe/Berlin) (231 min)
  - 2026-11-14 11:21 CET (Europe/Berlin) -> 2026-11-14 15:10 CET (Europe/Berlin) (228 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 58
- **Skip-Runs:** 46
- **Fehlgeschlagene Runs:** 0
- **Lucken >210min:** 11
- **Groesste Lucke:** 2026-11-08 01:44 CET (Europe/Berlin) -> 2026-11-08 07:25 CET (Europe/Berlin) (341 min = 5h 41min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 423
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 41

Letzte Watchdog-Eingriffe:
- 2026-11-14 07:52 CET (Europe/Berlin) (Run #43568411152, Laufzeit 15m 51s)
- 2026-11-14 15:10 CET (Europe/Berlin) (Run #43603442259, Laufzeit 12m 33s)
- 2026-11-14 16:45 CET (Europe/Berlin) (Run #43611879463, Laufzeit 15m 16s)
- 2026-11-14 20:59 CET (Europe/Berlin) (Run #43635065480, Laufzeit 19m 6s)
- 2026-11-14 22:30 CET (Europe/Berlin) (Run #43643143478, Laufzeit 14m 58s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
