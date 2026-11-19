# Workflow Health Dashboard

**Stand:** 2026-11-19 21:28 CET (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 7
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-11-19 05:03 CET (Europe/Berlin) -> 2026-11-19 09:47 CET (Europe/Berlin) (283 min)
  - 2026-11-19 13:16 CET (Europe/Berlin) -> 2026-11-19 17:34 CET (Europe/Berlin) (258 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 56
- **Skip-Runs:** 49
- **Fehlgeschlagene Runs:** 0
- **Lucken >210min:** 10
- **Groesste Lucke:** 2026-11-17 04:59 CET (Europe/Berlin) -> 2026-11-17 10:13 CET (Europe/Berlin) (313 min = 5h 13min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 348
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 47

Letzte Watchdog-Eingriffe:
- 2026-11-19 04:44 CET (Europe/Berlin) (Run #44453511074, Laufzeit 18m 59s)
- 2026-11-19 09:47 CET (Europe/Berlin) (Run #44490551825, Laufzeit 13m 34s)
- 2026-11-19 10:34 CET (Europe/Berlin) (Run #44497732906, Laufzeit 19m 55s)
- 2026-11-19 17:34 CET (Europe/Berlin) (Run #44567677983, Laufzeit 17m 28s)
- 2026-11-19 19:34 CET (Europe/Berlin) (Run #44589330434, Laufzeit 17m 21s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
