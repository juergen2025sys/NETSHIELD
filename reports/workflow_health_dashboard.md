# Workflow Health Dashboard

**Stand:** 2026-11-20 08:01 CET (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 7
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-11-19 13:16 CET (Europe/Berlin) -> 2026-11-19 17:34 CET (Europe/Berlin) (258 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 56
- **Skip-Runs:** 50
- **Fehlgeschlagene Runs:** 0
- **Lucken >210min:** 10
- **Groesste Lucke:** 2026-11-17 04:59 CET (Europe/Berlin) -> 2026-11-17 10:13 CET (Europe/Berlin) (313 min = 5h 13min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 340
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 46

Letzte Watchdog-Eingriffe:
- 2026-11-19 17:34 CET (Europe/Berlin) (Run #44567677983, Laufzeit 17m 28s)
- 2026-11-19 19:34 CET (Europe/Berlin) (Run #44589330434, Laufzeit 17m 21s)
- 2026-11-19 22:30 CET (Europe/Berlin) (Run #44619461809, Laufzeit 19m 6s)
- 2026-11-20 02:09 CET (Europe/Berlin) (Run #44651526407, Laufzeit 19m 36s)
- 2026-11-20 04:38 CET (Europe/Berlin) (Run #44669146702, Laufzeit 18m 55s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
