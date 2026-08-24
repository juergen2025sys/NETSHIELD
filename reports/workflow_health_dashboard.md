# Workflow Health Dashboard

**Stand:** 2026-08-24 09:16 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 16
- **Lucken (>210min zwischen echten Runs):** 2
  - 2026-08-23 17:16 CEST (Europe/Berlin) -> 2026-08-23 21:09 CEST (Europe/Berlin) (232 min)
  - 2026-08-24 00:56 CEST (Europe/Berlin) -> 2026-08-24 06:10 CEST (Europe/Berlin) (314 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 61
- **Skip-Runs:** 155
- **Fehlgeschlagene Runs:** 17
- **Lucken >210min:** 3
- **Groesste Lucke:** 2026-08-19 06:13 CEST (Europe/Berlin) -> 2026-08-19 17:02 CEST (Europe/Berlin) (649 min = 10h 49min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 751
- **Watchdog-Fehler:** 1
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 67

Letzte Watchdog-Eingriffe:
- 2026-08-24 04:39 CEST (Europe/Berlin) (Run #32683778064, Laufzeit 17m 31s)
- 2026-08-24 05:13 CEST (Europe/Berlin) (Run #32685733446, Laufzeit 18m 36s)
- 2026-08-24 05:32 CEST (Europe/Berlin) (Run #32686796245, Laufzeit 17m 6s)
- 2026-08-24 06:10 CEST (Europe/Berlin) (Run #32688993601, Laufzeit 21m 6s)
- 2026-08-24 06:32 CEST (Europe/Berlin) (Run #32690374851, Laufzeit 29m 3s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-08-23 20:58 CEST (Europe/Berlin) - failure - Run #32659726519 (9m 36s)
- 2026-08-24 02:30 CEST (Europe/Berlin) - failure - Run #32676895120 (18m 26s)
- 2026-08-24 03:07 CEST (Europe/Berlin) - failure - Run #32678765155 (14m 31s)
- 2026-08-24 03:50 CEST (Europe/Berlin) - failure - Run #32681094235 (18m 0s)
- 2026-08-24 04:10 CEST (Europe/Berlin) - failure - Run #32682166781 (18m 5s)
- 2026-08-24 04:39 CEST (Europe/Berlin) - failure - Run #32683778064 (17m 31s)
- 2026-08-24 05:13 CEST (Europe/Berlin) - failure - Run #32685733446 (18m 36s)
- 2026-08-24 05:32 CEST (Europe/Berlin) - failure - Run #32686796245 (17m 6s)
- 2026-08-24 06:00 CEST (Europe/Berlin) - cancelled - Run #32688419543 (6m 59s)
- 2026-08-24 06:32 CEST (Europe/Berlin) - failure - Run #32690374851 (29m 3s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
