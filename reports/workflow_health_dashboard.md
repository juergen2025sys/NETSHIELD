# Workflow Health Dashboard

**Stand:** 2026-11-18 21:24 CET (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 8 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 6
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-11-18 13:45 CET (Europe/Berlin) -> 2026-11-18 17:28 CET (Europe/Berlin) (223 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 55
- **Skip-Runs:** 49
- **Fehlgeschlagene Runs:** 0
- **Lucken >210min:** 10
- **Groesste Lucke:** 2026-11-17 04:59 CET (Europe/Berlin) -> 2026-11-17 10:13 CET (Europe/Berlin) (313 min = 5h 13min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 360
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 46

Letzte Watchdog-Eingriffe:
- 2026-11-18 08:37 CET (Europe/Berlin) (Run #44260339176, Laufzeit 19m 18s)
- 2026-11-18 11:36 CET (Europe/Berlin) (Run #44287079079, Laufzeit 17m 13s)
- 2026-11-18 13:33 CET (Europe/Berlin) (Run #44304984747, Laufzeit 12m 4s)
- 2026-11-18 17:28 CET (Europe/Berlin) (Run #44347569379, Laufzeit 17m 54s)
- 2026-11-18 20:10 CET (Europe/Berlin) (Run #44377733267, Laufzeit 15m 20s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
