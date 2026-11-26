# Workflow Health Dashboard

**Stand:** 2026-11-26 09:04 CET (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 7
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-11-25 11:05 CET (Europe/Berlin) -> 2026-11-25 15:30 CET (Europe/Berlin) (265 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 62
- **Skip-Runs:** 46
- **Fehlgeschlagene Runs:** 2
- **Lucken >210min:** 7
- **Groesste Lucke:** 2026-11-22 01:52 CET (Europe/Berlin) -> 2026-11-22 08:34 CET (Europe/Berlin) (401 min = 6h 41min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 269
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 53

Letzte Watchdog-Eingriffe:
- 2026-11-25 18:30 CET (Europe/Berlin) (Run #45665453973, Laufzeit 16m 8s)
- 2026-11-25 20:27 CET (Europe/Berlin) (Run #45685443764, Laufzeit 19m 26s)
- 2026-11-25 23:16 CET (Europe/Berlin) (Run #45711845665, Laufzeit 19m 28s)
- 2026-11-26 01:38 CET (Europe/Berlin) (Run #45730155484, Laufzeit 18m 32s)
- 2026-11-26 01:57 CET (Europe/Berlin) (Run #45732356296, Laufzeit 23m 26s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-11-21 11:52 CET (Europe/Berlin) - cancelled - Run #44896391381 (2m 3s)
- 2026-11-25 16:58 CET (Europe/Berlin) - failure - Run #45650104889 (18m 18s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
