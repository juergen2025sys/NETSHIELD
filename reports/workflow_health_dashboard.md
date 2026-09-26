# Workflow Health Dashboard

**Stand:** 2026-09-26 23:04 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 12 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 11
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-09-26 02:48 CEST (Europe/Berlin) -> 2026-09-26 06:46 CEST (Europe/Berlin) (237 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 74
- **Skip-Runs:** 68
- **Fehlgeschlagene Runs:** 3
- **Lucken >210min:** 7
- **Groesste Lucke:** 2026-09-23 02:10 CEST (Europe/Berlin) -> 2026-09-23 06:35 CEST (Europe/Berlin) (265 min = 4h 25min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 291
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 56

Letzte Watchdog-Eingriffe:
- 2026-09-26 14:28 CEST (Europe/Berlin) (Run #36242007151, Laufzeit 4m 18s)
- 2026-09-26 14:32 CEST (Europe/Berlin) (Run #36242232075, Laufzeit 23m 19s)
- 2026-09-26 17:06 CEST (Europe/Berlin) (Run #36250770522, Laufzeit 20m 1s)
- 2026-09-26 20:33 CEST (Europe/Berlin) (Run #36262972872, Laufzeit 17m 32s)
- 2026-09-26 21:29 CEST (Europe/Berlin) (Run #36266228891, Laufzeit 20m 14s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-09-21 02:31 CEST (Europe/Berlin) - cancelled - Run #35547981772 (5m 42s)
- 2026-09-23 19:43 CEST (Europe/Berlin) - cancelled - Run #35897617505 (2m 6s)
- 2026-09-26 14:28 CEST (Europe/Berlin) - cancelled - Run #36242007151 (4m 18s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
