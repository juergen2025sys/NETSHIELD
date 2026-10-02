# Workflow Health Dashboard

**Stand:** 2026-10-02 07:27 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 14 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 5
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 88
- **Skip-Runs:** 55
- **Fehlgeschlagene Runs:** 1
- **Lucken >210min:** 7
- **Groesste Lucke:** 2026-09-27 08:51 CEST (Europe/Berlin) -> 2026-09-27 13:54 CEST (Europe/Berlin) (302 min = 5h 2min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 248
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 65

Letzte Watchdog-Eingriffe:
- 2026-10-01 15:44 CEST (Europe/Berlin) (Run #36870978841, Laufzeit 21m 2s)
- 2026-10-01 17:46 CEST (Europe/Berlin) (Run #36886906485, Laufzeit 21m 42s)
- 2026-10-01 21:05 CEST (Europe/Berlin) (Run #36911725439, Laufzeit 20m 48s)
- 2026-10-01 21:29 CEST (Europe/Berlin) (Run #36914665069, Laufzeit 26m 16s)
- 2026-10-01 22:39 CEST (Europe/Berlin) (Run #36923140113, Laufzeit 19m 46s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-09-26 14:28 CEST (Europe/Berlin) - cancelled - Run #36242007151 (4m 18s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
