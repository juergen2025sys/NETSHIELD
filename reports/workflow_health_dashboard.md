# Workflow Health Dashboard

**Stand:** 2026-10-04 14:15 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 10 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 8
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 90
- **Skip-Runs:** 54
- **Fehlgeschlagene Runs:** 0
- **Lucken >210min:** 5
- **Groesste Lucke:** 2026-09-28 02:19 CEST (Europe/Berlin) -> 2026-09-28 07:11 CEST (Europe/Berlin) (292 min = 4h 52min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 239
- **Watchdog-Fehler:** 1
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 67

Letzte Watchdog-Eingriffe:
- 2026-10-03 21:35 CEST (Europe/Berlin) (Run #37148443347, Laufzeit 14m 55s)
- 2026-10-03 23:30 CEST (Europe/Berlin) (Run #37155318469, Laufzeit 23m 26s)
- 2026-10-04 02:32 CEST (Europe/Berlin) (Run #37165288260, Laufzeit 20m 25s)
- 2026-10-04 06:12 CEST (Europe/Berlin) (Run #37176336574, Laufzeit 21m 7s)
- 2026-10-04 10:55 CEST (Europe/Berlin) (Run #37190461801, Laufzeit 21m 14s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
