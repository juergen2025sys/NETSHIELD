# Workflow Health Dashboard

**Stand:** 2026-10-06 08:12 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 10 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 7
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 91
- **Skip-Runs:** 55
- **Fehlgeschlagene Runs:** 0
- **Lucken >210min:** 3
- **Groesste Lucke:** 2026-10-02 03:19 CEST (Europe/Berlin) -> 2026-10-02 07:29 CEST (Europe/Berlin) (250 min = 4h 10min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 231
- **Watchdog-Fehler:** 1
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 72

Letzte Watchdog-Eingriffe:
- 2026-10-05 20:53 CEST (Europe/Berlin) (Run #37359318611, Laufzeit 21m 11s)
- 2026-10-05 23:47 CEST (Europe/Berlin) (Run #37378257669, Laufzeit 17m 8s)
- 2026-10-06 00:50 CEST (Europe/Berlin) (Run #37385026548, Laufzeit 17m 21s)
- 2026-10-06 02:46 CEST (Europe/Berlin) (Run #37395763388, Laufzeit 17m 1s)
- 2026-10-06 05:31 CEST (Europe/Berlin) (Run #37409387865, Laufzeit 17m 40s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
