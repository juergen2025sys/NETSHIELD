# Workflow Health Dashboard

**Stand:** 2026-08-24 03:54 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 12 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 19
- **Lucken (>210min zwischen echten Runs):** 1
  - 2026-08-23 17:16 CEST (Europe/Berlin) -> 2026-08-23 21:09 CEST (Europe/Berlin) (232 min)

## Letzte 7 Tage

- **Echte Combined-Runs:** 62
- **Skip-Runs:** 157
- **Fehlgeschlagene Runs:** 10
- **Lucken >210min:** 2
- **Groesste Lucke:** 2026-08-19 06:13 CEST (Europe/Berlin) -> 2026-08-19 17:02 CEST (Europe/Berlin) (649 min = 10h 49min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 753
- **Watchdog-Fehler:** 1
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 63

Letzte Watchdog-Eingriffe:
- 2026-08-23 21:53 CEST (Europe/Berlin) (Run #32662646209, Laufzeit 21m 8s)
- 2026-08-23 23:33 CEST (Europe/Berlin) (Run #32667897410, Laufzeit 20m 56s)
- 2026-08-24 00:34 CEST (Europe/Berlin) (Run #32671024189, Laufzeit 21m 4s)
- 2026-08-24 02:30 CEST (Europe/Berlin) (Run #32676895120, Laufzeit 18m 26s)
- 2026-08-24 03:07 CEST (Europe/Berlin) (Run #32678765155, Laufzeit 14m 31s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-08-23 14:40 CEST (Europe/Berlin) - action_required - Run #32640043581 (1s)
- 2026-08-23 14:55 CEST (Europe/Berlin) - action_required - Run #32640807973 (0s)
- 2026-08-23 15:00 CEST (Europe/Berlin) - action_required - Run #32641049205 (1s)
- 2026-08-23 15:08 CEST (Europe/Berlin) - action_required - Run #32641464890 (0s)
- 2026-08-23 17:30 CEST (Europe/Berlin) - action_required - Run #32648775481 (0s)
- 2026-08-23 17:44 CEST (Europe/Berlin) - action_required - Run #32649488888 (0s)
- 2026-08-23 20:46 CEST (Europe/Berlin) - failure - Run #32659082123 (10m 12s)
- 2026-08-23 20:58 CEST (Europe/Berlin) - failure - Run #32659726519 (9m 36s)
- 2026-08-24 02:30 CEST (Europe/Berlin) - failure - Run #32676895120 (18m 26s)
- 2026-08-24 03:07 CEST (Europe/Berlin) - failure - Run #32678765155 (14m 31s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
