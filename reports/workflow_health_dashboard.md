# Workflow Health Dashboard

**Stand:** 2026-09-03 18:21 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 9 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 12
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 63
- **Skip-Runs:** 62
- **Fehlgeschlagene Runs:** 7
- **Lucken >210min:** 8
- **Groesste Lucke:** 2026-08-28 00:54 CEST (Europe/Berlin) -> 2026-08-28 06:06 CEST (Europe/Berlin) (312 min = 5h 12min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 172
- **Watchdog-Fehler:** 0
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 51

Letzte Watchdog-Eingriffe:
- 2026-09-02 22:52 CEST (Europe/Berlin) (Run #33681851595, Laufzeit 21m 47s)
- 2026-09-03 02:31 CEST (Europe/Berlin) (Run #33699849368, Laufzeit 18m 36s)
- 2026-09-03 08:35 CEST (Europe/Berlin) (Run #33723899583, Laufzeit 15m 41s)
- 2026-09-03 11:44 CEST (Europe/Berlin) (Run #33740474926, Laufzeit 20m 26s)
- 2026-09-03 15:33 CEST (Europe/Berlin) (Run #33761827666, Laufzeit 20m 17s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-08-28 02:36 CEST (Europe/Berlin) - failure - Run #33130252717 (24m 5s)
- 2026-08-28 06:04 CEST (Europe/Berlin) - cancelled - Run #33140716872 (8s)
- 2026-08-28 14:14 CEST (Europe/Berlin) - cancelled - Run #33170286806 (3m 58s)
- 2026-08-31 22:53 CEST (Europe/Berlin) - cancelled - Run #33438466768 (6m 40s)
- 2026-08-31 23:05 CEST (Europe/Berlin) - cancelled - Run #33439515318 (9m 45s)
- 2026-09-01 20:22 CEST (Europe/Berlin) - cancelled - Run #33543228443 (17m 24s)
- 2026-09-02 18:28 CEST (Europe/Berlin) - action_required - Run #33655138414 (0s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
