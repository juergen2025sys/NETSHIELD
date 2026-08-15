# Workflow Health Dashboard

**Stand:** 2026-08-15 20:43 CEST (Europe/Berlin)
**Betrachtungszeitraum:** 7 Tage

Generiert von `.github/workflows/workflow_health_dashboard.yml` alle 6h.
Klassifizierung: Echter Run = Laufzeit > 60s, Skip-Run = kurzer Idempotenz-Guard-Skip.

## Letzte 24h

- **Echte Combined-Runs:** 10 / 8 erwartet
- **Skip-Runs (Idempotenz-Guard):** 24
- **Lucken (>210min zwischen echten Runs):** 0

## Letzte 7 Tage

- **Echte Combined-Runs:** 82
- **Skip-Runs:** 131
- **Fehlgeschlagene Runs:** 15
- **Lucken >210min:** 4
- **Groesste Lucke:** 2026-08-13 00:17 CEST (Europe/Berlin) -> 2026-08-13 04:37 CEST (Europe/Berlin) (260 min = 4h 20min)

## Watchdog (letzte 7 Tage)

- **Watchdog-Laeufe insgesamt:** 507
- **Watchdog-Fehler:** 1
- **Combined-Runs via workflow_dispatch (Watchdog-Eingriff):** 60

Letzte Watchdog-Eingriffe:
- 2026-08-15 16:48 CEST (Europe/Berlin) (Run #31890948163, Laufzeit 33m 44s)
- 2026-08-15 17:37 CEST (Europe/Berlin) (Run #31893259272, Laufzeit 21m 34s)
- 2026-08-15 18:07 CEST (Europe/Berlin) (Run #31894633583, Laufzeit 66m 22s)
- 2026-08-15 19:35 CEST (Europe/Berlin) (Run #31898703429, Laufzeit 40m 20s)
- 2026-08-15 20:19 CEST (Europe/Berlin) (Run #31900786960, Laufzeit 11s)

## Fehlgeschlagene Combined-Runs (7d)

- 2026-08-09 21:00 CEST (Europe/Berlin) - cancelled - Run #31330530555 (44m 25s)
- 2026-08-09 21:09 CEST (Europe/Berlin) - cancelled - Run #31330921720 (36m 54s)
- 2026-08-09 21:19 CEST (Europe/Berlin) - cancelled - Run #31331350528 (27m 32s)
- 2026-08-10 18:05 CEST (Europe/Berlin) - action_required - Run #31407080526 (0s)
- 2026-08-12 05:10 CEST (Europe/Berlin) - failure - Run #31559262855 (10s)
- 2026-08-13 13:36 CEST (Europe/Berlin) - cancelled - Run #31696234312 (95m 18s)
- 2026-08-13 20:30 CEST (Europe/Berlin) - cancelled - Run #31731085374 (8m 7s)
- 2026-08-15 08:27 CEST (Europe/Berlin) - failure - Run #31869475966 (21m 45s)
- 2026-08-15 17:37 CEST (Europe/Berlin) - failure - Run #31893259272 (21m 34s)
- 2026-08-15 19:35 CEST (Europe/Berlin) - cancelled - Run #31898703429 (40m 20s)

---

**Hinweise zur Interpretation:**

- Echte Runs/24h sollte 8 sein (1 pro 3h-Fenster). Weniger = GitHub-Scheduler hat Slots geschluckt ODER Runs fehlgeschlagen.
- Skip-Runs sind normal und gewollt (Idempotenz-Guard verhindert Doppellaeufe). Hohe Zahl OK solange echte Runs auch laufen.
- Lucken > 210min zeigen Zeitraeume ohne Daten-Update. Bei haeufigen Lucken: Watchdog-Frequenz pruefen oder externer Trigger einrichten.
- Watchdog-Eingriffe (Combined via workflow_dispatch) sind ein Indikator dass das Sicherheitsnetz greift. Zu viele Eingriffe = primaerer Schedule unzuverlaessig.
