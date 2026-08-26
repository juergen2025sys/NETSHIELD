# IP-Ablauf-Verifikationsbericht

Lauf: 2026-08-26 15:47 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 0 |
| Active (180-Tage-Pfad) | 0 |

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ Noch keine IPs in den Ablauf-Listen - entweder ist der Fix noch nicht lange genug aktiv, oder es ist noch keine IP ohne Zweitbestaetigung abgelaufen. Keine Pruefung moeglich, bis der erste Ablauf passiert ist (siehe reports/ip_ablauf.md fuer die naechsten Ablauftermine, z.B. 2026-09-04).

## seen_db-Trend

- Seit letztem Lauf: 📈 +10,199 (Anstieg) (jetzt 9,605,118 IPs)
- Seit Zyklus-Start (2026-08-23): 📈 +209,079 (Anstieg)
- Letzter combined-Cleanup-Pass: 0 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 0 Active/180T), 1,868,289 neue IPs hinzugekommen (davon 1,669,413 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 21 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 188,677 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 16,182,857 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 630,159 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 630,159 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 0 (Summe letzte 8 Läufe / ~24h)
- Erfolgsquote letzte 16 combined-Läufe: 16/16 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-08-26T02:13 bis 2026-08-26T13:39 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-08-25 03:43 CEST (Europe/Berlin) | 8,927,629 | 665443 | 0 | 35410 |
| 2026-08-25 04:14 CEST (Europe/Berlin) | 8,927,629 | 665443 | 0 | 35410 |
| 2026-08-25 05:06 CEST (Europe/Berlin) | 8,927,629 | 665443 | 0 | 35410 |
| 2026-08-25 06:11 CEST (Europe/Berlin) | 8,936,454 | 662532 | 0 | 35410 |
| 2026-08-25 06:31 CEST (Europe/Berlin) | 8,936,454 | 662532 | 0 | 35410 |
| 2026-08-25 07:08 CEST (Europe/Berlin) | 8,936,798 | 627114 | 0 | 0 |
| 2026-08-25 09:27 CEST (Europe/Berlin) | 8,942,684 | 627078 | 0 | 0 |
| 2026-08-25 09:38 CEST (Europe/Berlin) | 8,942,684 | 627078 | 0 | 0 |
| 2026-08-25 12:23 CEST (Europe/Berlin) | 8,944,199 | 627052 | 0 | 0 |
| 2026-08-25 15:42 CEST (Europe/Berlin) | 8,947,997 | 627030 | 0 | 0 |
| 2026-08-25 18:27 CEST (Europe/Berlin) | 8,952,071 | 627009 | 0 | 0 |
| 2026-08-25 21:27 CEST (Europe/Berlin) | 8,958,104 | 626983 | 0 | 0 |
| 2026-08-26 00:18 CEST (Europe/Berlin) | 8,961,921 | 0 | 0 | 0 |
| 2026-08-26 03:49 CEST (Europe/Berlin) | 9,577,670 | 0 | 0 | 0 |
| 2026-08-26 04:21 CEST (Europe/Berlin) | 9,577,670 | 0 | 0 | 0 |
| 2026-08-26 06:32 CEST (Europe/Berlin) | 9,590,856 | 0 | 0 | 0 |
| 2026-08-26 09:29 CEST (Europe/Berlin) | 9,591,725 | 0 | 0 | 0 |
| 2026-08-26 09:40 CEST (Europe/Berlin) | 9,591,725 | 0 | 0 | 0 |
| 2026-08-26 12:27 CEST (Europe/Berlin) | 9,594,919 | 0 | 0 | 0 |
| 2026-08-26 15:47 CEST (Europe/Berlin) | 9,605,118 | 0 | 0 | 0 |
