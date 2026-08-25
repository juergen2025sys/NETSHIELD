# IP-Ablauf-Verifikationsbericht

Lauf: 2026-08-25 21:27 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 626983 |
| Active (180-Tage-Pfad) | 0 |

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

✅ 0 Rückfälle - keine der 626,983 eingefrorenen IPs taucht in 6 geprueften Output-Dateien auf. Der Fix haelt.

## seen_db-Trend

- Seit letztem Lauf: 📈 +6,033 (Anstieg) (jetzt 8,958,104 IPs)
- Seit Zyklus-Start (2026-08-23): 📉 -437,935 (Rückgang)
- Letzter combined-Cleanup-Pass: 618,701 IPs durch Ablauf entfernt (davon 618,701 Watchlist/30T, 0 Active/180T), 1,865,866 neue IPs hinzugekommen (davon 1,675,345 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 10 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 188,958 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 14,851,807 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 4,951,270 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 4,951,270 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 0 (Summe letzte 8 Läufe / ~24h)
- Erfolgsquote letzte 16 combined-Läufe: 16/16 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-08-25T07:23 bis 2026-08-25T19:17 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-08-24 22:16 CEST (Europe/Berlin) | 8,927,370 | 657370 | 0 | 35410 |
| 2026-08-24 22:39 CEST (Europe/Berlin) | 8,927,370 | 657370 | 0 | 35410 |
| 2026-08-24 22:58 CEST (Europe/Berlin) | 8,930,835 | 657355 | 0 | 35410 |
| 2026-08-24 23:37 CEST (Europe/Berlin) | 8,930,835 | 657355 | 0 | 35410 |
| 2026-08-25 00:17 CEST (Europe/Berlin) | 8,932,302 | 657348 | 0 | 35410 |
| 2026-08-25 00:35 CEST (Europe/Berlin) | 8,932,302 | 657348 | 0 | 35410 |
| 2026-08-25 01:28 CEST (Europe/Berlin) | 8,932,302 | 657348 | 0 | 35410 |
| 2026-08-25 01:52 CEST (Europe/Berlin) | 8,932,302 | 657348 | 0 | 35410 |
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
