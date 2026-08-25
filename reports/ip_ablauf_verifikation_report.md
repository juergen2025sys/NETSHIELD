# IP-Ablauf-Verifikationsbericht

Lauf: 2026-08-25 12:23 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 627052 |
| Active (180-Tage-Pfad) | 0 |

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

✅ 0 Rückfälle - keine der 627,052 eingefrorenen IPs taucht in 6 geprueften Output-Dateien auf. Der Fix haelt.

## seen_db-Trend

- Seit letztem Lauf: 📈 +1,515 (Anstieg) (jetzt 8,944,199 IPs)
- Seit Zyklus-Start (2026-08-23): 📉 -451,840 (Rückgang)
- Letzter combined-Cleanup-Pass: 618,754 IPs durch Ablauf entfernt (davon 618,754 Watchlist/30T, 0 Active/180T), 1,816,663 neue IPs hinzugekommen (davon 1,675,695 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 34 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 143,929 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 14,840,926 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 4,964,057 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 4,964,057 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 0 (Summe letzte 8 Läufe / ~24h)
- Erfolgsquote letzte 16 combined-Läufe: 16/16 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-08-25T00:40 bis 2026-08-25T10:12 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-08-24 20:55 CEST (Europe/Berlin) | 8,924,038 | 657370 | 0 | 35387 |
| 2026-08-24 21:23 CEST (Europe/Berlin) | 8,926,822 | 657370 | 0 | 35405 |
| 2026-08-24 21:36 CEST (Europe/Berlin) | 8,926,822 | 657370 | 0 | 35405 |
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
