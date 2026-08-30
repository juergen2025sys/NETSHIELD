# IP-Ablauf-Verifikationsbericht

Lauf: 2026-08-30 08:07 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 197970 |
| Active (180-Tage-Pfad) | 0 |

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

✅ 0 Rückfälle - keine der 197,970 eingefrorenen IPs taucht in 6 geprueften Output-Dateien auf. Der Fix haelt.

## seen_db-Trend

- Seit letztem Lauf: 📈 +8,308 (Anstieg) (jetzt 9,540,902 IPs)
- Seit Zyklus-Start (2026-08-23): 📈 +144,863 (Anstieg)
- Letzter combined-Cleanup-Pass: 171,840 IPs durch Ablauf entfernt (davon 171,840 Watchlist/30T, 0 Active/180T), 1,861,539 neue IPs hinzugekommen (davon 1,684,777 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 3,968 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 190,435 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 14,874,119 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 1,322,795 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 1,322,795 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 0 (Summe letzte 8 Läufe / ~24h)
- Erfolgsquote letzte 16 combined-Läufe: 16/16 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-08-29T14:41 bis 2026-08-30T05:51 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-08-27 04:28 CEST (Europe/Berlin) | 9,618,265 | 0 | 0 | 0 |
| 2026-08-27 13:07 CEST (Europe/Berlin) | 9,621,174 | 0 | 0 | 0 |
| 2026-08-27 16:53 CEST (Europe/Berlin) | 9,637,615 | 0 | 0 | 0 |
| 2026-08-27 23:08 CEST (Europe/Berlin) | 9,644,064 | 0 | 0 | 0 |
| 2026-08-28 02:42 CEST (Europe/Berlin) | 9,651,010 | 0 | 0 | 0 |
| 2026-08-28 07:35 CEST (Europe/Berlin) | 9,658,059 | 0 | 0 | 0 |
| 2026-08-28 14:24 CEST (Europe/Berlin) | 9,666,280 | 0 | 0 | 0 |
| 2026-08-28 20:31 CEST (Europe/Berlin) | 9,688,653 | 0 | 0 | 0 |
| 2026-08-29 00:49 CEST (Europe/Berlin) | 9,688,982 | 0 | 0 | 0 |
| 2026-08-29 04:02 CEST (Europe/Berlin) | 9,513,964 | 184313 | 0 | 0 |
| 2026-08-29 09:34 CEST (Europe/Berlin) | 9,517,844 | 183291 | 0 | 0 |
| 2026-08-29 13:26 CEST (Europe/Berlin) | 9,525,863 | 183269 | 0 | 0 |
| 2026-08-29 16:39 CEST (Europe/Berlin) | 9,533,394 | 183250 | 0 | 0 |
| 2026-08-29 16:50 CEST (Europe/Berlin) | 9,533,394 | 183250 | 0 | 0 |
| 2026-08-29 20:19 CEST (Europe/Berlin) | 9,535,319 | 183247 | 0 | 0 |
| 2026-08-29 21:02 CEST (Europe/Berlin) | 9,535,319 | 183247 | 0 | 0 |
| 2026-08-30 01:34 CEST (Europe/Berlin) | 9,542,887 | 183204 | 0 | 0 |
| 2026-08-30 01:46 CEST (Europe/Berlin) | 9,546,199 | 183204 | 0 | 0 |
| 2026-08-30 07:06 CEST (Europe/Berlin) | 9,532,594 | 198223 | 0 | 2687 |
| 2026-08-30 08:07 CEST (Europe/Berlin) | 9,540,902 | 197970 | 0 | 0 |
