# IP-Ablauf-Verifikationsbericht

Lauf: 2026-08-30 13:19 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 197532 |
| Active (180-Tage-Pfad) | 0 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zaehlt echte `eingefroren_am`-Eintraege im Ledger, die schon JETZT existieren; fuer zukuenftige Tage ist das naturgemaess 0, bis der Tag beginnt. Fuer heute steigt die Zahl im Laufe des Tages, sobald weitere combined-Cleanup-Passes laufen.

Keine ausstehenden Vorhersagen - entweder laeuft der Job "prognose" noch nicht, oder alle bisherigen Vorhersagen sind schon final aufgeloest (siehe Sektion weiter unten).

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

✅ 0 Rückfälle - keine der 197,532 eingefrorenen IPs taucht in 6 geprueften Output-Dateien auf. Der Fix haelt.

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen `eingefroren_am`-Zeitstempel im Watchlist-Ledger ab, sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen.

Noch keine aufgeloesten Tage - entweder laeuft der Job "prognose" noch nicht lange genug (woechentlich, siehe Cron), oder es ist noch kein vorhergesagtes Datum vergangen.

## seen_db-Trend

- Seit letztem Lauf: 📈 +52,240 (Anstieg) (jetzt 9,593,508 IPs)
- Seit Zyklus-Start (2026-08-23): 📈 +197,469 (Anstieg)
- Letzter combined-Cleanup-Pass: 171,412 IPs durch Ablauf entfernt (davon 171,412 Watchlist/30T, 0 Active/180T), 1,860,966 neue IPs hinzugekommen (davon 1,639,784 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 43 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 190,907 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 14,867,558 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 1,341,434 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 1,341,434 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 0 (Summe letzte 8 Läufe / ~24h)
- Netto-Wachstum (~24h): 📈 +13,526,124 (Neue minus Entfernte, ~24h)
- Erfolgsquote letzte 16 combined-Läufe: 16/16 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-08-29T16:39 bis 2026-08-30T10:47 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
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
| 2026-08-30 12:38 CEST (Europe/Berlin) | 9,541,268 | 197953 | 0 | 0 |
| 2026-08-30 13:19 CEST (Europe/Berlin) | 9,593,508 | 197532 | 0 | 0 |
