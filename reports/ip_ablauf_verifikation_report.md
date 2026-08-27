# IP-Ablauf-Verifikationsbericht

Lauf: 2026-08-27 16:53 CEST (Europe/Berlin)

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

- Seit letztem Lauf: 📈 +16,441 (Anstieg) (jetzt 9,637,615 IPs)
- Seit Zyklus-Start (2026-08-23): 📈 +241,576 (Anstieg)
- Letzter combined-Cleanup-Pass: 0 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 0 Active/180T), 1,861,292 neue IPs hinzugekommen (davon 1,668,064 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 18 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 188,812 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 14,890,635 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 0 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 0 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 0 (Summe letzte 8 Läufe / ~24h)
- Erfolgsquote letzte 16 combined-Läufe: 15/15 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt) | zusätzlich 1 cancelled (nicht gewertet), Zeitraum 2026-08-26T18:56 bis 2026-08-27T14:46 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
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
| 2026-08-26 18:43 CEST (Europe/Berlin) | 9,605,118 | 0 | 0 | 0 |
| 2026-08-26 23:00 CEST (Europe/Berlin) | 9,616,143 | 0 | 0 | 0 |
| 2026-08-26 23:30 CEST (Europe/Berlin) | 9,616,143 | 0 | 0 | 0 |
| 2026-08-27 02:43 CEST (Europe/Berlin) | 9,616,980 | 0 | 0 | 0 |
| 2026-08-27 04:28 CEST (Europe/Berlin) | 9,618,265 | 0 | 0 | 0 |
| 2026-08-27 13:07 CEST (Europe/Berlin) | 9,621,174 | 0 | 0 | 0 |
| 2026-08-27 16:53 CEST (Europe/Berlin) | 9,637,615 | 0 | 0 | 0 |
