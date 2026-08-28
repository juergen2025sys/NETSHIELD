# IP-Ablauf-Verifikationsbericht

Lauf: 2026-08-29 00:49 CEST (Europe/Berlin)

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

- Seit letztem Lauf: 📈 +329 (Anstieg) (jetzt 9,688,982 IPs)
- Seit Zyklus-Start (2026-08-23): 📈 +292,943 (Anstieg)
- Letzter combined-Cleanup-Pass: 0 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 0 Active/180T), 1,860,461 neue IPs hinzugekommen (davon 1,667,598 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 2 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 192,534 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): n/a (7/8 Läufe im Fenster mit Daten)
- Entfernte IPs (Summe letzter Läufe): n/a (7/8 Läufe im Fenster mit Daten)
  - davon Watchlist/30 Tage: n/a (7/8 Läufe im Fenster mit Daten)
  - davon Active/180 Tage: n/a (7/8 Läufe im Fenster mit Daten)
- Erfolgsquote letzte 16 combined-Läufe: 12/13 erfolgreich (92%, nur echte Erfolge/Fehlschläge gezählt) | zusätzlich 2 cancelled (nicht gewertet) | 1 sonstige, Zeitraum 2026-08-27T22:30 bis 2026-08-28T22:41 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
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
| 2026-08-27 23:08 CEST (Europe/Berlin) | 9,644,064 | 0 | 0 | 0 |
| 2026-08-28 02:42 CEST (Europe/Berlin) | 9,651,010 | 0 | 0 | 0 |
| 2026-08-28 07:35 CEST (Europe/Berlin) | 9,658,059 | 0 | 0 | 0 |
| 2026-08-28 14:24 CEST (Europe/Berlin) | 9,666,280 | 0 | 0 | 0 |
| 2026-08-28 20:31 CEST (Europe/Berlin) | 9,688,653 | 0 | 0 | 0 |
| 2026-08-29 00:49 CEST (Europe/Berlin) | 9,688,982 | 0 | 0 | 0 |
