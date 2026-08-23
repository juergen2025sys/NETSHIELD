# IP-Ablauf-Verifikationsbericht

Lauf: 2026-08-24 00:14 CEST (Europe/Berlin)

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

- Seit letztem Lauf: 📈 +3,405 (Anstieg) (jetzt 9,415,235 IPs)
- Seit Zyklus-Start (2026-08-23): 📈 +19,196 (Anstieg)
- Letzter combined-Cleanup-Pass: 0 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 0 Active/180T), 1,861,569 neue IPs hinzugekommen (davon 1,671,401 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) (zusätzlich: 186,763 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): n/a (3/8 Läufe im Fenster mit Daten)
- Entfernte IPs (Summe letzter Läufe): n/a (3/8 Läufe im Fenster mit Daten)
  - davon Watchlist/30 Tage: n/a (2/8 Läufe im Fenster mit Daten)
  - davon Active/180 Tage: n/a (2/8 Läufe im Fenster mit Daten)
- Erfolgsquote letzte 16 combined-Läufe: 12/14 erfolgreich (86%, nur echte Erfolge/Fehlschläge gezählt) | 2 sonstige, Zeitraum 2026-08-23T13:20 bis 2026-08-23T21:57 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-08-23 12:54 CEST (Europe/Berlin) | 9,396,039 | 0 | 0 | 0 |
| 2026-08-23 13:25 CEST (Europe/Berlin) | 9,396,039 | 0 | 0 | 0 |
| 2026-08-23 13:29 CEST (Europe/Berlin) | 9,396,039 | 0 | 0 | 0 |
| 2026-08-23 14:03 CEST (Europe/Berlin) | 9,396,039 | 0 | 0 | 0 |
| 2026-08-23 15:26 CEST (Europe/Berlin) | 9,396,039 | 0 | 0 | 0 |
| 2026-08-23 17:29 CEST (Europe/Berlin) | 9,406,053 | 0 | 0 | 0 |
| 2026-08-23 18:16 CEST (Europe/Berlin) | 9,406,053 | 0 | 0 | 0 |
| 2026-08-23 18:34 CEST (Europe/Berlin) | 9,406,053 | 0 | 0 | 0 |
| 2026-08-23 18:44 CEST (Europe/Berlin) | 9,406,053 | 0 | 0 | 0 |
| 2026-08-23 19:11 CEST (Europe/Berlin) | 9,406,053 | 0 | 0 | 0 |
| 2026-08-23 19:21 CEST (Europe/Berlin) | 9,406,053 | 0 | 0 | 0 |
| 2026-08-23 21:17 CEST (Europe/Berlin) | 9,406,053 | 0 | 0 | 0 |
| 2026-08-23 21:43 CEST (Europe/Berlin) | 9,411,701 | 0 | 0 | 0 |
| 2026-08-23 22:16 CEST (Europe/Berlin) | 9,411,830 | 0 | 0 | 0 |
| 2026-08-24 00:14 CEST (Europe/Berlin) | 9,415,235 | 0 | 0 | 0 |
