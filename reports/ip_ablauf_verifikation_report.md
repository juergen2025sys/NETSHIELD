# IP-Ablauf-Verifikationsbericht

Lauf: 2026-08-25 00:35 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 657348 |
| Active (180-Tage-Pfad) | 0 |

## Diagnose-Status

❌ **1 Problem(e) erkannt:**

- ❌ **Rückfall:** 35410 eingefrorene IP(s) stehen trotzdem in aktuellen Output-Dateien - der Anti-Churn-Fix greift hier NICHT wie erwartet.

## Wiederauftauch-Prüfung

❌ **35410 IP(s) gefunden, die laut Ablauf-Liste dauerhaft draussen sein sollten, aber trotzdem in einer aktuellen Output-Datei stehen - der Fix greift hier NICHT wie erwartet:**

| Datei | Anzahl Rückfälle | Beispiele |
|---|---:|---|
| active_blacklist_ipv4.txt | 35410 | 1.0.218.230, 1.1.202.148, 1.11.62.185, 1.11.62.186, 1.116.214.66, ... |
| combined_threat_blacklist_ipv4_part1.txt | 12671 | 1.0.218.230, 1.1.202.148, 1.11.62.185, 1.11.62.186, 1.116.214.66, ... |
| combined_threat_blacklist_ipv4_part2.txt | 22739 | 112.245.55.60, 112.245.59.63, 112.250.110.172, 112.252.132.185, 113.100.186.171, ... |
| blacklist_confidence40_ipv4_part1.txt | 35410 | 1.0.218.230, 1.1.202.148, 1.11.62.185, 1.11.62.186, 1.116.214.66, ... |

## seen_db-Trend

- Seit letztem Lauf: ➡️ unverändert (jetzt 8,932,302 IPs)
- Seit Zyklus-Start (2026-08-23): 📉 -463,737 (Rückgang)
- Letzter combined-Cleanup-Pass: 616,821 IPs durch Ablauf entfernt (davon 616,821 Watchlist/30T, 0 Active/180T), 1,858,123 neue IPs hinzugekommen (davon 1,671,499 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 43 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 187,897 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 14,867,520 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 4,934,686 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 4,934,686 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 0 (Summe letzte 8 Läufe / ~24h)
- Erfolgsquote letzte 16 combined-Läufe: 14/15 erfolgreich (93%, nur echte Erfolge/Fehlschläge gezählt) | zusätzlich 1 cancelled (nicht gewertet), Zeitraum 2026-08-24T14:21 bis 2026-08-24T22:01 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-08-24 12:30 CEST (Europe/Berlin) | 8,772,949 | 657370 | 0 | 62668 |
| 2026-08-24 12:48 CEST (Europe/Berlin) | 8,772,949 | 657370 | 0 | 62668 |
| 2026-08-24 13:36 CEST (Europe/Berlin) | 8,772,949 | 657370 | 0 | 62656 |
| 2026-08-24 15:05 CEST (Europe/Berlin) | 8,772,949 | 657370 | 0 | 62658 |
| 2026-08-24 15:44 CEST (Europe/Berlin) | 8,772,949 | 657370 | 0 | 62658 |
| 2026-08-24 16:20 CEST (Europe/Berlin) | 8,772,949 | 657370 | 0 | 62658 |
| 2026-08-24 17:12 CEST (Europe/Berlin) | 8,772,949 | 657370 | 0 | 62659 |
| 2026-08-24 18:06 CEST (Europe/Berlin) | 8,924,038 | 657370 | 0 | 35387 |
| 2026-08-24 18:27 CEST (Europe/Berlin) | 8,924,038 | 657370 | 0 | 35387 |
| 2026-08-24 19:08 CEST (Europe/Berlin) | 8,924,038 | 657370 | 0 | 35387 |
| 2026-08-24 20:00 CEST (Europe/Berlin) | 8,924,038 | 657370 | 0 | 35387 |
| 2026-08-24 20:55 CEST (Europe/Berlin) | 8,924,038 | 657370 | 0 | 35387 |
| 2026-08-24 21:23 CEST (Europe/Berlin) | 8,926,822 | 657370 | 0 | 35405 |
| 2026-08-24 21:36 CEST (Europe/Berlin) | 8,926,822 | 657370 | 0 | 35405 |
| 2026-08-24 22:16 CEST (Europe/Berlin) | 8,927,370 | 657370 | 0 | 35410 |
| 2026-08-24 22:39 CEST (Europe/Berlin) | 8,927,370 | 657370 | 0 | 35410 |
| 2026-08-24 22:58 CEST (Europe/Berlin) | 8,930,835 | 657355 | 0 | 35410 |
| 2026-08-24 23:37 CEST (Europe/Berlin) | 8,930,835 | 657355 | 0 | 35410 |
| 2026-08-25 00:17 CEST (Europe/Berlin) | 8,932,302 | 657348 | 0 | 35410 |
| 2026-08-25 00:35 CEST (Europe/Berlin) | 8,932,302 | 657348 | 0 | 35410 |
