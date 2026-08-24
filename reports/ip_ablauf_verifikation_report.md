# IP-Ablauf-Verifikationsbericht

Lauf: 2026-08-24 16:20 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 657370 |
| Active (180-Tage-Pfad) | 0 |

## Diagnose-Status

❌ **3 Problem(e) erkannt:**

- ❌ **Rückfall:** 62658 eingefrorene IP(s) stehen trotzdem in aktuellen Output-Dateien - der Anti-Churn-Fix greift hier NICHT wie erwartet.
- ⚠️ **Niedrige combined-Erfolgsquote:** nur 4/16 erfolgreich (25%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-08-24T07:13 bis 2026-08-24T13:37 UTC in den letzten 16 Läufen (Schwelle: 75%, cancelled nicht mitgezaehlt) - auch wenn der neueste Stand frisch wirkt, lief das System zuletzt nicht zuverlässig.
- ⚠️ **Veraltete Daten:** `state/seen_db_meta.json` ist 9.8h alt (Schwelle: 6h). `update_combined_blacklist.yml` (Cron alle 3h) läuft möglicherweise nicht mehr planmäßig - alle Aussagen dieses Berichts basieren auf diesem veralteten Stand.

## Wiederauftauch-Prüfung

❌ **62658 IP(s) gefunden, die laut Ablauf-Liste dauerhaft draussen sein sollten, aber trotzdem in einer aktuellen Output-Datei stehen - der Fix greift hier NICHT wie erwartet:**

| Datei | Anzahl Rückfälle | Beispiele |
|---|---:|---|
| bot_detector_blacklist_ipv4.txt | 29510 | 1.0.0.104, 1.0.171.2, 1.0.215.7, 1.0.227.38, 1.1.187.152, ... |
| honeypot_ips.txt | 34723 | 1.0.218.230, 1.1.202.148, 1.11.62.185, 1.11.62.186, 1.116.214.66, ... |
| honigtopf_ips.txt | 12 | 111.250.240.29, 119.4.109.82, 122.97.137.17, 129.226.193.45, 147.182.205.127, ... |
| tweetfeed_ips.txt | 64 | 1.0.2.0, 103.214.172.14, 115.226.251.119, 123.5.149.113, 13.140.8.25, ... |

## seen_db-Trend

- Seit letztem Lauf: ➡️ unverändert (jetzt 8,772,949 IPs)
- Seit Zyklus-Start (2026-08-23): 📉 -623,090 (Rückgang)
- Letzter combined-Cleanup-Pass: 657,370 IPs durch Ablauf entfernt (davon 657,370 Watchlist/30T, 0 Active/180T), 1,968,228 neue IPs hinzugekommen (davon 1,767,036 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) (zusätzlich: 187,059 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 15,745,824 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 5,258,960 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 5,258,960 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 0 (Summe letzte 8 Läufe / ~24h)
- Erfolgsquote letzte 16 combined-Läufe: 🔍 4/16 erfolgreich (25%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-08-24T07:13 bis 2026-08-24T13:37 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-08-23 19:21 CEST (Europe/Berlin) | 9,406,053 | 0 | 0 | 0 |
| 2026-08-23 21:17 CEST (Europe/Berlin) | 9,406,053 | 0 | 0 | 0 |
| 2026-08-23 21:43 CEST (Europe/Berlin) | 9,411,701 | 0 | 0 | 0 |
| 2026-08-23 22:16 CEST (Europe/Berlin) | 9,411,830 | 0 | 0 | 0 |
| 2026-08-24 00:14 CEST (Europe/Berlin) | 9,415,235 | 0 | 0 | 0 |
| 2026-08-24 03:48 CEST (Europe/Berlin) | 9,416,186 | 0 | 0 | 0 |
| 2026-08-24 04:19 CEST (Europe/Berlin) | 9,416,186 | 0 | 0 | 0 |
| 2026-08-24 05:12 CEST (Europe/Berlin) | 9,416,186 | 0 | 0 | 0 |
| 2026-08-24 06:24 CEST (Europe/Berlin) | 9,416,186 | 0 | 0 | 0 |
| 2026-08-24 06:37 CEST (Europe/Berlin) | 8,772,949 | 657370 | 0 | 62704 |
| 2026-08-24 07:21 CEST (Europe/Berlin) | 8,772,949 | 657370 | 0 | 62683 |
| 2026-08-24 08:06 CEST (Europe/Berlin) | 8,772,949 | 657370 | 0 | 62683 |
| 2026-08-24 09:40 CEST (Europe/Berlin) | 8,772,949 | 657370 | 0 | 62641 |
| 2026-08-24 09:52 CEST (Europe/Berlin) | 8,772,949 | 657370 | 0 | 62641 |
| 2026-08-24 12:30 CEST (Europe/Berlin) | 8,772,949 | 657370 | 0 | 62668 |
| 2026-08-24 12:48 CEST (Europe/Berlin) | 8,772,949 | 657370 | 0 | 62668 |
| 2026-08-24 13:36 CEST (Europe/Berlin) | 8,772,949 | 657370 | 0 | 62656 |
| 2026-08-24 15:05 CEST (Europe/Berlin) | 8,772,949 | 657370 | 0 | 62658 |
| 2026-08-24 15:44 CEST (Europe/Berlin) | 8,772,949 | 657370 | 0 | 62658 |
| 2026-08-24 16:20 CEST (Europe/Berlin) | 8,772,949 | 657370 | 0 | 62658 |
