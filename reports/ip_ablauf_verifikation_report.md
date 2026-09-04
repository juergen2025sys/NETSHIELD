# IP-Ablauf-Verifikationsbericht

Lauf: 2026-09-05 00:19 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 186484 |
| Active (180-Tage-Pfad) | 0 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zeigt jetzt die TATSAECHLICH an diesem Kalendertag vom Combined-Lauf entfernten IPs (`expired_watchlist` bzw. `expired_active`). Damit werden Watchlist-Rueckstaende durch den 2.000/Tag-Deckel korrekt dem realen Entfernungstag zugerechnet. Dieselbe Ist-Logik gilt fuer Active/180T, damit auch verspaetete Cleanup-Laeufe nicht dem theoretischen Faelligkeitsdatum zugeschrieben werden.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-09-05 (heute) | 2,000 | 2,000 | 100% |
| 2026-09-06 | 2,000 | 0 | 0% |
| 2026-09-07 | 2,000 | 0 | 0% |
| 2026-09-08 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-09-05 (heute) | 173,665 | 0 | 0% |
| 2026-09-07 | 663,981 | 0 | 0% |
| 2026-09-08 | 663,029 | 0 | 0% |
| 2026-09-21 | 6,509 | 0 | 0% |

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **174,449 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 342,781 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-09-05). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

⚠️ **206 IP(s) gefunden, die laut Ablauf-Liste dauerhaft draussen sein sollten, aber trotzdem in einer aktuellen Output-Datei stehen** - liegt unter der Alarm-Schwelle (300), daher KEIN Issue-Alarm. Laut Bug-21-Diagnose (ledger_diagnose.yml) vermutlich eine kurzlebige Sync-Verzoegerung, keine echte Regression:

| Datei | Anzahl Rückfälle | Beispiele |
|---|---:|---|
| active_blacklist_ipv4.txt | 206 | 101.53.250.20, 102.129.56.183, 102.64.41.246, 102.88.111.27, 103.125.37.253, ... |
| combined_threat_blacklist_ipv4_part1.txt | 89 | 101.53.250.20, 102.129.56.183, 102.64.41.246, 102.88.111.27, 103.125.37.253, ... |
| combined_threat_blacklist_ipv4_part2.txt | 117 | 113.161.44.1, 113.23.35.151, 113.57.184.205, 115.186.103.226, 115.241.25.146, ... |
| blacklist_confidence40_ipv4_part1.txt | 206 | 101.53.250.20, 102.129.56.183, 102.64.41.246, 102.88.111.27, 103.125.37.253, ... |

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen Ledger-Eintraege ab (nach Anker-Datum + Fenster gruppiert, dieselbe Formel wie die jeweilige Prognose: `first`+31 Tage fuer Watchlist, `last`+181 Tage fuer Active), sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-08-30 | 10,066 | 0 | 10,066 | 100.0% |
| 2026-08-31 | 5,240 | 9,838 | 0 | 0.0% |
| 2026-09-01 | 52,949 | 0 | 52,949 | 100.0% |
| 2026-09-02 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-03 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-04 | 2,000 | 0 | 2,000 | 100.0% |

_30 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-09-04 | 173,700 | 0 | 173,700 | 100.0% |

_47 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: 📉 -780 (Rückgang) (jetzt 11,196,359 IPs)
- Seit Zyklus-Start (2026-08-23): 📈 +1,800,320 (Anstieg)
- Letzter combined-Cleanup-Pass: 2,000 IPs durch Ablauf entfernt (davon 2,000 Watchlist/30T, 0 Active/180T), 1,014,662 neue IPs hinzugekommen (davon 829,109 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 11 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 188,668 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): n/a (7/8 Läufe im Fenster mit Daten)
- Entfernte IPs (Summe letzter Läufe): n/a (7/8 Läufe im Fenster mit Daten)
  - davon Watchlist/30 Tage: n/a (7/8 Läufe im Fenster mit Daten)
  - davon Active/180 Tage: n/a (7/8 Läufe im Fenster mit Daten)
- Netto-Wachstum (~24h): 📈 +18,594 (~24h)
- Erfolgsquote letzte 16 combined-Läufe: 15/15 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt) | zusätzlich 1 cancelled (nicht gewertet), Zeitraum 2026-09-04T05:07 bis 2026-09-04T22:00 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-09-03 01:44 CEST (Europe/Berlin) | 11,125,592 | 186488 | 0 | 122 |
| 2026-09-03 03:25 CEST (Europe/Berlin) | 11,128,935 | 186488 | 0 | 122 |
| 2026-09-03 07:23 CEST (Europe/Berlin) | 11,136,036 | 186488 | 0 | 126 |
| 2026-09-03 13:40 CEST (Europe/Berlin) | 11,145,357 | 186488 | 0 | 136 |
| 2026-09-03 13:51 CEST (Europe/Berlin) | 11,145,357 | 186488 | 0 | 136 |
| 2026-09-03 18:21 CEST (Europe/Berlin) | 11,152,005 | 186486 | 0 | 155 |
| 2026-09-03 18:48 CEST (Europe/Berlin) | 11,154,557 | 186486 | 0 | 158 |
| 2026-09-03 21:25 CEST (Europe/Berlin) | 11,160,186 | 186486 | 0 | 163 |
| 2026-09-03 23:32 CEST (Europe/Berlin) | 11,166,211 | 186486 | 0 | 167 |
| 2026-09-04 01:43 CEST (Europe/Berlin) | 11,165,432 | 186486 | 0 | 168 |
| 2026-09-04 06:16 CEST (Europe/Berlin) | 11,171,181 | 186486 | 0 | 173 |
| 2026-09-04 07:17 CEST (Europe/Berlin) | 11,176,453 | 186486 | 0 | 173 |
| 2026-09-04 11:03 CEST (Europe/Berlin) | 11,177,765 | 186486 | 0 | 176 |
| 2026-09-04 13:54 CEST (Europe/Berlin) | 11,181,320 | 186484 | 0 | 183 |
| 2026-09-04 15:30 CEST (Europe/Berlin) | 11,181,320 | 186484 | 0 | 183 |
| 2026-09-04 15:57 CEST (Europe/Berlin) | 11,181,320 | 186484 | 0 | 183 |
| 2026-09-04 18:41 CEST (Europe/Berlin) | 11,191,370 | 186484 | 0 | 204 |
| 2026-09-04 21:53 CEST (Europe/Berlin) | 11,195,318 | 186484 | 0 | 206 |
| 2026-09-04 23:10 CEST (Europe/Berlin) | 11,197,139 | 186484 | 0 | 206 |
| 2026-09-05 00:19 CEST (Europe/Berlin) | 11,196,359 | 186484 | 0 | 206 |
