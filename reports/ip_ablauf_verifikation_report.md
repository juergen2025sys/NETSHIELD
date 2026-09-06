# IP-Ablauf-Verifikationsbericht

Lauf: 2026-09-06 22:58 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 186481 |
| Active (180-Tage-Pfad) | 173624 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zeigt jetzt die TATSAECHLICH an diesem Kalendertag vom Combined-Lauf entfernten IPs (`expired_watchlist` bzw. `expired_active`). Damit werden Watchlist-Rueckstaende durch den 2.000/Tag-Deckel korrekt dem realen Entfernungstag zugerechnet. Dieselbe Ist-Logik gilt fuer Active/180T, damit auch verspaetete Cleanup-Laeufe nicht dem theoretischen Faelligkeitsdatum zugeschrieben werden.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-09-06 (heute) | 2,000 | 0 | 0% |
| 2026-09-07 | 2,000 | 0 | 0% |
| 2026-09-08 | 2,000 | 0 | 0% |
| 2026-09-09 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-09-07 | 663,981 | 0 | 0% |
| 2026-09-08 | 662,577 | 0 | 0% |
| 2026-09-21 | 6,509 | 0 | 0% |
| 2026-09-22 | 6,482 | 0 | 0% |

## Diagnose-Status

❌ **1 Problem(e) erkannt:**

- ❌ **Rückfall:** 300 eingefrorene IP(s) stehen trotzdem in aktuellen Output-Dateien - der Anti-Churn-Fix greift hier NICHT wie erwartet.

## Wiederauftauch-Prüfung

ℹ️ **247 Treffer sind legitime Active→Watchlist-Wiedereintritte und kein Anti-Churn-Rückfall.** Diese IPs stehen noch im Active-Ledger, wurden aber nur schwach neu bestätigt und erscheinen deshalb in konsolidierten Watchlist/Combined-Ausgaben, nicht jedoch in `active_blacklist_ipv4.txt`. Der eingefrorene Active-Anker bleibt erhalten; erst eine echte starke Neubestätigung darf wieder einen neuen 180-Tage-Active-Pfad starten.

ℹ️ **176,529 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 432,574 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-09-06). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

❌ **300 IP(s) gefunden, die laut Ablauf-Liste dauerhaft draussen sein sollten, aber trotzdem in einer aktuellen Output-Datei stehen - der Fix greift hier NICHT wie erwartet (Issue-Alarm ausgeloest, Schwelle 300):**

| Datei | Anzahl Rückfälle | Beispiele |
|---|---:|---|
| active_blacklist_ipv4.txt | 300 | 101.53.250.20, 102.129.153.207, 102.129.56.183, 102.165.52.148, 102.64.41.246, ... |
| combined_threat_blacklist_ipv4_part1.txt | 143 | 101.53.250.20, 102.129.153.207, 102.129.56.183, 102.165.52.148, 102.64.41.246, ... |
| combined_threat_blacklist_ipv4_part2.txt | 157 | 112.104.64.155, 113.161.44.1, 113.23.35.151, 113.57.184.205, 115.186.103.226, ... |
| blacklist_confidence40_ipv4_part1.txt | 295 | 101.53.250.20, 102.129.153.207, 102.129.56.183, 102.165.52.148, 102.64.41.246, ... |

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
| 2026-09-05 | 2,000 | 0 | 2,000 | 100.0% |

_31 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-09-04 | 173,700 | 0 | 173,700 | 100.0% |
| 2026-09-05 | 173,665 | 173,637 | 28 | 0.0% |

_48 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: 📈 +5,228 (Anstieg) (jetzt 11,155,666 IPs)
- Seit Zyklus-Start (2026-08-23): 📈 +1,759,627 (Anstieg)
- Letzter combined-Cleanup-Pass: 155,405 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 155,405 Active/180T), 1,015,828 neue IPs hinzugekommen (davon 826,179 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 14 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 188,675 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 8,173,389 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 1,243,544 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 0 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 1,243,544 (Summe letzte 8 Läufe / ~24h)
- Netto-Wachstum (~24h): 📈 +43,258 (~24h)
- Erfolgsquote letzte 16 combined-Läufe: 15/16 erfolgreich (94%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-09-06T01:05 bis 2026-09-06T20:50 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-09-05 06:54 CEST (Europe/Berlin) | 11,035,985 | 186482 | 173662 | 436 |
| 2026-09-05 07:07 CEST (Europe/Berlin) | 11,035,985 | 186482 | 173662 | 436 |
| 2026-09-05 10:59 CEST (Europe/Berlin) | 11,038,257 | 186482 | 173661 | 445 |
| 2026-09-05 13:04 CEST (Europe/Berlin) | 11,039,912 | 186482 | 173660 | 447 |
| 2026-09-05 14:38 CEST (Europe/Berlin) | 11,039,912 | 186482 | 173660 | 226 |
| 2026-09-05 14:43 CEST (Europe/Berlin) | 11,039,912 | 186482 | 173660 | 226 |
| 2026-09-05 17:44 CEST (Europe/Berlin) | 11,048,546 | 186482 | 173654 | 257 |
| 2026-09-05 19:49 CEST (Europe/Berlin) | 11,051,745 | 186482 | 173654 | 258 |
| 2026-09-05 22:43 CEST (Europe/Berlin) | 11,053,966 | 186482 | 173654 | 259 |
| 2026-09-05 22:50 CEST (Europe/Berlin) | 11,053,966 | 186482 | 173654 | 259 |
| 2026-09-06 00:49 CEST (Europe/Berlin) | 11,101,732 | 186482 | 173637 | 270 |
| 2026-09-06 01:28 CEST (Europe/Berlin) | 11,101,732 | 186482 | 173637 | 270 |
| 2026-09-06 07:21 CEST (Europe/Berlin) | 11,112,408 | 186482 | 173637 | 275 |
| 2026-09-06 12:48 CEST (Europe/Berlin) | 11,118,199 | 186481 | 173637 | 277 |
| 2026-09-06 13:27 CEST (Europe/Berlin) | 11,118,199 | 186481 | 173637 | 277 |
| 2026-09-06 16:08 CEST (Europe/Berlin) | 11,124,841 | 186481 | 173633 | 289 |
| 2026-09-06 17:55 CEST (Europe/Berlin) | 11,130,332 | 186481 | 173632 | 292 |
| 2026-09-06 20:09 CEST (Europe/Berlin) | 11,128,881 | 186481 | 173632 | 292 |
| 2026-09-06 21:30 CEST (Europe/Berlin) | 11,150,438 | 186481 | 173626 | 295 |
| 2026-09-06 22:58 CEST (Europe/Berlin) | 11,155,666 | 186481 | 173624 | 300 |
