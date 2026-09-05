# IP-Ablauf-Verifikationsbericht

Lauf: 2026-09-06 00:49 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 186482 |
| Active (180-Tage-Pfad) | 173637 |

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
| 2026-09-08 | 662,760 | 0 | 0% |
| 2026-09-21 | 6,509 | 0 | 0% |
| 2026-09-22 | 6,486 | 0 | 0% |

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **221 Treffer sind legitime Active→Watchlist-Wiedereintritte und kein Anti-Churn-Rückfall.** Diese IPs stehen noch im Active-Ledger, wurden aber nur schwach neu bestätigt und erscheinen deshalb in konsolidierten Watchlist/Combined-Ausgaben, nicht jedoch in `active_blacklist_ipv4.txt`. Der eingefrorene Active-Anker bleibt erhalten; erst eine echte starke Neubestätigung darf wieder einen neuen 180-Tage-Active-Pfad starten.

ℹ️ **176,516 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 342,781 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-09-05). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

⚠️ **270 IP(s) gefunden, die laut Ablauf-Liste dauerhaft draussen sein sollten, aber trotzdem in einer aktuellen Output-Datei stehen** - liegt unter der Alarm-Schwelle (300), daher KEIN Issue-Alarm. Laut Bug-21-Diagnose (ledger_diagnose.yml) vermutlich eine kurzlebige Sync-Verzoegerung, keine echte Regression:

| Datei | Anzahl Rückfälle | Beispiele |
|---|---:|---|
| active_blacklist_ipv4.txt | 270 | 101.53.250.20, 102.129.153.207, 102.129.56.183, 102.165.52.148, 102.64.41.246, ... |
| combined_threat_blacklist_ipv4_part1.txt | 128 | 101.53.250.20, 102.129.153.207, 102.129.56.183, 102.165.52.148, 102.64.41.246, ... |
| combined_threat_blacklist_ipv4_part2.txt | 142 | 112.104.64.155, 113.161.44.1, 113.23.35.151, 113.57.184.205, 115.186.103.226, ... |
| blacklist_confidence40_ipv4_part1.txt | 270 | 101.53.250.20, 102.129.153.207, 102.129.56.183, 102.165.52.148, 102.64.41.246, ... |

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

_30 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-09-04 | 173,700 | 0 | 173,700 | 100.0% |
| 2026-09-05 | 173,665 | 173,637 | 28 | 0.0% |

_47 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: 📈 +47,766 (Anstieg) (jetzt 11,101,732 IPs)
- Seit Zyklus-Start (2026-08-23): 📈 +1,705,693 (Anstieg)
- Letzter combined-Cleanup-Pass: 155,511 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 155,511 Active/180T), 977,818 neue IPs hinzugekommen (davon 795,083 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) (zusätzlich: 186,313 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 8,083,905 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 1,243,863 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 0 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 1,243,863 (Summe letzte 8 Läufe / ~24h)
- Netto-Wachstum (~24h): 📈 +61,820 (~24h)
- Erfolgsquote letzte 16 combined-Läufe: 16/16 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-09-05T10:28 bis 2026-09-05T22:48 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-09-04 13:54 CEST (Europe/Berlin) | 11,181,320 | 186484 | 0 | 183 |
| 2026-09-04 15:30 CEST (Europe/Berlin) | 11,181,320 | 186484 | 0 | 183 |
| 2026-09-04 15:57 CEST (Europe/Berlin) | 11,181,320 | 186484 | 0 | 183 |
| 2026-09-04 18:41 CEST (Europe/Berlin) | 11,191,370 | 186484 | 0 | 204 |
| 2026-09-04 21:53 CEST (Europe/Berlin) | 11,195,318 | 186484 | 0 | 206 |
| 2026-09-04 23:10 CEST (Europe/Berlin) | 11,197,139 | 186484 | 0 | 206 |
| 2026-09-05 00:19 CEST (Europe/Berlin) | 11,196,359 | 186484 | 0 | 206 |
| 2026-09-05 01:35 CEST (Europe/Berlin) | 11,196,359 | 186484 | 0 | 206 |
| 2026-09-05 05:46 CEST (Europe/Berlin) | 11,028,327 | 186482 | 173663 | 221 |
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
