# IP-Ablauf-Verifikationsbericht

Lauf: 2026-09-03 21:25 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 186486 |
| Active (180-Tage-Pfad) | 0 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zaehlt Ledger-Eintraege, deren Anker-Datum (`first` bzw. `last`) + Fenster (30 bzw. 180 Tage) auf dieses Datum faellt (exakt dieselbe Formel wie die Prognose selbst - NICHT `eingefroren_am`, das bei chronisch schwach bestaetigten IPs bei jedem erneuten Ablauf aufgefrischt wird und daher kein verlaesslicher Tages-Marker waere). Da ein Cleanup-Pass ueberfaellige Eintraege ohne feste Tages-Reihenfolge nachholt, kann "heute" laenger bei 0% bleiben, waehrend Rueckstand aus den letzten Tagen erst noch verarbeitet wird - das ist normal, keine Fehlfunktion.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-09-03 (heute) | 2,000 | 0 | 0% |
| 2026-09-04 | 2,000 | 0 | 0% |
| 2026-09-05 | 2,000 | 0 | 0% |
| 2026-09-06 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-09-04 | 173,700 | 0 | 0% |
| 2026-09-05 | 173,675 | 0 | 0% |
| 2026-09-07 | 663,981 | 0 | 0% |
| 2026-09-08 | 663,271 | 0 | 0% |

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **176,406 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 183,671 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-09-03). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

⚠️ **163 IP(s) gefunden, die laut Ablauf-Liste dauerhaft draussen sein sollten, aber trotzdem in einer aktuellen Output-Datei stehen** - liegt unter der Alarm-Schwelle (300), daher KEIN Issue-Alarm. Laut Bug-21-Diagnose (ledger_diagnose.yml) vermutlich eine kurzlebige Sync-Verzoegerung, keine echte Regression:

| Datei | Anzahl Rückfälle | Beispiele |
|---|---:|---|
| active_blacklist_ipv4.txt | 163 | 101.53.250.20, 102.129.56.183, 103.125.37.253, 103.160.234.194, 103.182.69.27, ... |
| combined_threat_blacklist_ipv4_part1.txt | 70 | 101.53.250.20, 102.129.56.183, 103.125.37.253, 103.160.234.194, 103.182.69.27, ... |
| combined_threat_blacklist_ipv4_part2.txt | 93 | 113.23.35.151, 115.186.103.226, 115.241.25.146, 118.96.142.15, 119.152.22.139, ... |
| blacklist_confidence40_ipv4_part1.txt | 158 | 101.53.250.20, 103.125.37.253, 103.160.234.194, 103.182.69.27, 103.82.252.62, ... |

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen Ledger-Eintraege ab (nach Anker-Datum + Fenster gruppiert, dieselbe Formel wie die jeweilige Prognose: `first`+31 Tage fuer Watchlist, `last`+181 Tage fuer Active), sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-08-30 | 10,066 | 0 | 10,066 | 100.0% |
| 2026-08-31 | 5,240 | 9,838 | 0 | 0.0% |
| 2026-09-01 | 52,949 | 0 | 52,949 | 100.0% |
| 2026-09-02 | 2,000 | 0 | 2,000 | 100.0% |

_31 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

Noch keine aufgeloesten Tage - entweder laeuft der Job "prognose" noch nicht lange genug, oder es ist noch kein vorhergesagtes Active-Ablaufdatum vergangen (aktuell zeigt die Active-Liste konstant 0, siehe oben - das 180-Tage-Fenster hat noch nicht scharf geschaltet).

_47 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: 📈 +5,629 (Anstieg) (jetzt 11,160,186 IPs)
- Seit Zyklus-Start (2026-08-23): 📈 +1,764,147 (Anstieg)
- Letzter combined-Cleanup-Pass: 0 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 0 Active/180T), 1,023,675 neue IPs hinzugekommen (davon 829,774 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 80 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 192,716 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 8,030,491 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 2,000 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 2,000 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 0 (Summe letzte 8 Läufe / ~24h)
- Netto-Wachstum (~24h): 📈 +34,594 (~24h)
- Erfolgsquote letzte 16 combined-Läufe: 15/15 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt) | zusätzlich 1 cancelled (nicht gewertet), Zeitraum 2026-09-02T23:33 bis 2026-09-03T19:03 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-09-02 01:35 CEST (Europe/Berlin) | 11,089,134 | 186490 | 0 | 101 |
| 2026-09-02 01:42 CEST (Europe/Berlin) | 11,089,134 | 186490 | 0 | 101 |
| 2026-09-02 06:13 CEST (Europe/Berlin) | 11,093,086 | 186489 | 0 | 176369 |
| 2026-09-02 07:18 CEST (Europe/Berlin) | 11,096,250 | 186488 | 0 | 176424 |
| 2026-09-02 11:01 CEST (Europe/Berlin) | 11,100,052 | 186488 | 0 | 176436 |
| 2026-09-02 13:53 CEST (Europe/Berlin) | 11,104,068 | 186488 | 0 | 176447 |
| 2026-09-02 15:36 CEST (Europe/Berlin) | 11,107,873 | 186488 | 0 | 176452 |
| 2026-09-02 18:56 CEST (Europe/Berlin) | 11,109,436 | 186488 | 0 | 176452 |
| 2026-09-02 19:53 CEST (Europe/Berlin) | 11,138,217 | 186488 | 0 | 176786 |
| 2026-09-02 23:15 CEST (Europe/Berlin) | 11,148,706 | 186488 | 0 | 176803 |
| 2026-09-02 23:28 CEST (Europe/Berlin) | 11,148,706 | 186488 | 0 | 176803 |
| 2026-09-03 01:17 CEST (Europe/Berlin) | 11,148,706 | 186488 | 0 | 176803 |
| 2026-09-03 01:44 CEST (Europe/Berlin) | 11,125,592 | 186488 | 0 | 122 |
| 2026-09-03 03:25 CEST (Europe/Berlin) | 11,128,935 | 186488 | 0 | 122 |
| 2026-09-03 07:23 CEST (Europe/Berlin) | 11,136,036 | 186488 | 0 | 126 |
| 2026-09-03 13:40 CEST (Europe/Berlin) | 11,145,357 | 186488 | 0 | 136 |
| 2026-09-03 13:51 CEST (Europe/Berlin) | 11,145,357 | 186488 | 0 | 136 |
| 2026-09-03 18:21 CEST (Europe/Berlin) | 11,152,005 | 186486 | 0 | 155 |
| 2026-09-03 18:48 CEST (Europe/Berlin) | 11,154,557 | 186486 | 0 | 158 |
| 2026-09-03 21:25 CEST (Europe/Berlin) | 11,160,186 | 186486 | 0 | 163 |
