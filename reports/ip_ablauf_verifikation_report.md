# IP-Ablauf-Verifikationsbericht

Lauf: 2026-09-01 06:06 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 207353 |
| Active (180-Tage-Pfad) | 0 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zaehlt Ledger-Eintraege, deren Anker-Datum (`first` bzw. `last`) + Fenster (30 bzw. 180 Tage) auf dieses Datum faellt (exakt dieselbe Formel wie die Prognose selbst - NICHT `eingefroren_am`, das bei chronisch schwach bestaetigten IPs bei jedem erneuten Ablauf aufgefrischt wird und daher kein verlaesslicher Tages-Marker waere). Da ein Cleanup-Pass ueberfaellige Eintraege ohne feste Tages-Reihenfolge nachholt, kann "heute" laenger bei 0% bleiben, waehrend Rueckstand aus den letzten Tagen erst noch verarbeitet wird - das ist normal, keine Fehlfunktion.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-09-01 (heute) | 52,971 | 0 | 0% |
| 2026-09-02 | 9,342 | 0 | 0% |
| 2026-09-03 | 10,983 | 0 | 0% |
| 2026-09-04 | 148,174 | 0 | 0% |

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-09-04 | 173,700 | 0 | 0% |
| 2026-09-05 | 173,699 | 0 | 0% |
| 2026-09-07 | 663,981 | 0 | 0% |
| 2026-09-08 | 663,918 | 0 | 0% |

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **174,598 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 227,569 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-09-01). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

⚠️ **12 IP(s) gefunden, die laut Ablauf-Liste dauerhaft draussen sein sollten, aber trotzdem in einer aktuellen Output-Datei stehen** - liegt unter der Alarm-Schwelle (300), daher KEIN Issue-Alarm. Laut Bug-21-Diagnose (ledger_diagnose.yml) vermutlich eine kurzlebige Sync-Verzoegerung, keine echte Regression:

| Datei | Anzahl Rückfälle | Beispiele |
|---|---:|---|
| active_blacklist_ipv4.txt | 12 | 122.167.158.186, 122.183.40.107, 122.252.253.2, 123.14.124.135, 137.184.125.181, ... |
| combined_threat_blacklist_ipv4_part1.txt | 4 | 45.181.120.48, 58.84.62.78, 91.151.136.181, 91.236.157.136 |
| combined_threat_blacklist_ipv4_part2.txt | 8 | 122.167.158.186, 122.183.40.107, 122.252.253.2, 123.14.124.135, 137.184.125.181, ... |
| blacklist_confidence40_ipv4_part1.txt | 12 | 122.167.158.186, 122.183.40.107, 122.252.253.2, 123.14.124.135, 137.184.125.181, ... |

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen Ledger-Eintraege ab (nach Anker-Datum + Fenster gruppiert, dieselbe Formel wie die jeweilige Prognose: `first`+31 Tage fuer Watchlist, `last`+181 Tage fuer Active), sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-08-30 | 10,066 | 0 | 10,066 | 100.0% |
| 2026-08-31 | 5,240 | 9,838 | 0 | 0.0% |

_31 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

Noch keine aufgeloesten Tage - entweder laeuft der Job "prognose" noch nicht lange genug, oder es ist noch kein vorhergesagtes Active-Ablaufdatum vergangen (aktuell zeigt die Active-Liste konstant 0, siehe oben - das 180-Tage-Fenster hat noch nicht scharf geschaltet).

_45 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: ➡️ unverändert (jetzt 9,796,731 IPs)
- Seit Zyklus-Start (2026-08-23): 📈 +400,692 (Anstieg)
- Letzter combined-Cleanup-Pass: 2,000 IPs durch Ablauf entfernt (davon 2,000 Watchlist/30T, 0 Active/180T), 1,802,404 neue IPs hinzugekommen (davon 1,635,618 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 19 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 188,506 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 14,365,439 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 533,801 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 533,801 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 0 (Summe letzte 8 Läufe / ~24h)
- Netto-Wachstum (~24h): 📈 +207,475 (~24h)
- Erfolgsquote letzte 16 combined-Läufe: 14/14 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt) | zusätzlich 2 cancelled (nicht gewertet), Zeitraum 2026-08-31T12:34 bis 2026-09-01T00:47 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-08-30 13:39 CEST (Europe/Berlin) | 9,593,508 | 197532 | 0 | 0 |
| 2026-08-30 13:48 CEST (Europe/Berlin) | 9,593,508 | 197532 | 0 | 0 |
| 2026-08-30 14:06 CEST (Europe/Berlin) | 9,593,508 | 197532 | 0 | 0 |
| 2026-08-30 14:21 CEST (Europe/Berlin) | 9,593,508 | 197532 | 0 | 0 |
| 2026-08-30 14:28 CEST (Europe/Berlin) | 9,593,508 | 197532 | 0 | 0 |
| 2026-08-30 17:21 CEST (Europe/Berlin) | 9,597,703 | 197527 | 0 | 0 |
| 2026-08-30 19:06 CEST (Europe/Berlin) | 9,599,977 | 197523 | 0 | 0 |
| 2026-08-30 23:46 CEST (Europe/Berlin) | 9,586,079 | 199291 | 0 | 2 |
| 2026-08-30 23:57 CEST (Europe/Berlin) | 9,586,079 | 199291 | 0 | 2 |
| 2026-08-31 02:05 CEST (Europe/Berlin) | 9,589,730 | 197628 | 0 | 2 |
| 2026-08-31 02:26 CEST (Europe/Berlin) | 9,589,730 | 197628 | 0 | 2 |
| 2026-08-31 08:04 CEST (Europe/Berlin) | 9,589,256 | 207447 | 0 | 2 |
| 2026-08-31 08:29 CEST (Europe/Berlin) | 9,589,256 | 207447 | 0 | 2 |
| 2026-08-31 15:38 CEST (Europe/Berlin) | 9,607,940 | 207363 | 0 | 2 |
| 2026-08-31 16:41 CEST (Europe/Berlin) | 9,607,940 | 207363 | 0 | 2 |
| 2026-08-31 22:00 CEST (Europe/Berlin) | 9,791,651 | 207354 | 0 | 176575 |
| 2026-08-31 23:14 CEST (Europe/Berlin) | 9,791,651 | 207354 | 0 | 176575 |
| 2026-09-01 01:48 CEST (Europe/Berlin) | 9,795,135 | 207354 | 0 | 176590 |
| 2026-09-01 02:56 CEST (Europe/Berlin) | 9,796,731 | 207353 | 0 | 12 |
| 2026-09-01 06:06 CEST (Europe/Berlin) | 9,796,731 | 207353 | 0 | 12 |
