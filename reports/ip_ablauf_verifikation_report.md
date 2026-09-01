# IP-Ablauf-Verifikationsbericht

Lauf: 2026-09-01 20:24 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 207346 |
| Active (180-Tage-Pfad) | 0 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zaehlt Ledger-Eintraege, deren Anker-Datum (`first` bzw. `last`) + Fenster (30 bzw. 180 Tage) auf dieses Datum faellt (exakt dieselbe Formel wie die Prognose selbst - NICHT `eingefroren_am`, das bei chronisch schwach bestaetigten IPs bei jedem erneuten Ablauf aufgefrischt wird und daher kein verlaesslicher Tages-Marker waere). Da ein Cleanup-Pass ueberfaellige Eintraege ohne feste Tages-Reihenfolge nachholt, kann "heute" laenger bei 0% bleiben, waehrend Rueckstand aus den letzten Tagen erst noch verarbeitet wird - das ist normal, keine Fehlfunktion.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-09-01 (heute) | 52,949 | 0 | 0% |
| 2026-09-02 | 9,332 | 0 | 0% |
| 2026-09-03 | 10,975 | 0 | 0% |
| 2026-09-04 | 148,148 | 0 | 0% |

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-09-04 | 173,700 | 0 | 0% |
| 2026-09-05 | 173,692 | 0 | 0% |
| 2026-09-07 | 663,981 | 0 | 0% |
| 2026-09-08 | 663,731 | 0 | 0% |

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **176,906 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 227,569 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-09-01). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

⚠️ **85 IP(s) gefunden, die laut Ablauf-Liste dauerhaft draussen sein sollten, aber trotzdem in einer aktuellen Output-Datei stehen** - liegt unter der Alarm-Schwelle (300), daher KEIN Issue-Alarm. Laut Bug-21-Diagnose (ledger_diagnose.yml) vermutlich eine kurzlebige Sync-Verzoegerung, keine echte Regression:

| Datei | Anzahl Rückfälle | Beispiele |
|---|---:|---|
| active_blacklist_ipv4.txt | 85 | 101.53.250.20, 103.160.234.194, 103.182.69.27, 104.207.57.110, 104.207.57.255, ... |
| combined_threat_blacklist_ipv4_part1.txt | 42 | 101.53.250.20, 103.160.234.194, 103.182.69.27, 104.207.57.110, 104.207.57.255, ... |
| combined_threat_blacklist_ipv4_part2.txt | 43 | 118.96.142.15, 119.156.228.186, 122.167.158.186, 122.183.40.107, 122.252.253.2, ... |
| blacklist_confidence40_ipv4_part1.txt | 85 | 101.53.250.20, 103.160.234.194, 103.182.69.27, 104.207.57.110, 104.207.57.255, ... |

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

- Seit letztem Lauf: 📈 +4,865 (Anstieg) (jetzt 9,824,674 IPs)
- Seit Zyklus-Start (2026-08-23): 📈 +428,635 (Anstieg)
- Letzter combined-Cleanup-Pass: 0 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 0 Active/180T), 1,809,271 neue IPs hinzugekommen (davon 1,633,447 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 47 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 195,767 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 14,432,435 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 4,000 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 4,000 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 0 (Summe letzte 8 Läufe / ~24h)
- Netto-Wachstum (~24h): 📈 +33,023 (~24h)
- Erfolgsquote letzte 16 combined-Läufe: 15/15 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt) | 1 sonstige, Zeitraum 2026-08-31T21:22 bis 2026-09-01T18:22 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
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
| 2026-09-01 11:02 CEST (Europe/Berlin) | 9,809,413 | 207351 | 0 | 25 |
| 2026-09-01 16:25 CEST (Europe/Berlin) | 9,819,809 | 207350 | 0 | 77 |
| 2026-09-01 20:24 CEST (Europe/Berlin) | 9,824,674 | 207346 | 0 | 85 |
