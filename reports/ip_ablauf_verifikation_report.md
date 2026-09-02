# IP-Ablauf-Verifikationsbericht

Lauf: 2026-09-02 07:18 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 186488 |
| Active (180-Tage-Pfad) | 0 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zaehlt Ledger-Eintraege, deren Anker-Datum (`first` bzw. `last`) + Fenster (30 bzw. 180 Tage) auf dieses Datum faellt (exakt dieselbe Formel wie die Prognose selbst - NICHT `eingefroren_am`, das bei chronisch schwach bestaetigten IPs bei jedem erneuten Ablauf aufgefrischt wird und daher kein verlaesslicher Tages-Marker waere). Da ein Cleanup-Pass ueberfaellige Eintraege ohne feste Tages-Reihenfolge nachholt, kann "heute" laenger bei 0% bleiben, waehrend Rueckstand aus den letzten Tagen erst noch verarbeitet wird - das ist normal, keine Fehlfunktion.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-09-02 (heute) | 2,000 | 0 | 0% |
| 2026-09-03 | 2,000 | 0 | 0% |
| 2026-09-04 | 2,000 | 0 | 0% |
| 2026-09-05 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-09-04 | 173,700 | 0 | 0% |
| 2026-09-05 | 173,689 | 0 | 0% |
| 2026-09-07 | 663,981 | 0 | 0% |
| 2026-09-08 | 663,617 | 0 | 0% |

## Diagnose-Status

❌ **1 Problem(e) erkannt:**

- ❌ **Rückfall:** 176424 eingefrorene IP(s) stehen trotzdem in aktuellen Output-Dateien - der Anti-Churn-Fix greift hier NICHT wie erwartet.

## Wiederauftauch-Prüfung

❌ **176424 IP(s) gefunden, die laut Ablauf-Liste dauerhaft draussen sein sollten, aber trotzdem in einer aktuellen Output-Datei stehen - der Fix greift hier NICHT wie erwartet (Issue-Alarm ausgeloest, Schwelle 300):**

| Datei | Anzahl Rückfälle | Beispiele |
|---|---:|---|
| active_blacklist_ipv4.txt | 102 | 101.53.250.20, 103.160.234.194, 103.182.69.27, 103.82.252.62, 104.207.57.110, ... |
| combined_threat_blacklist_ipv4_part1.txt | 83234 | 1.0.137.182, 1.1.176.123, 1.1.197.87, 1.1.221.157, 1.1.245.219, ... |
| combined_threat_blacklist_ipv4_part2.txt | 93190 | 112.132.172.196, 112.132.212.252, 112.132.249.126, 112.133.195.17, 112.133.195.52, ... |
| blacklist_confidence40_ipv4_part1.txt | 102 | 101.53.250.20, 103.160.234.194, 103.182.69.27, 103.82.252.62, 104.207.57.110, ... |

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen Ledger-Eintraege ab (nach Anker-Datum + Fenster gruppiert, dieselbe Formel wie die jeweilige Prognose: `first`+31 Tage fuer Watchlist, `last`+181 Tage fuer Active), sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-08-30 | 10,066 | 0 | 10,066 | 100.0% |
| 2026-08-31 | 5,240 | 9,838 | 0 | 0.0% |
| 2026-09-01 | 52,949 | 0 | 52,949 | 100.0% |

_31 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

Noch keine aufgeloesten Tage - entweder laeuft der Job "prognose" noch nicht lange genug, oder es ist noch kein vorhergesagtes Active-Ablaufdatum vergangen (aktuell zeigt die Active-Liste konstant 0, siehe oben - das 180-Tage-Fenster hat noch nicht scharf geschaltet).

_46 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: 📈 +3,164 (Anstieg) (jetzt 11,096,250 IPs)
- Seit Zyklus-Start (2026-08-23): 📈 +1,700,211 (Anstieg)
- Letzter combined-Cleanup-Pass: 0 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 0 Active/180T), 1,023,829 neue IPs hinzugekommen (davon 827,952 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 222 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 197,271 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 9,945,369 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 4,000 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 4,000 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 0 (Summe letzte 8 Läufe / ~24h)
- Netto-Wachstum (~24h): 📈 +1,286,837 (~24h)
- Erfolgsquote letzte 16 combined-Läufe: 15/15 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt) | zusätzlich 1 cancelled (nicht gewertet), Zeitraum 2026-09-01T14:13 bis 2026-09-02T05:05 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
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
| 2026-09-01 21:04 CEST (Europe/Berlin) | 9,829,710 | 207341 | 0 | 95 |
| 2026-09-02 01:35 CEST (Europe/Berlin) | 11,089,134 | 186490 | 0 | 101 |
| 2026-09-02 01:42 CEST (Europe/Berlin) | 11,089,134 | 186490 | 0 | 101 |
| 2026-09-02 06:13 CEST (Europe/Berlin) | 11,093,086 | 186489 | 0 | 176369 |
| 2026-09-02 07:18 CEST (Europe/Berlin) | 11,096,250 | 186488 | 0 | 176424 |
