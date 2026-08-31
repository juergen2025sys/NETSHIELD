# IP-Ablauf-Verifikationsbericht

Lauf: 2026-08-31 15:38 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 207363 |
| Active (180-Tage-Pfad) | 0 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zaehlt Ledger-Eintraege, deren Anker-Datum (`first` bzw. `last`) + Fenster (30 bzw. 180 Tage) auf dieses Datum faellt (exakt dieselbe Formel wie die Prognose selbst - NICHT `eingefroren_am`, das bei chronisch schwach bestaetigten IPs bei jedem erneuten Ablauf aufgefrischt wird und daher kein verlaesslicher Tages-Marker waere). Da ein Cleanup-Pass ueberfaellige Eintraege ohne feste Tages-Reihenfolge nachholt, kann "heute" laenger bei 0% bleiben, waehrend Rueckstand aus den letzten Tagen erst noch verarbeitet wird - das ist normal, keine Fehlfunktion.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-08-31 (heute) | 52,975 | 0 | 0% |
| 2026-09-01 | 9,350 | 0 | 0% |
| 2026-09-02 | 10,986 | 0 | 0% |
| 2026-09-03 | 148,182 | 0 | 0% |

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-09-04 | 173,700 | 0 | 0% |
| 2026-09-07 | 663,981 | 0 | 0% |
| 2026-09-21 | 6,509 | 0 | 0% |
| 2026-09-22 | 13,226 | 0 | 0% |

## Diagnose-Status

❌ **1 Problem(e) erkannt:**

- ❌ **Rückfall:** 2 eingefrorene IP(s) stehen trotzdem in aktuellen Output-Dateien - der Anti-Churn-Fix greift hier NICHT wie erwartet.

## Wiederauftauch-Prüfung

❌ **2 IP(s) gefunden, die laut Ablauf-Liste dauerhaft draussen sein sollten, aber trotzdem in einer aktuellen Output-Datei stehen - der Fix greift hier NICHT wie erwartet:**

| Datei | Anzahl Rückfälle | Beispiele |
|---|---:|---|
| active_blacklist_ipv4.txt | 2 | 122.183.40.107, 137.184.125.181 |
| combined_threat_blacklist_ipv4_part2.txt | 2 | 122.183.40.107, 137.184.125.181 |

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen Ledger-Eintraege ab (nach Anker-Datum + Fenster gruppiert, dieselbe Formel wie die jeweilige Prognose: `first`+30 Tage fuer Watchlist, `last`+180 Tage fuer Active), sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-08-30 | 10,066 | 0 | 10,066 | 100.0% |

_31 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

Noch keine aufgeloesten Tage - entweder laeuft der Job "prognose" noch nicht lange genug, oder es ist noch kein vorhergesagtes Active-Ablaufdatum vergangen (aktuell zeigt die Active-Liste konstant 0, siehe oben - das 180-Tage-Fenster hat noch nicht scharf geschaltet).

_42 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: 📈 +18,684 (Anstieg) (jetzt 9,607,940 IPs)
- Seit Zyklus-Start (2026-08-23): 📈 +211,901 (Anstieg)
- Letzter combined-Cleanup-Pass: 176,555 IPs durch Ablauf entfernt (davon 176,555 Watchlist/30T, 0 Active/180T), 1,768,569 neue IPs hinzugekommen (davon 1,635,807 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 95 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 143,555 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 14,713,458 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 1,442,918 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 1,442,918 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 0 (Summe letzte 8 Läufe / ~24h)
- Netto-Wachstum (~24h): 📈 +7,963 (~24h)
- Erfolgsquote letzte 16 combined-Läufe: 16/16 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-08-30T16:51 bis 2026-08-31T13:31 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-08-30 01:34 CEST (Europe/Berlin) | 9,542,887 | 183204 | 0 | 0 |
| 2026-08-30 01:46 CEST (Europe/Berlin) | 9,546,199 | 183204 | 0 | 0 |
| 2026-08-30 07:06 CEST (Europe/Berlin) | 9,532,594 | 198223 | 0 | 2687 |
| 2026-08-30 08:07 CEST (Europe/Berlin) | 9,540,902 | 197970 | 0 | 0 |
| 2026-08-30 12:38 CEST (Europe/Berlin) | 9,541,268 | 197953 | 0 | 0 |
| 2026-08-30 13:19 CEST (Europe/Berlin) | 9,593,508 | 197532 | 0 | 0 |
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
