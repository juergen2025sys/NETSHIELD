# IP-Ablauf-Verifikationsbericht

Lauf: 2026-08-30 17:21 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 197527 |
| Active (180-Tage-Pfad) | 0 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zaehlt Ledger-Eintraege, deren Anker-Datum (`first` bzw. `last`) + Fenster (30 bzw. 180 Tage) auf dieses Datum faellt (exakt dieselbe Formel wie die Prognose selbst - NICHT `eingefroren_am`, das bei chronisch schwach bestaetigten IPs bei jedem erneuten Ablauf aufgefrischt wird und daher kein verlaesslicher Tages-Marker waere). Da ein Cleanup-Pass ueberfaellige Eintraege ohne feste Tages-Reihenfolge nachholt, kann "heute" laenger bei 0% bleiben, waehrend Rueckstand aus den letzten Tagen erst noch verarbeitet wird - das ist normal, keine Fehlfunktion.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-08-30 (heute) | 10,056 | 0 | 0% |
| 2026-08-31 | 52,982 | 0 | 0% |
| 2026-09-01 | 9,347 | 0 | 0% |
| 2026-09-02 | 10,982 | 0 | 0% |

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-09-04 | 173,698 | 0 | 0% |
| 2026-09-07 | 664,077 | 0 | 0% |
| 2026-09-21 | 6,508 | 0 | 0% |
| 2026-09-22 | 13,224 | 0 | 0% |

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

✅ 0 Rückfälle - keine der 197,527 eingefrorenen IPs taucht in 6 geprueften Output-Dateien auf. Der Fix haelt.

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen Ledger-Eintraege ab (nach Anker-Datum + Fenster gruppiert, dieselbe Formel wie die jeweilige Prognose: `first`+30 Tage fuer Watchlist, `last`+180 Tage fuer Active), sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen.

**Watchlist (30-Tage-Pfad):**

Noch keine aufgeloesten Tage - entweder laeuft der Job "prognose" noch nicht lange genug (woechentlich, siehe Cron), oder es ist noch kein vorhergesagtes Datum vergangen.

_31 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

Noch keine aufgeloesten Tage - entweder laeuft der Job "prognose" noch nicht lange genug, oder es ist noch kein vorhergesagtes Active-Ablaufdatum vergangen (aktuell zeigt die Active-Liste konstant 0, siehe oben - das 180-Tage-Fenster hat noch nicht scharf geschaltet).

_41 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: 📈 +4,195 (Anstieg) (jetzt 9,597,703 IPs)
- Seit Zyklus-Start (2026-08-23): 📈 +201,664 (Anstieg)
- Letzter combined-Cleanup-Pass: 171,410 IPs durch Ablauf entfernt (davon 171,410 Watchlist/30T, 0 Active/180T), 1,801,508 neue IPs hinzugekommen (davon 1,629,618 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 24 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 189,656 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 14,826,047 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 1,371,707 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 1,371,707 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 0 (Summe letzte 8 Läufe / ~24h)
- Netto-Wachstum (~24h): 📈 +56,435 (~24h)
- Erfolgsquote letzte 16 combined-Läufe: 16/16 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-08-29T20:50 bis 2026-08-30T13:09 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-08-29 00:49 CEST (Europe/Berlin) | 9,688,982 | 0 | 0 | 0 |
| 2026-08-29 04:02 CEST (Europe/Berlin) | 9,513,964 | 184313 | 0 | 0 |
| 2026-08-29 09:34 CEST (Europe/Berlin) | 9,517,844 | 183291 | 0 | 0 |
| 2026-08-29 13:26 CEST (Europe/Berlin) | 9,525,863 | 183269 | 0 | 0 |
| 2026-08-29 16:39 CEST (Europe/Berlin) | 9,533,394 | 183250 | 0 | 0 |
| 2026-08-29 16:50 CEST (Europe/Berlin) | 9,533,394 | 183250 | 0 | 0 |
| 2026-08-29 20:19 CEST (Europe/Berlin) | 9,535,319 | 183247 | 0 | 0 |
| 2026-08-29 21:02 CEST (Europe/Berlin) | 9,535,319 | 183247 | 0 | 0 |
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
