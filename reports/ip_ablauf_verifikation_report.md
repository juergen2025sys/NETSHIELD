# IP-Ablauf-Verifikationsbericht

Lauf: 2026-11-23 14:54 CET (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 18131 |
| Active (180-Tage-Pfad) | 4341947 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zeigt die tatsaechlich an diesem Kalendertag entfernten IPs. Fuer Watchlist/30T wird zusaetzlich der persistente Tages-Cap-State verwendet, damit ein frueher 2.000er-Lauf nicht durch spaetere Combined-Laeufe mit `expired_watchlist=0` aus der Anzeige verschwindet. Active/180T wird dagegen aus dem Ledger-Feld `eingefroren_am` als eindeutige Tagesmenge gezaehlt. Der Wert des letzten Combined-Laufs wird separat angezeigt und nicht mehr ueber mehrere Laeufe aufsummiert.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-11-23 (heute) | 2,000 | 2,000 | 100% |
| 2026-11-24 | 2,000 | 0 | 0% |
| 2026-11-25 | 2,000 | 0 | 0% |
| 2026-11-26 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

Beim Active-Pfad ist die Prognose die regulaer fuer diesen Tag erwartete Faelligkeits-Kohorte. Wenn gleichzeitig ein alter 180T-Rueckstau abgearbeitet wird, kann die reale Tagesmenge deutlich hoeher sein; deshalb wird in diesem Fall bewusst kein irrefuehrender Prozentwert berechnet.

| Datum | Prognose regulaer faellig | Heute eindeutig neu eingefroren | Letzter Combined-Cleanup | Einordnung |
|---|---:|---:|---:|---|
| 2026-11-23 (heute) | 25,500 | 25,498 | 0 | regulaerer Tagesstand |
| 2026-11-24 | 26,305 | 0 | – | noch nicht faellig |
| 2026-11-25 | 27,329 | 0 | – | noch nicht faellig |
| 2026-11-26 | 28,515 | 0 | – | noch nicht faellig |

**Active heute:** 25,498 eindeutige IPs neu im 180T-Ledger eingefroren; letzter Combined-Lauf: 0 Active-IP(s) als Ablauf entfernt.

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **973 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 3,098,123 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-11-23). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

✅ 0 echte Rückfälle nach Bereinigung - 973 erklaerte Watchlist-Cap-Backlog-Treffer. Sonst keine Auffaelligkeit. Der Fix haelt.

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen Ledger-Eintraege ab (nach Anker-Datum + Fenster gruppiert, dieselbe Formel wie die jeweilige Prognose: `first`+31 Tage fuer Watchlist, `last`+181 Tage fuer Active), sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen. **Ausnahme Watchlist mit Tagesdeckel:** Vorhersage und Ist sind hier die am Kalendertag entfernte Menge (max. 2.000, "Muell zuerst" aus dem Rueckstau); eine Rettungsquote ist dann nicht bestimmbar ("–").

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-11-09 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-10 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-11 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-12 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-13 | 2,000 | 1,154 | – (Tagesdeckel) | – |
| 2026-11-14 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-15 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-16 | 2,000 | 1,175 | – (Tagesdeckel) | – |
| 2026-11-17 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-18 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-19 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-20 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-21 | 2,000 | 1,117 | – (Tagesdeckel) | – |
| 2026-11-22 | 2,000 | 2,000 | – (Tagesdeckel) | – |

_30 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-11-09 | 25,366 | 25,361 | 5 | 0.0% |
| 2026-11-10 | 32,519 | 32,513 | 6 | 0.0% |
| 2026-11-11 | 22,188 | 22,182 | 6 | 0.0% |
| 2026-11-12 | 20,378 | 20,376 | 2 | 0.0% |
| 2026-11-13 | 19,523 | 19,521 | 2 | 0.0% |
| 2026-11-14 | 22,797 | 22,796 | 1 | 0.0% |
| 2026-11-15 | 17,365 | 17,363 | 2 | 0.0% |
| 2026-11-16 | 17,836 | 17,832 | 4 | 0.0% |
| 2026-11-17 | 15,142 | 15,141 | 1 | 0.0% |
| 2026-11-18 | 19,382 | 19,379 | 3 | 0.0% |
| 2026-11-19 | 173,112 | 173,100 | 12 | 0.0% |
| 2026-11-20 | 25,980 | 25,979 | 1 | 0.0% |
| 2026-11-21 | 61,068 | 61,066 | 2 | 0.0% |
| 2026-11-22 | 30,223 | 30,215 | 8 | 0.0% |

_60 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: 📈 +17,753 (Anstieg) (jetzt 11,269,936 IPs)
- Seit Zyklus-Start (2026-11-21): 📉 -2,274 (Rückgang)
- Letzter combined-Cleanup-Pass: 0 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 0 Active/180T), 914,162 neue IPs hinzugekommen (davon 804,623 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 210 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 106,925 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 7,240,965 (Summe 8 verschiedene Combined-Läufe in den letzten 8 Prüfläufen / ~24h; vor dem Aufnahme-Filter gezählt)
- Entfernte IPs (abgelaufen): heute 27,498 | gestern 32,213 (Kalendertag, aus Ablauf-Ledgern)
  - davon Watchlist/30 Tage: heute 2,000 | gestern 2,000
  - davon Active/180 Tage: heute 25,498 | gestern 30,213
- Netto-Wachstum (~24h): 📈 +33,767 (~24h)
- Erfolgsquote letzte 16 combined-Läufe: 16/16 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-11-22T12:56 bis 2026-11-23T13:40 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-11-21 01:00 CET (Europe/Berlin) | 11,272,210 | 18270 | 4226028 | 0 |
| 2026-11-21 03:56 CET (Europe/Berlin) | 11,213,618 | 18194 | 4287043 | 0 |
| 2026-11-21 07:59 CET (Europe/Berlin) | 11,228,674 | 18194 | 4287011 | 0 |
| 2026-11-21 12:56 CET (Europe/Berlin) | 11,236,560 | 18194 | 4286963 | 0 |
| 2026-11-21 16:18 CET (Europe/Berlin) | 11,248,765 | 18194 | 4286936 | 0 |
| 2026-11-21 20:53 CET (Europe/Berlin) | 11,261,799 | 18193 | 4286856 | 0 |
| 2026-11-22 02:35 CET (Europe/Berlin) | 11,236,169 | 18168 | 4317016 | 0 |
| 2026-11-22 02:50 CET (Europe/Berlin) | 11,236,169 | 18168 | 4317016 | 0 |
| 2026-11-22 10:50 CET (Europe/Berlin) | 11,257,207 | 18168 | 4316924 | 0 |
| 2026-11-22 13:10 CET (Europe/Berlin) | 11,259,767 | 18168 | 4316855 | 0 |
| 2026-11-22 18:47 CET (Europe/Berlin) | 11,262,927 | 18168 | 4316773 | 0 |
| 2026-11-22 21:04 CET (Europe/Berlin) | 11,266,209 | 18168 | 4316732 | 0 |
| 2026-11-23 00:34 CET (Europe/Berlin) | 11,269,172 | 18168 | 4316682 | 0 |
| 2026-11-23 03:06 CET (Europe/Berlin) | 11,252,183 | 18132 | 4342140 | 0 |
| 2026-11-23 14:54 CET (Europe/Berlin) | 11,269,936 | 18131 | 4341947 | 0 |
