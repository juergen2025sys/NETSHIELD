# IP-Ablauf-Verifikationsbericht

Lauf: 2026-11-17 17:36 CET (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 18127 |
| Active (180-Tage-Pfad) | 4008899 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zeigt die tatsaechlich an diesem Kalendertag entfernten IPs. Fuer Watchlist/30T wird zusaetzlich der persistente Tages-Cap-State verwendet, damit ein frueher 2.000er-Lauf nicht durch spaetere Combined-Laeufe mit `expired_watchlist=0` aus der Anzeige verschwindet. Active/180T wird dagegen aus dem Ledger-Feld `eingefroren_am` als eindeutige Tagesmenge gezaehlt. Der Wert des letzten Combined-Laufs wird separat angezeigt und nicht mehr ueber mehrere Laeufe aufsummiert.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-11-17 (heute) | 2,000 | 2,000 | 100% |
| 2026-11-18 | 2,000 | 0 | 0% |
| 2026-11-19 | 2,000 | 0 | 0% |
| 2026-11-20 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

Beim Active-Pfad ist die Prognose die regulaer fuer diesen Tag erwartete Faelligkeits-Kohorte. Wenn gleichzeitig ein alter 180T-Rueckstau abgearbeitet wird, kann die reale Tagesmenge deutlich hoeher sein; deshalb wird in diesem Fall bewusst kein irrefuehrender Prozentwert berechnet.

| Datum | Prognose regulaer faellig | Heute eindeutig neu eingefroren | Letzter Combined-Cleanup | Einordnung |
|---|---:|---:|---:|---|
| 2026-11-17 (heute) | 15,142 | 15,141 | 0 | regulaerer Tagesstand |
| 2026-11-18 | 19,385 | 0 | – | noch nicht faellig |
| 2026-11-19 | 173,128 | 0 | – | noch nicht faellig |
| 2026-11-20 | 25,985 | 0 | – | noch nicht faellig |

**Active heute:** 15,141 eindeutige IPs neu im 180T-Ledger eingefroren; letzter Combined-Lauf: 0 Active-IP(s) als Ablauf entfernt.

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **1,047 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 3,053,459 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-11-17). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

✅ 0 echte Rückfälle nach Bereinigung - 1,047 erklaerte Watchlist-Cap-Backlog-Treffer. Sonst keine Auffaelligkeit. Der Fix haelt.

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen Ledger-Eintraege ab (nach Anker-Datum + Fenster gruppiert, dieselbe Formel wie die jeweilige Prognose: `first`+31 Tage fuer Watchlist, `last`+181 Tage fuer Active), sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen. **Ausnahme Watchlist mit Tagesdeckel:** Vorhersage und Ist sind hier die am Kalendertag entfernte Menge (max. 2.000, "Muell zuerst" aus dem Rueckstau); eine Rettungsquote ist dann nicht bestimmbar ("–").

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-11-03 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-04 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-05 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-06 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-07 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-08 | 2,000 | 1,149 | – (Tagesdeckel) | – |
| 2026-11-09 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-10 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-11 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-12 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-13 | 2,000 | 1,154 | – (Tagesdeckel) | – |
| 2026-11-14 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-15 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-16 | 2,000 | 1,175 | – (Tagesdeckel) | – |

_31 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-11-03 | 29,561 | 29,555 | 6 | 0.0% |
| 2026-11-04 | 29,404 | 29,401 | 3 | 0.0% |
| 2026-11-05 | 25,089 | 25,084 | 5 | 0.0% |
| 2026-11-06 | 36,119 | 36,118 | 1 | 0.0% |
| 2026-11-07 | 24,295 | 24,291 | 4 | 0.0% |
| 2026-11-08 | 25,970 | 25,966 | 4 | 0.0% |
| 2026-11-09 | 25,366 | 25,361 | 5 | 0.0% |
| 2026-11-10 | 32,519 | 32,513 | 6 | 0.0% |
| 2026-11-11 | 22,188 | 22,182 | 6 | 0.0% |
| 2026-11-12 | 20,378 | 20,376 | 2 | 0.0% |
| 2026-11-13 | 19,523 | 19,521 | 2 | 0.0% |
| 2026-11-14 | 22,797 | 22,796 | 1 | 0.0% |
| 2026-11-15 | 17,365 | 17,363 | 2 | 0.0% |
| 2026-11-16 | 17,836 | 17,832 | 4 | 0.0% |

_61 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: 📈 +9,331 (Anstieg) (jetzt 11,379,379 IPs)
- Seit Zyklus-Start (2026-10-22): 📈 +320,936 (Anstieg)
- Letzter combined-Cleanup-Pass: 0 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 0 Active/180T), 825,262 neue IPs hinzugekommen (davon 714,583 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 18 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 108,453 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 6,592,275 (Summe 8 verschiedene Combined-Läufe in den letzten 8 Prüfläufen / ~24h; vor dem Aufnahme-Filter gezählt)
- Entfernte IPs (abgelaufen): heute 17,141 | gestern 19,007 (Kalendertag, aus Ablauf-Ledgern)
  - davon Watchlist/30 Tage: heute 2,000 | gestern 1,175
  - davon Active/180 Tage: heute 15,141 | gestern 17,832
- Netto-Wachstum (~24h): 📈 +20,329 (~24h)
- Erfolgsquote letzte 16 combined-Läufe: 16/16 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-11-16T13:14 bis 2026-11-17T16:29 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-11-13 21:12 CET (Europe/Berlin) | 11,330,730 | 14821 | 3936960 | 0 |
| 2026-11-13 23:52 CET (Europe/Berlin) | 11,334,522 | 14821 | 3936910 | 0 |
| 2026-11-14 02:55 CET (Europe/Berlin) | 11,312,273 | 15955 | 3959675 | 0 |
| 2026-11-14 11:54 CET (Europe/Berlin) | 11,329,277 | 15954 | 3959584 | 0 |
| 2026-11-14 12:07 CET (Europe/Berlin) | 11,329,277 | 15954 | 3959584 | 0 |
| 2026-11-14 18:01 CET (Europe/Berlin) | 11,333,809 | 15953 | 3959547 | 0 |
| 2026-11-14 19:37 CET (Europe/Berlin) | 11,336,028 | 15952 | 3959533 | 0 |
| 2026-11-14 22:24 CET (Europe/Berlin) | 11,347,269 | 15952 | 3959424 | 0 |
| 2026-11-14 23:49 CET (Europe/Berlin) | 11,348,990 | 15952 | 3959418 | 0 |
| 2026-11-15 08:23 CET (Europe/Berlin) | 11,336,511 | 17105 | 3976719 | 0 |
| 2026-11-15 16:53 CET (Europe/Berlin) | 11,354,029 | 17104 | 3976565 | 0 |
| 2026-11-15 17:43 CET (Europe/Berlin) | 11,355,872 | 17104 | 3976547 | 0 |
| 2026-11-15 22:01 CET (Europe/Berlin) | 11,359,050 | 17104 | 3976494 | 0 |
| 2026-11-16 00:17 CET (Europe/Berlin) | 11,361,396 | 17104 | 3976462 | 0 |
| 2026-11-16 08:29 CET (Europe/Berlin) | 11,354,240 | 18260 | 3994187 | 0 |
| 2026-11-16 20:57 CET (Europe/Berlin) | 11,371,193 | 18259 | 3993972 | 0 |
| 2026-11-17 03:05 CET (Europe/Berlin) | 11,359,063 | 18128 | 4009060 | 0 |
| 2026-11-17 05:15 CET (Europe/Berlin) | 11,362,192 | 18127 | 4009042 | 0 |
| 2026-11-17 11:40 CET (Europe/Berlin) | 11,370,048 | 18127 | 4009020 | 0 |
| 2026-11-17 17:36 CET (Europe/Berlin) | 11,379,379 | 18127 | 4008899 | 0 |
