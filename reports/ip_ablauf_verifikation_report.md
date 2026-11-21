# IP-Ablauf-Verifikationsbericht

Lauf: 2026-11-21 12:56 CET (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 18194 |
| Active (180-Tage-Pfad) | 4286963 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zeigt die tatsaechlich an diesem Kalendertag entfernten IPs. Fuer Watchlist/30T wird zusaetzlich der persistente Tages-Cap-State verwendet, damit ein frueher 2.000er-Lauf nicht durch spaetere Combined-Laeufe mit `expired_watchlist=0` aus der Anzeige verschwindet. Active/180T wird dagegen aus dem Ledger-Feld `eingefroren_am` als eindeutige Tagesmenge gezaehlt. Der Wert des letzten Combined-Laufs wird separat angezeigt und nicht mehr ueber mehrere Laeufe aufsummiert.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-11-21 (heute) | 2,000 | 2,000 | 100% |
| 2026-11-22 | 2,000 | 0 | 0% |
| 2026-11-23 | 2,000 | 0 | 0% |
| 2026-11-24 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

Beim Active-Pfad ist die Prognose die regulaer fuer diesen Tag erwartete Faelligkeits-Kohorte. Wenn gleichzeitig ein alter 180T-Rueckstau abgearbeitet wird, kann die reale Tagesmenge deutlich hoeher sein; deshalb wird in diesem Fall bewusst kein irrefuehrender Prozentwert berechnet.

| Datum | Prognose regulaer faellig | Heute eindeutig neu eingefroren | Letzter Combined-Cleanup | Einordnung |
|---|---:|---:|---:|---|
| 2026-11-21 (heute) | 61,068 | 61,067 | 0 | regulaerer Tagesstand |
| 2026-11-22 | 30,224 | 0 | – | noch nicht faellig |
| 2026-11-23 | 25,502 | 0 | – | noch nicht faellig |
| 2026-11-24 | 26,309 | 0 | – | noch nicht faellig |

**Active heute:** 61,067 eindeutige IPs neu im 180T-Ledger eingefroren; letzter Combined-Lauf: 0 Active-IP(s) als Ablauf entfernt.

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **910 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 3,080,787 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-11-21). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

✅ 0 echte Rückfälle nach Bereinigung - 910 erklaerte Watchlist-Cap-Backlog-Treffer. Sonst keine Auffaelligkeit. Der Fix haelt.

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen Ledger-Eintraege ab (nach Anker-Datum + Fenster gruppiert, dieselbe Formel wie die jeweilige Prognose: `first`+31 Tage fuer Watchlist, `last`+181 Tage fuer Active), sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen. **Ausnahme Watchlist mit Tagesdeckel:** Vorhersage und Ist sind hier die am Kalendertag entfernte Menge (max. 2.000, "Muell zuerst" aus dem Rueckstau); eine Rettungsquote ist dann nicht bestimmbar ("–").

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
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
| 2026-11-17 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-18 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-19 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-20 | 2,000 | 2,000 | – (Tagesdeckel) | – |

_31 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
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
| 2026-11-17 | 15,142 | 15,141 | 1 | 0.0% |
| 2026-11-18 | 19,382 | 19,379 | 3 | 0.0% |
| 2026-11-19 | 173,112 | 173,100 | 12 | 0.0% |
| 2026-11-20 | 25,980 | 25,979 | 1 | 0.0% |

_61 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: 📈 +7,886 (Anstieg) (jetzt 11,236,560 IPs)
- Seit Zyklus-Start (2026-11-21): 📉 -35,650 (Rückgang)
- Letzter combined-Cleanup-Pass: 0 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 0 Active/180T), 845,503 neue IPs hinzugekommen (davon 727,096 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 234 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 110,713 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 3,349,577 (Summe 4 verschiedene Combined-Läufe in den letzten 4 Prüfläufen / 4 Lauf(e), noch keine 24h Historie seit Zyklus-Start; vor dem Aufnahme-Filter gezählt)
- Entfernte IPs (abgelaufen): heute 63,067 | gestern 27,157 (Kalendertag, aus Ablauf-Ledgern)
  - davon Watchlist/30 Tage: heute 2,000 | gestern 1,178
  - davon Active/180 Tage: heute 61,067 | gestern 25,979
- Netto-Wachstum (4 Lauf(e), noch keine 24h Historie seit Zyklus-Start): 📉 -35,650 (4 Lauf(e), noch keine 24h Historie seit Zyklus-Start) ⚠️ **schrumpft aktuell netto** - mehr entfernt als neu aufgenommen
- Erfolgsquote letzte 16 combined-Läufe: 14/14 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt) | zusätzlich 1 cancelled (nicht gewertet) | 1 sonstige, Zeitraum 2026-11-20T18:57 bis 2026-11-21T11:48 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-11-21 01:00 CET (Europe/Berlin) | 11,272,210 | 18270 | 4226028 | 0 |
| 2026-11-21 03:56 CET (Europe/Berlin) | 11,213,618 | 18194 | 4287043 | 0 |
| 2026-11-21 07:59 CET (Europe/Berlin) | 11,228,674 | 18194 | 4287011 | 0 |
| 2026-11-21 12:56 CET (Europe/Berlin) | 11,236,560 | 18194 | 4286963 | 0 |
