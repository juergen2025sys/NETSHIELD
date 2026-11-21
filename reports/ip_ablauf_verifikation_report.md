# IP-Ablauf-Verifikationsbericht

Lauf: 2026-11-21 01:00 CET (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 18270 |
| Active (180-Tage-Pfad) | 4226028 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zeigt die tatsaechlich an diesem Kalendertag entfernten IPs. Fuer Watchlist/30T wird zusaetzlich der persistente Tages-Cap-State verwendet, damit ein frueher 2.000er-Lauf nicht durch spaetere Combined-Laeufe mit `expired_watchlist=0` aus der Anzeige verschwindet. Active/180T wird dagegen aus dem Ledger-Feld `eingefroren_am` als eindeutige Tagesmenge gezaehlt. Der Wert des letzten Combined-Laufs wird separat angezeigt und nicht mehr ueber mehrere Laeufe aufsummiert.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-11-21 (heute) | 2,000 | 0 | 0% |
| 2026-11-22 | 2,000 | 0 | 0% |
| 2026-11-23 | 2,000 | 0 | 0% |
| 2026-11-24 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

Beim Active-Pfad ist die Prognose die regulaer fuer diesen Tag erwartete Faelligkeits-Kohorte. Wenn gleichzeitig ein alter 180T-Rueckstau abgearbeitet wird, kann die reale Tagesmenge deutlich hoeher sein; deshalb wird in diesem Fall bewusst kein irrefuehrender Prozentwert berechnet.

| Datum | Prognose regulaer faellig | Heute eindeutig neu eingefroren | Letzter Combined-Cleanup | Einordnung |
|---|---:|---:|---:|---|
| 2026-11-21 (heute) | 61,068 | 0 | – | regulaerer Tagesstand |
| 2026-11-22 | 30,225 | 0 | – | noch nicht faellig |
| 2026-11-23 | 25,503 | 0 | – | noch nicht faellig |
| 2026-11-24 | 26,309 | 0 | – | noch nicht faellig |

**Active heute:** 0 eindeutige IPs neu im 180T-Ledger eingefroren; letzter Combined-Lauf: 0 Active-IP(s) als Ablauf entfernt.

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **958 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 3,072,304 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-11-20). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

✅ 0 echte Rückfälle nach Bereinigung - 958 erklaerte Watchlist-Cap-Backlog-Treffer. Sonst keine Auffaelligkeit. Der Fix haelt.

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

_30 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

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

_60 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: 📈 +2,203 (Anstieg) (jetzt 11,272,210 IPs)
- Seit Zyklus-Start (2026-11-21): n/a (kein Vergleichswert)
- Letzter combined-Cleanup-Pass: 0 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 0 Active/180T), 822,988 neue IPs hinzugekommen (davon 713,544 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) (zusätzlich: 107,340 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 822,988 (Summe 1 verschiedene Combined-Läufe in den letzten 1 Prüfläufen / 1 Lauf(e), noch keine 24h Historie seit Zyklus-Start; vor dem Aufnahme-Filter gezählt)
- Entfernte IPs (abgelaufen): heute 0 | gestern 27,979 (Kalendertag, aus Ablauf-Ledgern)
  - davon Watchlist/30 Tage: heute 0 | gestern 2,000
  - davon Active/180 Tage: heute 0 | gestern 25,979
- Netto-Wachstum (1 Lauf(e), noch keine 24h Historie seit Zyklus-Start): ➡️ unverändert
- Erfolgsquote letzte 16 combined-Läufe: 16/16 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-11-20T02:27 bis 2026-11-20T21:29 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-11-21 01:00 CET (Europe/Berlin) | 11,272,210 | 18270 | 4226028 | 0 |
