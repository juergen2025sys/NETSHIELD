# IP-Ablauf-Verifikationsbericht

Lauf: 2026-11-19 19:39 CET (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 18244 |
| Active (180-Tage-Pfad) | 4200519 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zeigt die tatsaechlich an diesem Kalendertag entfernten IPs. Fuer Watchlist/30T wird zusaetzlich der persistente Tages-Cap-State verwendet, damit ein frueher 2.000er-Lauf nicht durch spaetere Combined-Laeufe mit `expired_watchlist=0` aus der Anzeige verschwindet. Active/180T wird dagegen aus dem Ledger-Feld `eingefroren_am` als eindeutige Tagesmenge gezaehlt. Der Wert des letzten Combined-Laufs wird separat angezeigt und nicht mehr ueber mehrere Laeufe aufsummiert.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-11-19 (heute) | 2,000 | 2,000 | 100% |
| 2026-11-20 | 2,000 | 0 | 0% |
| 2026-11-21 | 2,000 | 0 | 0% |
| 2026-11-22 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

Beim Active-Pfad ist die Prognose die regulaer fuer diesen Tag erwartete Faelligkeits-Kohorte. Wenn gleichzeitig ein alter 180T-Rueckstau abgearbeitet wird, kann die reale Tagesmenge deutlich hoeher sein; deshalb wird in diesem Fall bewusst kein irrefuehrender Prozentwert berechnet.

| Datum | Prognose regulaer faellig | Heute eindeutig neu eingefroren | Letzter Combined-Cleanup | Einordnung |
|---|---:|---:|---:|---|
| 2026-11-19 (heute) | 173,112 | 173,103 | 0 | regulaerer Tagesstand |
| 2026-11-20 | 25,982 | 0 | – | noch nicht faellig |
| 2026-11-21 | 61,072 | 0 | – | noch nicht faellig |
| 2026-11-22 | 30,227 | 0 | – | noch nicht faellig |

**Active heute:** 173,103 eindeutige IPs neu im 180T-Ledger eingefroren; letzter Combined-Lauf: 0 Active-IP(s) als Ablauf entfernt.

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **1,035 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 3,062,865 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-11-19). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

✅ 0 echte Rückfälle nach Bereinigung - 1,035 erklaerte Watchlist-Cap-Backlog-Treffer. Sonst keine Auffaelligkeit. Der Fix haelt.

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen Ledger-Eintraege ab (nach Anker-Datum + Fenster gruppiert, dieselbe Formel wie die jeweilige Prognose: `first`+31 Tage fuer Watchlist, `last`+181 Tage fuer Active), sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen. **Ausnahme Watchlist mit Tagesdeckel:** Vorhersage und Ist sind hier die am Kalendertag entfernte Menge (max. 2.000, "Muell zuerst" aus dem Rueckstau); eine Rettungsquote ist dann nicht bestimmbar ("–").

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
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
| 2026-11-17 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-18 | 2,000 | 2,000 | – (Tagesdeckel) | – |

_31 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
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
| 2026-11-17 | 15,142 | 15,141 | 1 | 0.0% |
| 2026-11-18 | 19,382 | 19,379 | 3 | 0.0% |

_61 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: 📈 +4,099 (Anstieg) (jetzt 11,258,907 IPs)
- Seit Zyklus-Start (2026-10-22): 📈 +200,464 (Anstieg)
- Letzter combined-Cleanup-Pass: 0 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 0 Active/180T), 822,859 neue IPs hinzugekommen (davon 712,906 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 117 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 106,389 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 4,945,577 (Summe 6 verschiedene Combined-Läufe in den letzten 8 Prüfläufen / ~24h; vor dem Aufnahme-Filter gezählt)
- Entfernte IPs (abgelaufen): heute 175,103 | gestern 21,377 (Kalendertag, aus Ablauf-Ledgern)
  - davon Watchlist/30 Tage: heute 2,000 | gestern 2,000
  - davon Active/180 Tage: heute 173,103 | gestern 19,377
- Netto-Wachstum (~24h): 📉 -123,975 (~24h) ⚠️ **schrumpft aktuell netto** - mehr entfernt als neu aufgenommen
- Erfolgsquote letzte 16 combined-Läufe: 15/15 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt) | 1 sonstige, Zeitraum 2026-11-18T20:22 bis 2026-11-19T18:34 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-11-15 17:43 CET (Europe/Berlin) | 11,355,872 | 17104 | 3976547 | 0 |
| 2026-11-15 22:01 CET (Europe/Berlin) | 11,359,050 | 17104 | 3976494 | 0 |
| 2026-11-16 00:17 CET (Europe/Berlin) | 11,361,396 | 17104 | 3976462 | 0 |
| 2026-11-16 08:29 CET (Europe/Berlin) | 11,354,240 | 18260 | 3994187 | 0 |
| 2026-11-16 20:57 CET (Europe/Berlin) | 11,371,193 | 18259 | 3993972 | 0 |
| 2026-11-17 03:05 CET (Europe/Berlin) | 11,359,063 | 18128 | 4009060 | 0 |
| 2026-11-17 05:15 CET (Europe/Berlin) | 11,362,192 | 18127 | 4009042 | 0 |
| 2026-11-17 11:40 CET (Europe/Berlin) | 11,370,048 | 18127 | 4009020 | 0 |
| 2026-11-17 17:36 CET (Europe/Berlin) | 11,379,379 | 18127 | 4008899 | 0 |
| 2026-11-17 20:48 CET (Europe/Berlin) | 11,385,629 | 18126 | 4008806 | 0 |
| 2026-11-18 02:27 CET (Europe/Berlin) | 11,370,319 | 18218 | 4028073 | 0 |
| 2026-11-18 11:42 CET (Europe/Berlin) | 11,378,459 | 18218 | 4027950 | 0 |
| 2026-11-18 13:31 CET (Europe/Berlin) | 11,382,882 | 18218 | 4027893 | 0 |
| 2026-11-18 20:26 CET (Europe/Berlin) | 11,397,165 | 18217 | 4027709 | 0 |
| 2026-11-18 22:01 CET (Europe/Berlin) | 11,397,165 | 18217 | 4027709 | 0 |
| 2026-11-19 02:28 CET (Europe/Berlin) | 11,233,056 | 18245 | 4200757 | 0 |
| 2026-11-19 03:54 CET (Europe/Berlin) | 11,233,056 | 18245 | 4200757 | 0 |
| 2026-11-19 10:26 CET (Europe/Berlin) | 11,247,973 | 18245 | 4200692 | 0 |
| 2026-11-19 13:21 CET (Europe/Berlin) | 11,254,808 | 18245 | 4200613 | 0 |
| 2026-11-19 19:39 CET (Europe/Berlin) | 11,258,907 | 18244 | 4200519 | 0 |
