# IP-Ablauf-Verifikationsbericht

Lauf: 2026-11-12 00:01 CET (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 12556 |
| Active (180-Tage-Pfad) | 3897841 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zeigt die tatsaechlich an diesem Kalendertag entfernten IPs. Fuer Watchlist/30T wird zusaetzlich der persistente Tages-Cap-State verwendet, damit ein frueher 2.000er-Lauf nicht durch spaetere Combined-Laeufe mit `expired_watchlist=0` aus der Anzeige verschwindet. Active/180T wird dagegen aus dem Ledger-Feld `eingefroren_am` als eindeutige Tagesmenge gezaehlt. Der Wert des letzten Combined-Laufs wird separat angezeigt und nicht mehr ueber mehrere Laeufe aufsummiert.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-11-12 (heute) | 2,000 | 0 | 0% |
| 2026-11-13 | 2,000 | 0 | 0% |
| 2026-11-14 | 2,000 | 0 | 0% |
| 2026-11-15 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

Beim Active-Pfad ist die Prognose die regulaer fuer diesen Tag erwartete Faelligkeits-Kohorte. Wenn gleichzeitig ein alter 180T-Rueckstau abgearbeitet wird, kann die reale Tagesmenge deutlich hoeher sein; deshalb wird in diesem Fall bewusst kein irrefuehrender Prozentwert berechnet.

| Datum | Prognose regulaer faellig | Heute eindeutig neu eingefroren | Letzter Combined-Cleanup | Einordnung |
|---|---:|---:|---:|---|
| 2026-11-12 (heute) | 20,378 | 0 | – | regulaerer Tagesstand |
| 2026-11-13 | 19,524 | 0 | – | noch nicht faellig |
| 2026-11-14 | 22,804 | 0 | – | noch nicht faellig |
| 2026-11-15 | 17,370 | 0 | – | noch nicht faellig |

**Active heute:** 0 eindeutige IPs neu im 180T-Ledger eingefroren; letzter Combined-Lauf: 0 Active-IP(s) als Ablauf entfernt.

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **1,026 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 2,996,371 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-11-11). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

✅ 0 echte Rückfälle nach Bereinigung - 1,026 erklaerte Watchlist-Cap-Backlog-Treffer. Sonst keine Auffaelligkeit. Der Fix haelt.

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen Ledger-Eintraege ab (nach Anker-Datum + Fenster gruppiert, dieselbe Formel wie die jeweilige Prognose: `first`+31 Tage fuer Watchlist, `last`+181 Tage fuer Active), sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen. **Ausnahme Watchlist mit Tagesdeckel:** Vorhersage und Ist sind hier die am Kalendertag entfernte Menge (max. 2.000, "Muell zuerst" aus dem Rueckstau); eine Rettungsquote ist dann nicht bestimmbar ("–").

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-10-29 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-10-30 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-10-31 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-01 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-02 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-03 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-04 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-05 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-06 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-07 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-08 | 2,000 | 1,149 | – (Tagesdeckel) | – |
| 2026-11-09 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-10 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-11 | 2,000 | 2,000 | – (Tagesdeckel) | – |

_30 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-10-29 | 9,468 | 9,465 | 3 | 0.0% |
| 2026-10-30 | 61,481 | 61,477 | 4 | 0.0% |
| 2026-10-31 | 87,983 | 87,983 | 0 | 0.0% |
| 2026-11-01 | 27,681 | 27,680 | 1 | 0.0% |
| 2026-11-02 | 28,622 | 28,619 | 3 | 0.0% |
| 2026-11-03 | 29,561 | 29,555 | 6 | 0.0% |
| 2026-11-04 | 29,404 | 29,401 | 3 | 0.0% |
| 2026-11-05 | 25,089 | 25,084 | 5 | 0.0% |
| 2026-11-06 | 36,119 | 36,118 | 1 | 0.0% |
| 2026-11-07 | 24,295 | 24,291 | 4 | 0.0% |
| 2026-11-08 | 25,970 | 25,966 | 4 | 0.0% |
| 2026-11-09 | 25,366 | 25,361 | 5 | 0.0% |
| 2026-11-10 | 32,519 | 32,513 | 6 | 0.0% |
| 2026-11-11 | 22,188 | 22,182 | 6 | 0.0% |

_60 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: 📈 +8,043 (Anstieg) (jetzt 11,274,995 IPs)
- Seit Zyklus-Start (2026-10-22): 📈 +216,552 (Anstieg)
- Letzter combined-Cleanup-Pass: 0 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 0 Active/180T), 819,567 neue IPs hinzugekommen (davon 716,172 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 56 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 107,661 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 6,535,086 (Summe 8 verschiedene Combined-Läufe in den letzten 8 Prüfläufen / ~24h; vor dem Aufnahme-Filter gezählt)
- Entfernte IPs (abgelaufen): heute 0 | gestern 24,182 (Kalendertag, aus Ablauf-Ledgern)
  - davon Watchlist/30 Tage: heute 0 | gestern 2,000
  - davon Active/180 Tage: heute 0 | gestern 22,182
- Netto-Wachstum (~24h): 📈 +46,331 (~24h)
- Erfolgsquote letzte 16 combined-Läufe: 16/16 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-11-10T19:37 bis 2026-11-11T22:19 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-11-08 15:00 CET (Europe/Berlin) | 11,187,895 | 9161 | 3819367 | 0 |
| 2026-11-08 20:03 CET (Europe/Berlin) | 11,197,257 | 9161 | 3819213 | 0 |
| 2026-11-08 21:04 CET (Europe/Berlin) | 11,197,257 | 9161 | 3819213 | 0 |
| 2026-11-08 23:54 CET (Europe/Berlin) | 11,199,190 | 9161 | 3819168 | 0 |
| 2026-11-09 02:20 CET (Europe/Berlin) | 11,199,190 | 10301 | 3844504 | 25366 |
| 2026-11-09 03:37 CET (Europe/Berlin) | 11,178,721 | 10301 | 3844504 | 0 |
| 2026-11-09 12:20 CET (Europe/Berlin) | 11,201,610 | 10301 | 3844323 | 0 |
| 2026-11-09 13:23 CET (Europe/Berlin) | 11,209,981 | 10301 | 3844269 | 0 |
| 2026-11-09 22:48 CET (Europe/Berlin) | 11,230,936 | 10301 | 3844092 | 0 |
| 2026-11-09 23:49 CET (Europe/Berlin) | 11,230,936 | 10301 | 3844092 | 0 |
| 2026-11-10 05:10 CET (Europe/Berlin) | 11,208,112 | 11427 | 3876515 | 0 |
| 2026-11-10 08:55 CET (Europe/Berlin) | 11,210,399 | 11425 | 3876492 | 0 |
| 2026-11-10 13:59 CET (Europe/Berlin) | 11,228,664 | 11425 | 3876310 | 0 |
| 2026-11-10 18:23 CET (Europe/Berlin) | 11,231,007 | 11424 | 3876284 | 0 |
| 2026-11-10 21:29 CET (Europe/Berlin) | 11,239,675 | 11423 | 3876141 | 0 |
| 2026-11-11 00:51 CET (Europe/Berlin) | 11,243,443 | 11423 | 3876105 | 0 |
| 2026-11-11 08:23 CET (Europe/Berlin) | 11,241,183 | 12556 | 3898120 | 0 |
| 2026-11-11 17:06 CET (Europe/Berlin) | 11,260,037 | 12556 | 3897996 | 0 |
| 2026-11-11 18:36 CET (Europe/Berlin) | 11,266,952 | 12556 | 3897938 | 0 |
| 2026-11-12 00:01 CET (Europe/Berlin) | 11,274,995 | 12556 | 3897841 | 0 |
