# IP-Ablauf-Verifikationsbericht

Lauf: 2026-11-27 12:25 CET (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 17478 |
| Active (180-Tage-Pfad) | 4450373 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zeigt die tatsaechlich an diesem Kalendertag entfernten IPs. Fuer Watchlist/30T wird zusaetzlich der persistente Tages-Cap-State verwendet, damit ein frueher 2.000er-Lauf nicht durch spaetere Combined-Laeufe mit `expired_watchlist=0` aus der Anzeige verschwindet. Active/180T wird dagegen aus dem Ledger-Feld `eingefroren_am` als eindeutige Tagesmenge gezaehlt. Der Wert des letzten Combined-Laufs wird separat angezeigt und nicht mehr ueber mehrere Laeufe aufsummiert.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-11-27 (heute) | 2,000 | 2,000 | 100% |
| 2026-11-28 | 2,000 | 0 | 0% |
| 2026-11-29 | 2,000 | 0 | 0% |
| 2026-11-30 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

Beim Active-Pfad ist die Prognose die regulaer fuer diesen Tag erwartete Faelligkeits-Kohorte. Wenn gleichzeitig ein alter 180T-Rueckstau abgearbeitet wird, kann die reale Tagesmenge deutlich hoeher sein; deshalb wird in diesem Fall bewusst kein irrefuehrender Prozentwert berechnet.

| Datum | Prognose regulaer faellig | Heute eindeutig neu eingefroren | Letzter Combined-Cleanup | Einordnung |
|---|---:|---:|---:|---|
| 2026-11-27 (heute) | 27,695 | 27,692 | 0 | regulaerer Tagesstand |
| 2026-11-28 | 108,938 | 0 | – | noch nicht faellig |
| 2026-11-29 | 28,029 | 0 | – | noch nicht faellig |
| 2026-11-30 | 25,386 | 0 | – | noch nicht faellig |

**Active heute:** 27,692 eindeutige IPs neu im 180T-Ledger eingefroren; letzter Combined-Lauf: 0 Active-IP(s) als Ablauf entfernt.

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **1,154 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 3,118,156 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-11-27). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

✅ 0 echte Rückfälle nach Bereinigung - 1,154 erklaerte Watchlist-Cap-Backlog-Treffer. Sonst keine Auffaelligkeit. Der Fix haelt.

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen Ledger-Eintraege ab (nach Anker-Datum + Fenster gruppiert, dieselbe Formel wie die jeweilige Prognose: `first`+31 Tage fuer Watchlist, `last`+181 Tage fuer Active), sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen. **Ausnahme Watchlist mit Tagesdeckel:** Vorhersage und Ist sind hier die am Kalendertag entfernte Menge (max. 2.000, "Muell zuerst" aus dem Rueckstau); eine Rettungsquote ist dann nicht bestimmbar ("–").

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
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
| 2026-11-23 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-24 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-25 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-26 | 2,000 | 1,999 | – (Tagesdeckel) | – |

_31 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
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
| 2026-11-23 | 25,500 | 25,498 | 2 | 0.0% |
| 2026-11-24 | 26,303 | 26,299 | 4 | 0.0% |
| 2026-11-25 | 27,323 | 27,323 | 0 | 0.0% |
| 2026-11-26 | 28,508 | 28,507 | 1 | 0.0% |

_61 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: 📈 +10,973 (Anstieg) (jetzt 11,308,698 IPs)
- Seit Zyklus-Start (2026-11-21): 📈 +36,488 (Anstieg)
- Letzter combined-Cleanup-Pass: 0 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 0 Active/180T), 915,899 neue IPs hinzugekommen (davon 800,633 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 7,112 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 107,540 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 6,360,560 (Summe 7 verschiedene Combined-Läufe in den letzten 8 Prüfläufen / ~24h; vor dem Aufnahme-Filter gezählt)
- Entfernte IPs (abgelaufen): heute 29,692 | gestern 29,420 (Kalendertag, aus Ablauf-Ledgern)
  - davon Watchlist/30 Tage: heute 2,000 | gestern 914
  - davon Active/180 Tage: heute 27,692 | gestern 28,506
- Netto-Wachstum (~24h): 📈 +30,700 (~24h)
- Erfolgsquote letzte 16 combined-Läufe: 16/16 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-11-26T03:40 bis 2026-11-27T09:06 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-11-23 15:28 CET (Europe/Berlin) | 11,269,936 | 18131 | 4341947 | 0 |
| 2026-11-24 02:54 CET (Europe/Berlin) | 11,255,087 | 18046 | 4368074 | 0 |
| 2026-11-24 03:42 CET (Europe/Berlin) | 11,255,087 | 18046 | 4368074 | 0 |
| 2026-11-24 13:24 CET (Europe/Berlin) | 11,276,403 | 18045 | 4367954 | 0 |
| 2026-11-24 15:27 CET (Europe/Berlin) | 11,280,661 | 18045 | 4367911 | 0 |
| 2026-11-24 23:47 CET (Europe/Berlin) | 11,288,357 | 18045 | 4367777 | 0 |
| 2026-11-25 01:15 CET (Europe/Berlin) | 11,291,247 | 18045 | 4367728 | 0 |
| 2026-11-25 06:25 CET (Europe/Berlin) | 11,276,349 | 17922 | 4394996 | 0 |
| 2026-11-25 10:25 CET (Europe/Berlin) | 11,279,296 | 17922 | 4394955 | 0 |
| 2026-11-25 17:01 CET (Europe/Berlin) | 11,288,835 | 17921 | 4394852 | 0 |
| 2026-11-25 20:40 CET (Europe/Berlin) | 11,292,015 | 17920 | 4394833 | 0 |
| 2026-11-26 01:16 CET (Europe/Berlin) | 11,296,988 | 17920 | 4394771 | 0 |
| 2026-11-26 04:51 CET (Europe/Berlin) | 11,277,998 | 17756 | 4423227 | 0 |
| 2026-11-26 09:52 CET (Europe/Berlin) | 11,277,998 | 17756 | 4423227 | 0 |
| 2026-11-26 14:30 CET (Europe/Berlin) | 11,308,792 | 17755 | 4423099 | 0 |
| 2026-11-26 20:01 CET (Europe/Berlin) | 11,311,169 | 17754 | 4423018 | 0 |
| 2026-11-27 01:12 CET (Europe/Berlin) | 11,317,100 | 17753 | 4422852 | 0 |
| 2026-11-27 03:11 CET (Europe/Berlin) | 11,289,194 | 17478 | 4450507 | 0 |
| 2026-11-27 10:19 CET (Europe/Berlin) | 11,297,725 | 17478 | 4450373 | 0 |
| 2026-11-27 12:25 CET (Europe/Berlin) | 11,308,698 | 17478 | 4450373 | 0 |
