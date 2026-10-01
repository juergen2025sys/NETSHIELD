# IP-Ablauf-Verifikationsbericht

Lauf: 2026-10-01 21:26 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 4379 |
| Active (180-Tage-Pfad) | 964619 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zeigt die tatsaechlich an diesem Kalendertag entfernten IPs. Fuer Watchlist/30T wird zusaetzlich der persistente Tages-Cap-State verwendet, damit ein frueher 2.000er-Lauf nicht durch spaetere Combined-Laeufe mit `expired_watchlist=0` aus der Anzeige verschwindet. Active/180T wird dagegen aus dem Ledger-Feld `eingefroren_am` als eindeutige Tagesmenge gezaehlt. Der Wert des letzten Combined-Laufs wird separat angezeigt und nicht mehr ueber mehrere Laeufe aufsummiert.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-10-01 (heute) | 2,000 | 2,000 | 100% |
| 2026-10-02 | 2,000 | 0 | 0% |
| 2026-10-03 | 2,000 | 0 | 0% |
| 2026-10-04 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

Beim Active-Pfad ist die Prognose die regulaer fuer diesen Tag erwartete Faelligkeits-Kohorte. Wenn gleichzeitig ein alter 180T-Rueckstau abgearbeitet wird, kann die reale Tagesmenge deutlich hoeher sein; deshalb wird in diesem Fall bewusst kein irrefuehrender Prozentwert berechnet.

| Datum | Prognose regulaer faellig | Heute eindeutig neu eingefroren | Letzter Combined-Cleanup | Einordnung |
|---|---:|---:|---:|---|
| 2026-10-01 (heute) | 16,547 | 16,532 | 0 | regulaerer Tagesstand |
| 2026-10-02 | 7,694 | 0 | – | noch nicht faellig |
| 2026-10-03 | 7,302 | 0 | – | noch nicht faellig |
| 2026-10-04 | 12,564 | 0 | – | noch nicht faellig |

**Active heute:** 16,532 eindeutige IPs neu im 180T-Ledger eingefroren; letzter Combined-Lauf: 0 Active-IP(s) als Ablauf entfernt.

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **3,875 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 1,310,310 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-10-01). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

✅ 0 echte Rückfälle nach Bereinigung - 3,875 erklaerte Watchlist-Cap-Backlog-Treffer. Sonst keine Auffaelligkeit. Der Fix haelt.

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen Ledger-Eintraege ab (nach Anker-Datum + Fenster gruppiert, dieselbe Formel wie die jeweilige Prognose: `first`+31 Tage fuer Watchlist, `last`+181 Tage fuer Active), sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-09-17 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-18 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-19 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-20 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-21 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-22 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-23 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-24 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-25 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-26 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-27 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-28 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-29 | 60,458 | 0 | 60,458 | 100.0% |
| 2026-09-30 | 2,000 | 0 | 2,000 | 100.0% |

_30 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-09-04 | 173,700 | 0 | 173,700 | 100.0% |
| 2026-09-05 | 173,665 | 173,637 | 28 | 0.0% |
| 2026-09-07 | 663,981 | 0 | 663,981 | 100.0% |
| 2026-09-08 | 662,324 | 661,899 | 425 | 0.1% |
| 2026-09-21 | 6,509 | 0 | 6,509 | 100.0% |
| 2026-09-22 | 6,431 | 6,424 | 7 | 0.1% |
| 2026-09-23 | 13,041 | 13,030 | 11 | 0.1% |
| 2026-09-24 | 16,629 | 16,621 | 8 | 0.0% |
| 2026-09-25 | 20,902 | 20,894 | 8 | 0.0% |
| 2026-09-26 | 17,410 | 17,399 | 11 | 0.1% |
| 2026-09-27 | 14,989 | 14,978 | 11 | 0.1% |
| 2026-09-28 | 11,588 | 11,587 | 1 | 0.0% |
| 2026-09-29 | 9,326 | 9,318 | 8 | 0.1% |
| 2026-09-30 | 10,132 | 10,126 | 6 | 0.1% |

_60 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: 📈 +7,740 (Anstieg) (jetzt 12,028,855 IPs)
- Seit Zyklus-Start (2026-09-22): 📈 +551,136 (Anstieg)
- Letzter combined-Cleanup-Pass: 0 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 0 Active/180T), 915,487 neue IPs hinzugekommen (davon 791,050 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 18 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 119,424 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 7,379,052 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 18,547 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 2,000 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 16,547 (Summe letzte 8 Läufe / ~24h)
- Netto-Wachstum (~24h): 📈 +60,832 (~24h)
- Erfolgsquote letzte 16 combined-Läufe: 16/16 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-10-01T00:39 bis 2026-10-01T19:05 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-09-29 02:22 CEST (Europe/Berlin) | 11,847,341 | 4134 | 929754 | 0 |
| 2026-09-29 03:22 CEST (Europe/Berlin) | 11,847,341 | 4134 | 929754 | 0 |
| 2026-09-29 08:07 CEST (Europe/Berlin) | 11,858,404 | 4244 | 939009 | 0 |
| 2026-09-29 12:17 CEST (Europe/Berlin) | 11,874,119 | 4228 | 938930 | 0 |
| 2026-09-29 15:20 CEST (Europe/Berlin) | 11,881,181 | 4228 | 938855 | 0 |
| 2026-09-29 20:24 CEST (Europe/Berlin) | 11,891,440 | 4227 | 938827 | 0 |
| 2026-09-30 00:47 CEST (Europe/Berlin) | 11,907,182 | 4224 | 938760 | 0 |
| 2026-09-30 04:02 CEST (Europe/Berlin) | 11,911,950 | 4270 | 948846 | 0 |
| 2026-09-30 08:12 CEST (Europe/Berlin) | 11,927,351 | 4265 | 948778 | 0 |
| 2026-09-30 10:27 CEST (Europe/Berlin) | 11,934,094 | 4265 | 948745 | 0 |
| 2026-09-30 15:14 CEST (Europe/Berlin) | 11,949,715 | 4263 | 948686 | 0 |
| 2026-09-30 22:19 CEST (Europe/Berlin) | 11,968,023 | 4242 | 948613 | 0 |
| 2026-09-30 22:26 CEST (Europe/Berlin) | 11,968,023 | 4242 | 948613 | 0 |
| 2026-10-01 02:23 CEST (Europe/Berlin) | 11,957,361 | 4391 | 965138 | 16547 |
| 2026-10-01 02:57 CEST (Europe/Berlin) | 11,965,315 | 4391 | 965111 | 0 |
| 2026-10-01 08:38 CEST (Europe/Berlin) | 11,983,200 | 4388 | 965049 | 0 |
| 2026-10-01 12:37 CEST (Europe/Berlin) | 12,000,275 | 4388 | 965018 | 0 |
| 2026-10-01 16:07 CEST (Europe/Berlin) | 12,015,090 | 4387 | 964672 | 0 |
| 2026-10-01 20:39 CEST (Europe/Berlin) | 12,021,115 | 4387 | 964660 | 0 |
| 2026-10-01 21:26 CEST (Europe/Berlin) | 12,028,855 | 4379 | 964619 | 0 |
