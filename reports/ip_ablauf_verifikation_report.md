# IP-Ablauf-Verifikationsbericht

Lauf: 2026-10-18 07:05 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 28562 |
| Active (180-Tage-Pfad) | 3196159 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zeigt die tatsaechlich an diesem Kalendertag entfernten IPs. Fuer Watchlist/30T wird zusaetzlich der persistente Tages-Cap-State verwendet, damit ein frueher 2.000er-Lauf nicht durch spaetere Combined-Laeufe mit `expired_watchlist=0` aus der Anzeige verschwindet. Active/180T wird dagegen aus dem Ledger-Feld `eingefroren_am` als eindeutige Tagesmenge gezaehlt. Der Wert des letzten Combined-Laufs wird separat angezeigt und nicht mehr ueber mehrere Laeufe aufsummiert.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-10-18 (heute) | 2,000 | 2,000 | 100% |
| 2026-10-19 | 2,000 | 0 | 0% |
| 2026-10-20 | 2,000 | 0 | 0% |
| 2026-10-21 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

Beim Active-Pfad ist die Prognose die regulaer fuer diesen Tag erwartete Faelligkeits-Kohorte. Wenn gleichzeitig ein alter 180T-Rueckstau abgearbeitet wird, kann die reale Tagesmenge deutlich hoeher sein; deshalb wird in diesem Fall bewusst kein irrefuehrender Prozentwert berechnet.

| Datum | Prognose regulaer faellig | Heute eindeutig neu eingefroren | Letzter Combined-Cleanup | Einordnung |
|---|---:|---:|---:|---|
| 2026-10-18 (heute) | 14,154 | 14,153 | 0 | regulaerer Tagesstand |
| 2026-10-19 | 21,957 | 0 | – | noch nicht faellig |
| 2026-10-20 | 11,054 | 0 | – | noch nicht faellig |
| 2026-10-21 | 11,014 | 0 | – | noch nicht faellig |

**Active heute:** 14,153 eindeutige IPs neu im 180T-Ledger eingefroren; letzter Combined-Lauf: 0 Active-IP(s) als Ablauf entfernt.

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **1,923 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 2,699,689 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-10-18). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

✅ 0 echte Rückfälle nach Bereinigung - 1,923 erklaerte Watchlist-Cap-Backlog-Treffer. Sonst keine Auffaelligkeit. Der Fix haelt.

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen Ledger-Eintraege ab (nach Anker-Datum + Fenster gruppiert, dieselbe Formel wie die jeweilige Prognose: `first`+31 Tage fuer Watchlist, `last`+181 Tage fuer Active), sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-10-04 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-05 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-06 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-07 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-08 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-09 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-10 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-11 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-12 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-13 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-14 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-15 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-16 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-17 | 2,000 | 0 | 2,000 | 100.0% |

_31 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-10-04 | 12,537 | 12,528 | 9 | 0.1% |
| 2026-10-05 | 17,446 | 17,441 | 5 | 0.0% |
| 2026-10-06 | 16,020 | 16,001 | 19 | 0.1% |
| 2026-10-07 | 14,942 | 14,928 | 14 | 0.1% |
| 2026-10-08 | 60,917 | 60,866 | 51 | 0.1% |
| 2026-10-09 | 220,692 | 220,508 | 184 | 0.1% |
| 2026-10-10 | 53,244 | 53,239 | 5 | 0.0% |
| 2026-10-11 | 15,987 | 15,987 | 0 | 0.0% |
| 2026-10-12 | 66,480 | 66,477 | 3 | 0.0% |
| 2026-10-13 | 1,579,746 | 1,579,622 | 124 | 0.0% |
| 2026-10-14 | 32,901 | 32,898 | 3 | 0.0% |
| 2026-10-15 | 41,267 | 41,263 | 4 | 0.0% |
| 2026-10-16 | 51,126 | 51,121 | 5 | 0.0% |
| 2026-10-17 | 24,149 | 24,147 | 2 | 0.0% |

_61 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: 📉 -2,411 (Rückgang) (jetzt 10,870,469 IPs)
- Seit Zyklus-Start (2026-09-22): 📉 -607,250 (Rückgang)
- Letzter combined-Cleanup-Pass: 0 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 0 Active/180T), 883,713 neue IPs hinzugekommen (davon 758,555 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 178 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 121,017 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 7,045,956 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 0 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 0 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 0 (Summe letzte 8 Läufe / ~24h)
- Netto-Wachstum (~24h): 📈 +37,073 (~24h)
- Erfolgsquote letzte 16 combined-Läufe: 16/16 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-10-17T11:11 bis 2026-10-18T04:51 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-10-16 00:41 CEST (Europe/Berlin) | 10,830,920 | 29981 | 3107200 | 0 |
| 2026-10-16 02:06 CEST (Europe/Berlin) | 10,830,920 | 29981 | 3107200 | 0 |
| 2026-10-16 07:18 CEST (Europe/Berlin) | 10,792,029 | 29999 | 3158248 | 0 |
| 2026-10-16 13:58 CEST (Europe/Berlin) | 10,803,365 | 29999 | 3158168 | 0 |
| 2026-10-16 14:02 CEST (Europe/Berlin) | 10,803,365 | 29999 | 3158168 | 0 |
| 2026-10-16 18:34 CEST (Europe/Berlin) | 10,804,942 | 29999 | 3158162 | 0 |
| 2026-10-16 19:07 CEST (Europe/Berlin) | 10,816,539 | 29999 | 3158141 | 0 |
| 2026-10-16 21:45 CEST (Europe/Berlin) | 10,829,161 | 29999 | 3158125 | 0 |
| 2026-10-16 23:51 CEST (Europe/Berlin) | 10,837,810 | 29999 | 3158114 | 0 |
| 2026-10-17 00:49 CEST (Europe/Berlin) | 10,837,810 | 29999 | 3158114 | 0 |
| 2026-10-17 02:06 CEST (Europe/Berlin) | 10,843,602 | 29999 | 3158074 | 0 |
| 2026-10-17 07:14 CEST (Europe/Berlin) | 10,826,398 | 29999 | 3182201 | 0 |
| 2026-10-17 13:11 CEST (Europe/Berlin) | 10,833,396 | 29999 | 3182167 | 0 |
| 2026-10-17 13:18 CEST (Europe/Berlin) | 10,833,396 | 29999 | 3182167 | 0 |
| 2026-10-17 16:25 CEST (Europe/Berlin) | 10,847,320 | 29999 | 3182137 | 0 |
| 2026-10-17 18:03 CEST (Europe/Berlin) | 10,852,149 | 29999 | 3182111 | 0 |
| 2026-10-17 21:45 CEST (Europe/Berlin) | 10,863,828 | 29999 | 3182086 | 0 |
| 2026-10-17 23:10 CEST (Europe/Berlin) | 10,868,765 | 29999 | 3182057 | 0 |
| 2026-10-18 01:40 CEST (Europe/Berlin) | 10,872,880 | 29999 | 3182045 | 0 |
| 2026-10-18 07:05 CEST (Europe/Berlin) | 10,870,469 | 28562 | 3196159 | 0 |
