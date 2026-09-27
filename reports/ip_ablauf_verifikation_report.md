# IP-Ablauf-Verifikationsbericht

Lauf: 2026-09-27 23:18 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 4003 |
| Active (180-Tage-Pfad) | 918428 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zeigt die tatsaechlich an diesem Kalendertag entfernten IPs. Fuer Watchlist/30T wird zusaetzlich der persistente Tages-Cap-State verwendet, damit ein frueher 2.000er-Lauf nicht durch spaetere Combined-Laeufe mit `expired_watchlist=0` aus der Anzeige verschwindet. Active/180T wird dagegen aus dem Ledger-Feld `eingefroren_am` als eindeutige Tagesmenge gezaehlt. Der Wert des letzten Combined-Laufs wird separat angezeigt und nicht mehr ueber mehrere Laeufe aufsummiert.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-09-27 (heute) | 2,000 | 2,000 | 100% |
| 2026-09-28 | 2,000 | 0 | 0% |
| 2026-09-29 | 60,458 | 0 | 0% |
| 2026-09-30 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

Beim Active-Pfad ist die Prognose die regulaer fuer diesen Tag erwartete Faelligkeits-Kohorte. Wenn gleichzeitig ein alter 180T-Rueckstau abgearbeitet wird, kann die reale Tagesmenge deutlich hoeher sein; deshalb wird in diesem Fall bewusst kein irrefuehrender Prozentwert berechnet.

| Datum | Prognose regulaer faellig | Heute eindeutig neu eingefroren | Letzter Combined-Cleanup | Einordnung |
|---|---:|---:|---:|---|
| 2026-09-27 (heute) | 14,989 | 14,978 | 0 | regulaerer Tagesstand |
| 2026-09-28 | 11,589 | 0 | – | noch nicht faellig |
| 2026-09-29 | 9,332 | 0 | – | noch nicht faellig |
| 2026-09-30 | 10,146 | 0 | – | noch nicht faellig |

**Active heute:** 14,978 eindeutige IPs neu im 180T-Ledger eingefroren; letzter Combined-Lauf: 0 Active-IP(s) als Ablauf entfernt.

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **3,697 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 1,243,979 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-09-27). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

✅ 0 echte Rückfälle nach Bereinigung - 3,697 erklaerte Watchlist-Cap-Backlog-Treffer. Sonst keine Auffaelligkeit. Der Fix haelt.

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen Ledger-Eintraege ab (nach Anker-Datum + Fenster gruppiert, dieselbe Formel wie die jeweilige Prognose: `first`+31 Tage fuer Watchlist, `last`+181 Tage fuer Active), sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-09-13 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-14 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-15 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-16 | 2,000 | 0 | 2,000 | 100.0% |
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

_31 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

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

_61 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: 📈 +7,972 (Anstieg) (jetzt 11,802,966 IPs)
- Seit Zyklus-Start (2026-09-22): 📈 +325,247 (Anstieg)
- Letzter combined-Cleanup-Pass: 0 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 0 Active/180T), 921,966 neue IPs hinzugekommen (davon 794,453 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 155 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 121,630 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 7,462,109 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 16,988 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 2,000 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 14,988 (Summe letzte 8 Läufe / ~24h)
- Netto-Wachstum (~24h): 📈 +38,793 (~24h)
- Erfolgsquote letzte 16 combined-Läufe: 16/16 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-09-26T23:55 bis 2026-09-27T21:15 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-09-25 14:28 CEST (Europe/Berlin) | 11,677,487 | 3865 | 886566 | 0 |
| 2026-09-25 17:33 CEST (Europe/Berlin) | 11,678,981 | 3865 | 886560 | 0 |
| 2026-09-25 19:40 CEST (Europe/Berlin) | 11,684,754 | 3864 | 886545 | 0 |
| 2026-09-25 21:33 CEST (Europe/Berlin) | 11,694,193 | 3864 | 886530 | 0 |
| 2026-09-25 23:55 CEST (Europe/Berlin) | 11,696,626 | 3863 | 886525 | 0 |
| 2026-09-26 02:26 CEST (Europe/Berlin) | 11,696,626 | 3863 | 886525 | 0 |
| 2026-09-26 03:30 CEST (Europe/Berlin) | 11,687,860 | 3696 | 903896 | 0 |
| 2026-09-26 07:43 CEST (Europe/Berlin) | 11,697,517 | 3696 | 903887 | 0 |
| 2026-09-26 13:59 CEST (Europe/Berlin) | 11,724,771 | 3696 | 903769 | 0 |
| 2026-09-26 18:44 CEST (Europe/Berlin) | 11,752,320 | 3693 | 903742 | 0 |
| 2026-09-26 18:50 CEST (Europe/Berlin) | 11,752,320 | 3693 | 903742 | 0 |
| 2026-09-26 21:50 CEST (Europe/Berlin) | 11,764,173 | 3693 | 903718 | 0 |
| 2026-09-26 23:44 CEST (Europe/Berlin) | 11,764,173 | 3693 | 903718 | 0 |
| 2026-09-27 00:42 CEST (Europe/Berlin) | 11,771,598 | 3522 | 903700 | 0 |
| 2026-09-27 02:05 CEST (Europe/Berlin) | 11,773,485 | 3521 | 903671 | 0 |
| 2026-09-27 03:21 CEST (Europe/Berlin) | 11,765,767 | 4005 | 918647 | 0 |
| 2026-09-27 08:02 CEST (Europe/Berlin) | 11,772,586 | 4005 | 918635 | 0 |
| 2026-09-27 14:37 CEST (Europe/Berlin) | 11,785,856 | 4004 | 918508 | 0 |
| 2026-09-27 19:23 CEST (Europe/Berlin) | 11,794,994 | 4003 | 918466 | 0 |
| 2026-09-27 23:18 CEST (Europe/Berlin) | 11,802,966 | 4003 | 918428 | 0 |
