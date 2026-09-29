# IP-Ablauf-Verifikationsbericht

Lauf: 2026-09-29 03:22 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 4134 |
| Active (180-Tage-Pfad) | 929754 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zeigt die tatsaechlich an diesem Kalendertag entfernten IPs. Fuer Watchlist/30T wird zusaetzlich der persistente Tages-Cap-State verwendet, damit ein frueher 2.000er-Lauf nicht durch spaetere Combined-Laeufe mit `expired_watchlist=0` aus der Anzeige verschwindet. Active/180T wird dagegen aus dem Ledger-Feld `eingefroren_am` als eindeutige Tagesmenge gezaehlt. Der Wert des letzten Combined-Laufs wird separat angezeigt und nicht mehr ueber mehrere Laeufe aufsummiert.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-09-29 (heute) | 60,458 | 0 | 0% |
| 2026-09-30 | 2,000 | 0 | 0% |
| 2026-10-01 | 2,000 | 0 | 0% |
| 2026-10-02 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

Beim Active-Pfad ist die Prognose die regulaer fuer diesen Tag erwartete Faelligkeits-Kohorte. Wenn gleichzeitig ein alter 180T-Rueckstau abgearbeitet wird, kann die reale Tagesmenge deutlich hoeher sein; deshalb wird in diesem Fall bewusst kein irrefuehrender Prozentwert berechnet.

| Datum | Prognose regulaer faellig | Heute eindeutig neu eingefroren | Letzter Combined-Cleanup | Einordnung |
|---|---:|---:|---:|---|
| 2026-09-29 (heute) | 9,326 | 0 | – | regulaerer Tagesstand |
| 2026-09-30 | 10,138 | 0 | – | noch nicht faellig |
| 2026-10-01 | 16,558 | 0 | – | noch nicht faellig |
| 2026-10-02 | 7,697 | 0 | – | noch nicht faellig |

**Active heute:** 0 eindeutige IPs neu im 180T-Ledger eingefroren; letzter Combined-Lauf: 0 Active-IP(s) als Ablauf entfernt.

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **3,702 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 1,244,359 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-09-28). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

✅ 0 echte Rückfälle nach Bereinigung - 3,702 erklaerte Watchlist-Cap-Backlog-Treffer. Sonst keine Auffaelligkeit. Der Fix haelt.

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen Ledger-Eintraege ab (nach Anker-Datum + Fenster gruppiert, dieselbe Formel wie die jeweilige Prognose: `first`+31 Tage fuer Watchlist, `last`+181 Tage fuer Active), sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
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
| 2026-09-27 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-28 | 2,000 | 0 | 2,000 | 100.0% |

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
| 2026-09-27 | 14,989 | 14,978 | 11 | 0.1% |
| 2026-09-28 | 11,588 | 11,587 | 1 | 0.0% |

_61 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: ➡️ unverändert (jetzt 11,847,341 IPs)
- Seit Zyklus-Start (2026-09-22): 📈 +369,622 (Anstieg)
- Letzter combined-Cleanup-Pass: 0 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 0 Active/180T), 925,953 neue IPs hinzugekommen (davon 795,304 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 255 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 124,642 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 7,397,345 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 13,588 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 2,000 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 11,588 (Summe letzte 8 Läufe / ~24h)
- Netto-Wachstum (~24h): 📈 +52,465 (~24h)
- Erfolgsquote letzte 16 combined-Läufe: 15/15 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt) | 1 sonstige, Zeitraum 2026-09-28T07:13 bis 2026-09-29T01:16 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-09-26 21:50 CEST (Europe/Berlin) | 11,764,173 | 3693 | 903718 | 0 |
| 2026-09-26 23:44 CEST (Europe/Berlin) | 11,764,173 | 3693 | 903718 | 0 |
| 2026-09-27 00:42 CEST (Europe/Berlin) | 11,771,598 | 3522 | 903700 | 0 |
| 2026-09-27 02:05 CEST (Europe/Berlin) | 11,773,485 | 3521 | 903671 | 0 |
| 2026-09-27 03:21 CEST (Europe/Berlin) | 11,765,767 | 4005 | 918647 | 0 |
| 2026-09-27 08:02 CEST (Europe/Berlin) | 11,772,586 | 4005 | 918635 | 0 |
| 2026-09-27 14:37 CEST (Europe/Berlin) | 11,785,856 | 4004 | 918508 | 0 |
| 2026-09-27 19:23 CEST (Europe/Berlin) | 11,794,994 | 4003 | 918466 | 0 |
| 2026-09-27 23:18 CEST (Europe/Berlin) | 11,802,966 | 4003 | 918428 | 0 |
| 2026-09-27 23:46 CEST (Europe/Berlin) | 11,802,966 | 4003 | 918428 | 0 |
| 2026-09-28 01:58 CEST (Europe/Berlin) | 11,802,966 | 4003 | 918428 | 0 |
| 2026-09-28 02:10 CEST (Europe/Berlin) | 11,802,966 | 4003 | 918428 | 0 |
| 2026-09-28 07:09 CEST (Europe/Berlin) | 11,794,876 | 4145 | 929976 | 0 |
| 2026-09-28 08:09 CEST (Europe/Berlin) | 11,808,614 | 4140 | 929937 | 0 |
| 2026-09-28 13:59 CEST (Europe/Berlin) | 11,827,769 | 4136 | 929855 | 0 |
| 2026-09-28 16:46 CEST (Europe/Berlin) | 11,830,887 | 4135 | 929797 | 0 |
| 2026-09-28 21:40 CEST (Europe/Berlin) | 11,840,960 | 4134 | 929769 | 0 |
| 2026-09-28 23:29 CEST (Europe/Berlin) | 11,840,960 | 4134 | 929769 | 0 |
| 2026-09-29 02:22 CEST (Europe/Berlin) | 11,847,341 | 4134 | 929754 | 0 |
| 2026-09-29 03:22 CEST (Europe/Berlin) | 11,847,341 | 4134 | 929754 | 0 |
