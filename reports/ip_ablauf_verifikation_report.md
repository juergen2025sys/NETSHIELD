# IP-Ablauf-Verifikationsbericht

Lauf: 2026-10-08 02:57 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 16199 |
| Active (180-Tage-Pfad) | 1038229 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zeigt die tatsaechlich an diesem Kalendertag entfernten IPs. Fuer Watchlist/30T wird zusaetzlich der persistente Tages-Cap-State verwendet, damit ein frueher 2.000er-Lauf nicht durch spaetere Combined-Laeufe mit `expired_watchlist=0` aus der Anzeige verschwindet. Active/180T wird dagegen aus dem Ledger-Feld `eingefroren_am` als eindeutige Tagesmenge gezaehlt. Der Wert des letzten Combined-Laufs wird separat angezeigt und nicht mehr ueber mehrere Laeufe aufsummiert.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-10-08 (heute) | 2,000 | 0 | 0% |
| 2026-10-09 | 2,000 | 0 | 0% |
| 2026-10-10 | 2,000 | 0 | 0% |
| 2026-10-11 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

Beim Active-Pfad ist die Prognose die regulaer fuer diesen Tag erwartete Faelligkeits-Kohorte. Wenn gleichzeitig ein alter 180T-Rueckstau abgearbeitet wird, kann die reale Tagesmenge deutlich hoeher sein; deshalb wird in diesem Fall bewusst kein irrefuehrender Prozentwert berechnet.

| Datum | Prognose regulaer faellig | Heute eindeutig neu eingefroren | Letzter Combined-Cleanup | Einordnung |
|---|---:|---:|---:|---|
| 2026-10-08 (heute) | 60,917 | 0 | 0 | regulaerer Tagesstand |
| 2026-10-09 | 220,775 | 0 | – | noch nicht faellig |
| 2026-10-10 | 53,254 | 0 | – | noch nicht faellig |
| 2026-10-11 | 15,993 | 0 | – | noch nicht faellig |

**Active heute:** 0 eindeutige IPs neu im 180T-Ledger eingefroren; letzter Combined-Lauf: 0 Active-IP(s) als Ablauf entfernt.

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **3,794 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 2,630,319 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-10-07). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

✅ 0 echte Rückfälle nach Bereinigung - 3,794 erklaerte Watchlist-Cap-Backlog-Treffer. Sonst keine Auffaelligkeit. Der Fix haelt.

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen Ledger-Eintraege ab (nach Anker-Datum + Fenster gruppiert, dieselbe Formel wie die jeweilige Prognose: `first`+31 Tage fuer Watchlist, `last`+181 Tage fuer Active), sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-09-24 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-25 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-26 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-27 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-28 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-29 | 60,458 | 0 | 60,458 | 100.0% |
| 2026-09-30 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-01 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-02 | 2,000 | 2,000 | 0 | 0.0% |
| 2026-10-03 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-04 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-05 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-06 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-07 | 2,000 | 0 | 2,000 | 100.0% |

_31 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-09-24 | 16,629 | 16,621 | 8 | 0.0% |
| 2026-09-25 | 20,902 | 20,894 | 8 | 0.0% |
| 2026-09-26 | 17,410 | 17,399 | 11 | 0.1% |
| 2026-09-27 | 14,989 | 14,978 | 11 | 0.1% |
| 2026-09-28 | 11,588 | 11,587 | 1 | 0.0% |
| 2026-09-29 | 9,326 | 9,318 | 8 | 0.1% |
| 2026-09-30 | 10,132 | 10,126 | 6 | 0.1% |
| 2026-10-01 | 16,547 | 16,532 | 15 | 0.1% |
| 2026-10-02 | 7,694 | 7,681 | 13 | 0.2% |
| 2026-10-03 | 7,291 | 7,288 | 3 | 0.0% |
| 2026-10-04 | 12,537 | 12,528 | 9 | 0.1% |
| 2026-10-05 | 17,446 | 17,441 | 5 | 0.0% |
| 2026-10-06 | 16,020 | 16,001 | 19 | 0.1% |
| 2026-10-07 | 14,942 | 14,928 | 14 | 0.1% |

_61 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: 📈 +11,445 (Anstieg) (jetzt 12,400,991 IPs)
- Seit Zyklus-Start (2026-09-22): 📈 +923,272 (Anstieg)
- Letzter combined-Cleanup-Pass: 0 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 0 Active/180T), 914,561 neue IPs hinzugekommen (davon 786,611 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 9 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 125,516 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 7,314,689 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 0 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 0 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 0 (Summe letzte 8 Läufe / ~24h)
- Netto-Wachstum (~24h): 📈 +69,977 (~24h)
- Erfolgsquote letzte 16 combined-Läufe: 16/16 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-10-07T08:02 bis 2026-10-08T00:55 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-10-04 20:23 CEST (Europe/Berlin) | 12,236,371 | 10299 | 991373 | 0 |
| 2026-10-04 20:54 CEST (Europe/Berlin) | 12,238,086 | 10299 | 991365 | 0 |
| 2026-10-04 23:55 CEST (Europe/Berlin) | 12,238,086 | 10299 | 991365 | 0 |
| 2026-10-05 00:14 CEST (Europe/Berlin) | 12,243,533 | 10299 | 991346 | 0 |
| 2026-10-05 08:27 CEST (Europe/Berlin) | 12,249,186 | 12271 | 1008691 | 0 |
| 2026-10-05 17:26 CEST (Europe/Berlin) | 12,271,629 | 12269 | 1008567 | 0 |
| 2026-10-05 17:53 CEST (Europe/Berlin) | 12,271,629 | 12269 | 1008567 | 0 |
| 2026-10-06 00:16 CEST (Europe/Berlin) | 12,292,805 | 12269 | 1008514 | 0 |
| 2026-10-06 04:33 CEST (Europe/Berlin) | 12,278,090 | 14246 | 1024490 | 0 |
| 2026-10-06 09:03 CEST (Europe/Berlin) | 12,298,552 | 14245 | 1024445 | 0 |
| 2026-10-06 18:20 CEST (Europe/Berlin) | 12,327,487 | 14243 | 1023797 | 0 |
| 2026-10-06 18:25 CEST (Europe/Berlin) | 12,327,487 | 14243 | 1023797 | 0 |
| 2026-10-06 23:15 CEST (Europe/Berlin) | 12,331,014 | 14242 | 1023764 | 0 |
| 2026-10-07 00:51 CEST (Europe/Berlin) | 12,340,164 | 14241 | 1023712 | 0 |
| 2026-10-07 08:44 CEST (Europe/Berlin) | 12,336,175 | 16203 | 1038579 | 0 |
| 2026-10-07 16:06 CEST (Europe/Berlin) | 12,377,303 | 16201 | 1038373 | 0 |
| 2026-10-07 16:45 CEST (Europe/Berlin) | 12,377,303 | 16201 | 1038373 | 0 |
| 2026-10-07 22:36 CEST (Europe/Berlin) | 12,389,546 | 16201 | 1038310 | 0 |
| 2026-10-07 22:55 CEST (Europe/Berlin) | 12,389,546 | 16201 | 1038310 | 0 |
| 2026-10-08 02:57 CEST (Europe/Berlin) | 12,400,991 | 16199 | 1038229 | 0 |
