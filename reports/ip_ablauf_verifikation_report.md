# IP-Ablauf-Verifikationsbericht

Lauf: 2026-10-04 10:23 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 10300 |
| Active (180-Tage-Pfad) | 991550 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zeigt die tatsaechlich an diesem Kalendertag entfernten IPs. Fuer Watchlist/30T wird zusaetzlich der persistente Tages-Cap-State verwendet, damit ein frueher 2.000er-Lauf nicht durch spaetere Combined-Laeufe mit `expired_watchlist=0` aus der Anzeige verschwindet. Active/180T wird dagegen aus dem Ledger-Feld `eingefroren_am` als eindeutige Tagesmenge gezaehlt. Der Wert des letzten Combined-Laufs wird separat angezeigt und nicht mehr ueber mehrere Laeufe aufsummiert.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-10-04 (heute) | 2,000 | 2,000 | 100% |
| 2026-10-05 | 2,000 | 0 | 0% |
| 2026-10-06 | 2,000 | 0 | 0% |
| 2026-10-07 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

Beim Active-Pfad ist die Prognose die regulaer fuer diesen Tag erwartete Faelligkeits-Kohorte. Wenn gleichzeitig ein alter 180T-Rueckstau abgearbeitet wird, kann die reale Tagesmenge deutlich hoeher sein; deshalb wird in diesem Fall bewusst kein irrefuehrender Prozentwert berechnet.

| Datum | Prognose regulaer faellig | Heute eindeutig neu eingefroren | Letzter Combined-Cleanup | Einordnung |
|---|---:|---:|---:|---|
| 2026-10-04 (heute) | 12,537 | 12,534 | 0 | regulaerer Tagesstand |
| 2026-10-05 | 17,448 | 0 | – | noch nicht faellig |
| 2026-10-06 | 16,031 | 0 | – | noch nicht faellig |
| 2026-10-07 | 14,966 | 0 | – | noch nicht faellig |

**Active heute:** 12,534 eindeutige IPs neu im 180T-Ledger eingefroren; letzter Combined-Lauf: 0 Active-IP(s) als Ablauf entfernt.

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **3,847 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 2,620,328 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-10-04). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

✅ 0 echte Rückfälle nach Bereinigung - 3,847 erklaerte Watchlist-Cap-Backlog-Treffer. Sonst keine Auffaelligkeit. Der Fix haelt.

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen Ledger-Eintraege ab (nach Anker-Datum + Fenster gruppiert, dieselbe Formel wie die jeweilige Prognose: `first`+31 Tage fuer Watchlist, `last`+181 Tage fuer Active), sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
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
| 2026-10-01 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-02 | 2,000 | 2,000 | 0 | 0.0% |
| 2026-10-03 | 2,000 | 0 | 2,000 | 100.0% |

_31 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
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
| 2026-10-01 | 16,547 | 16,532 | 15 | 0.1% |
| 2026-10-02 | 7,694 | 7,681 | 13 | 0.2% |
| 2026-10-03 | 7,291 | 7,288 | 3 | 0.0% |

_61 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: 📈 +17,420 (Anstieg) (jetzt 12,187,710 IPs)
- Seit Zyklus-Start (2026-09-22): 📈 +709,991 (Anstieg)
- Letzter combined-Cleanup-Pass: 0 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 0 Active/180T), 918,272 neue IPs hinzugekommen (davon 789,175 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 296 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 112,055 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 7,279,359 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 14,536 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 2,000 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 12,536 (Summe letzte 8 Läufe / ~24h)
- Netto-Wachstum (~24h): 📈 +40,059 (~24h)
- Erfolgsquote letzte 16 combined-Läufe: 16/16 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-10-03T14:46 bis 2026-10-04T06:22 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-10-01 21:26 CEST (Europe/Berlin) | 12,028,855 | 4379 | 964619 | 0 |
| 2026-10-02 00:58 CEST (Europe/Berlin) | 12,030,043 | 4379 | 964615 | 0 |
| 2026-10-02 04:34 CEST (Europe/Berlin) | 12,035,157 | 6359 | 972260 | 0 |
| 2026-10-02 08:29 CEST (Europe/Berlin) | 12,045,251 | 6358 | 972240 | 0 |
| 2026-10-02 11:41 CEST (Europe/Berlin) | 12,067,620 | 6358 | 972191 | 0 |
| 2026-10-02 15:24 CEST (Europe/Berlin) | 12,081,833 | 6358 | 972107 | 0 |
| 2026-10-02 20:54 CEST (Europe/Berlin) | 12,098,116 | 6358 | 972067 | 0 |
| 2026-10-02 22:16 CEST (Europe/Berlin) | 12,106,117 | 6358 | 972054 | 0 |
| 2026-10-03 02:25 CEST (Europe/Berlin) | 12,113,245 | 6358 | 972042 | 0 |
| 2026-10-03 02:51 CEST (Europe/Berlin) | 12,113,245 | 6358 | 972042 | 0 |
| 2026-10-03 07:43 CEST (Europe/Berlin) | 12,113,975 | 8330 | 979283 | 0 |
| 2026-10-03 07:58 CEST (Europe/Berlin) | 12,113,975 | 8330 | 979283 | 0 |
| 2026-10-03 13:34 CEST (Europe/Berlin) | 12,147,651 | 8329 | 979234 | 0 |
| 2026-10-03 14:10 CEST (Europe/Berlin) | 12,147,651 | 8329 | 979234 | 0 |
| 2026-10-03 17:20 CEST (Europe/Berlin) | 12,159,299 | 8329 | 979160 | 0 |
| 2026-10-03 18:54 CEST (Europe/Berlin) | 12,159,299 | 8329 | 979160 | 0 |
| 2026-10-03 23:55 CEST (Europe/Berlin) | 12,170,704 | 8329 | 979137 | 0 |
| 2026-10-04 04:01 CEST (Europe/Berlin) | 12,167,966 | 10300 | 991624 | 0 |
| 2026-10-04 08:33 CEST (Europe/Berlin) | 12,170,290 | 10300 | 991615 | 0 |
| 2026-10-04 10:23 CEST (Europe/Berlin) | 12,187,710 | 10300 | 991550 | 0 |
