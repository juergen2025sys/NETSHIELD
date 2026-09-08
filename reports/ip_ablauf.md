# Seen-DB Expiry Forecast

Lauf: 2026-09-08 18:31 CEST (Europe/Berlin)
Gesamt: 10,762,899 IPs in seen_db.json (7,944,946 aktiv/180-Tage-Pfad, 2,817,953 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 0 |
| 8-14 Tage | 6,471 |
| 15-30 Tage | 271,151 |
| 31-60 Tage | 2,730,494 |
| 61-90 Tage | 1,026,230 |
| 91-180 Tage | 3,910,600 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 450,641 |
| 0-3 Tage | 50,199 |
| 4-7 Tage | 52,622 |
| 8-14 Tage | 47,541 |
| 15-30 Tage | 2,216,950 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-08 | 13,061 |
| 2026-09-09 | 17,000 |
| 2026-09-10 | 8,779 |
| 2026-09-11 | 11,359 |
| 2026-09-12 | 11,945 |
| 2026-09-13 | 12,092 |
| 2026-09-14 | 12,912 |
| 2026-09-15 | 15,673 |
| 2026-09-16 | 6,277 |
| 2026-09-17 | 5,818 |
| 2026-09-18 | 8,845 |
| 2026-09-19 | 5,181 |
| 2026-09-20 | 5,094 |
| 2026-09-21 | 5,078 |
| 2026-09-22 | 11,248 |
| 2026-09-23 | 5,190 |
| 2026-09-24 | 11,463 |
| 2026-09-25 | 5,536 |
| 2026-09-26 | 624,575 |
| 2026-09-27 | 6,375 |
| 2026-09-28 | 786 |
| 2026-09-30 | 60,035 |
| 2026-10-01 | 7,757 |
| 2026-10-02 | 1,310,463 |
| 2026-10-03 | 3,018 |
| 2026-10-04 | 7,021 |
| 2026-10-05 | 2,981 |
| 2026-10-06 | 8,485 |
| 2026-10-07 | 8,204 |
| 2026-10-08 | 7,517 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **450,641** IPs. Brutto faellig in den naechsten 30 Tagen: **2,219,768**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,610,409**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-08 | 13,061 | 2,000 |
| 2026-09-09 | 17,000 | 2,000 |
| 2026-09-10 | 8,779 | 2,000 |
| 2026-09-11 | 11,359 | 2,000 |
| 2026-09-12 | 11,945 | 2,000 |
| 2026-09-13 | 12,092 | 2,000 |
| 2026-09-14 | 12,912 | 2,000 |
| 2026-09-15 | 15,673 | 2,000 |
| 2026-09-16 | 6,277 | 2,000 |
| 2026-09-17 | 5,818 | 2,000 |
| 2026-09-18 | 8,845 | 2,000 |
| 2026-09-19 | 5,181 | 2,000 |
| 2026-09-20 | 5,094 | 2,000 |
| 2026-09-21 | 5,078 | 2,000 |
| 2026-09-22 | 11,248 | 2,000 |
| 2026-09-23 | 5,190 | 2,000 |
| 2026-09-24 | 11,463 | 2,000 |
| 2026-09-25 | 5,536 | 2,000 |
| 2026-09-26 | 624,575 | 2,000 |
| 2026-09-27 | 6,375 | 2,000 |
| 2026-09-28 | 786 | 2,000 |
| 2026-09-30 | 60,035 | 2,000 |
| 2026-10-01 | 7,757 | 2,000 |
| 2026-10-02 | 1,310,463 | 2,000 |
| 2026-10-03 | 3,018 | 2,000 |
| 2026-10-04 | 7,021 | 2,000 |
| 2026-10-05 | 2,981 | 2,000 |
| 2026-10-06 | 8,485 | 2,000 |
| 2026-10-07 | 8,204 | 2,000 |
| 2026-10-08 | 7,517 | 2,000 |

> Hinweis: Der Rueckstau von 2,610,409 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,471 |
| 2026-09-23 | 13,163 |
| 2026-09-24 | 16,833 |
| 2026-09-25 | 21,108 |
| 2026-09-26 | 17,612 |
| 2026-09-27 | 15,209 |
| 2026-09-28 | 11,671 |
| 2026-09-29 | 9,426 |
| 2026-09-30 | 10,284 |
| 2026-10-01 | 16,710 |
| 2026-10-02 | 7,799 |
| 2026-10-03 | 7,393 |
| 2026-10-04 | 12,772 |
| 2026-10-05 | 17,687 |
| 2026-10-06 | 16,257 |
| 2026-10-07 | 15,179 |
| 2026-10-08 | 62,048 |
| 2026-10-09 | 225,885 |
| 2026-10-10 | 53,519 |
| 2026-10-11 | 16,109 |
| 2026-10-12 | 66,697 |
| 2026-10-13 | 1,590,859 |
| 2026-10-14 | 32,961 |
| 2026-10-15 | 41,445 |
| 2026-10-16 | 51,501 |
| 2026-10-17 | 24,466 |
| 2026-10-18 | 14,383 |
| 2026-10-19 | 22,669 |
| 2026-10-20 | 11,217 |
| 2026-10-21 | 11,198 |
| 2026-10-22 | 30,969 |
| 2026-10-23 | 50,610 |
| 2026-10-24 | 41,915 |
| 2026-10-25 | 21,764 |
| 2026-10-26 | 20,527 |
| 2026-10-27 | 20,885 |
| 2026-10-28 | 15,942 |
| 2026-10-29 | 9,813 |
| 2026-10-30 | 62,397 |
| 2026-10-31 | 88,447 |
| 2026-11-01 | 28,059 |
| 2026-11-02 | 29,069 |
| 2026-11-03 | 30,139 |
| 2026-11-04 | 29,930 |
| 2026-11-05 | 25,497 |
| 2026-11-06 | 36,949 |
| 2026-11-07 | 24,673 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 142552 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
