# Seen-DB Expiry Forecast

Lauf: 2026-09-18 18:41 CEST (Europe/Berlin)
Gesamt: 11,473,877 IPs in seen_db.json (8,529,862 aktiv/180-Tage-Pfad, 2,944,015 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 57,149 |
| 8-14 Tage | 88,070 |
| 15-30 Tage | 2,240,910 |
| 31-60 Tage | 831,341 |
| 61-90 Tage | 1,090,380 |
| 91-180 Tage | 4,222,012 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 561,407 |
| 0-3 Tage | 23,938 |
| 4-7 Tage | 33,160 |
| 8-14 Tage | 2,006,301 |
| 15-30 Tage | 319,209 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-18 | 8,753 |
| 2026-09-19 | 5,126 |
| 2026-09-20 | 5,039 |
| 2026-09-21 | 5,020 |
| 2026-09-22 | 11,154 |
| 2026-09-23 | 5,124 |
| 2026-09-24 | 11,407 |
| 2026-09-25 | 5,475 |
| 2026-09-26 | 623,973 |
| 2026-09-27 | 6,296 |
| 2026-09-28 | 778 |
| 2026-09-30 | 59,739 |
| 2026-10-01 | 7,674 |
| 2026-10-02 | 1,307,841 |
| 2026-10-03 | 2,974 |
| 2026-10-04 | 6,931 |
| 2026-10-05 | 2,913 |
| 2026-10-06 | 8,297 |
| 2026-10-07 | 8,018 |
| 2026-10-08 | 7,342 |
| 2026-10-09 | 152,043 |
| 2026-10-10 | 8,228 |
| 2026-10-11 | 23,207 |
| 2026-10-12 | 33,349 |
| 2026-10-13 | 9,065 |
| 2026-10-14 | 8,116 |
| 2026-10-15 | 8,898 |
| 2026-10-16 | 16,299 |
| 2026-10-17 | 10,678 |
| 2026-10-18 | 9,486 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **561,407** IPs. Brutto faellig in den naechsten 30 Tagen: **2,379,243**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,880,650**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-18 | 8,753 | 2,000 |
| 2026-09-19 | 5,126 | 2,000 |
| 2026-09-20 | 5,039 | 2,000 |
| 2026-09-21 | 5,020 | 2,000 |
| 2026-09-22 | 11,154 | 2,000 |
| 2026-09-23 | 5,124 | 2,000 |
| 2026-09-24 | 11,407 | 2,000 |
| 2026-09-25 | 5,475 | 2,000 |
| 2026-09-26 | 623,973 | 2,000 |
| 2026-09-27 | 6,296 | 2,000 |
| 2026-09-28 | 778 | 2,000 |
| 2026-09-30 | 59,739 | 2,000 |
| 2026-10-01 | 7,674 | 2,000 |
| 2026-10-02 | 1,307,841 | 2,000 |
| 2026-10-03 | 2,974 | 2,000 |
| 2026-10-04 | 6,931 | 2,000 |
| 2026-10-05 | 2,913 | 2,000 |
| 2026-10-06 | 8,297 | 2,000 |
| 2026-10-07 | 8,018 | 2,000 |
| 2026-10-08 | 7,342 | 2,000 |
| 2026-10-09 | 152,043 | 2,000 |
| 2026-10-10 | 8,228 | 2,000 |
| 2026-10-11 | 23,207 | 2,000 |
| 2026-10-12 | 33,349 | 2,000 |
| 2026-10-13 | 9,065 | 2,000 |
| 2026-10-14 | 8,116 | 2,000 |
| 2026-10-15 | 8,898 | 2,000 |
| 2026-10-16 | 16,299 | 2,000 |
| 2026-10-17 | 10,678 | 2,000 |
| 2026-10-18 | 9,486 | 2,000 |

> Hinweis: Der Rueckstau von 2,880,650 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,437 |
| 2026-09-23 | 13,071 |
| 2026-09-24 | 16,686 |
| 2026-09-25 | 20,955 |
| 2026-09-26 | 17,475 |
| 2026-09-27 | 15,057 |
| 2026-09-28 | 11,620 |
| 2026-09-29 | 9,369 |
| 2026-09-30 | 10,195 |
| 2026-10-01 | 16,621 |
| 2026-10-02 | 7,733 |
| 2026-10-03 | 7,342 |
| 2026-10-04 | 12,643 |
| 2026-10-05 | 17,568 |
| 2026-10-06 | 16,152 |
| 2026-10-07 | 15,094 |
| 2026-10-08 | 61,511 |
| 2026-10-09 | 223,620 |
| 2026-10-10 | 53,416 |
| 2026-10-11 | 16,068 |
| 2026-10-12 | 66,607 |
| 2026-10-13 | 1,586,544 |
| 2026-10-14 | 32,928 |
| 2026-10-15 | 41,368 |
| 2026-10-16 | 51,390 |
| 2026-10-17 | 24,356 |
| 2026-10-18 | 14,303 |
| 2026-10-19 | 22,438 |
| 2026-10-20 | 11,166 |
| 2026-10-21 | 11,140 |
| 2026-10-22 | 30,817 |
| 2026-10-23 | 50,481 |
| 2026-10-24 | 41,798 |
| 2026-10-25 | 21,676 |
| 2026-10-26 | 20,404 |
| 2026-10-27 | 20,761 |
| 2026-10-28 | 15,842 |
| 2026-10-29 | 9,724 |
| 2026-10-30 | 62,101 |
| 2026-10-31 | 88,293 |
| 2026-11-01 | 27,939 |
| 2026-11-02 | 28,915 |
| 2026-11-03 | 29,945 |
| 2026-11-04 | 29,756 |
| 2026-11-05 | 25,370 |
| 2026-11-06 | 36,791 |
| 2026-11-07 | 24,557 |
| 2026-11-08 | 26,222 |
| 2026-11-09 | 25,656 |
| 2026-11-10 | 32,845 |
| 2026-11-11 | 22,474 |
| 2026-11-12 | 20,574 |
| 2026-11-13 | 19,724 |
| 2026-11-14 | 23,057 |
| 2026-11-15 | 17,525 |
| 2026-11-16 | 18,047 |
| 2026-11-17 | 15,303 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 193096 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
