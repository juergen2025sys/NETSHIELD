# Seen-DB Expiry Forecast

Lauf: 2026-09-21 08:10 CEST (Europe/Berlin)
Gesamt: 11,645,885 IPs in seen_db.json (8,671,845 aktiv/180-Tage-Pfad, 2,974,040 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 101,188 |
| 8-14 Tage | 81,380 |
| 15-30 Tage | 2,246,561 |
| 31-60 Tage | 1,006,104 |
| 61-90 Tage | 932,475 |
| 91-180 Tage | 4,304,137 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 579,784 |
| 0-3 Tage | 32,637 |
| 4-7 Tage | 636,359 |
| 8-14 Tage | 1,387,557 |
| 15-30 Tage | 337,703 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-21 | 5,004 |
| 2026-09-22 | 11,134 |
| 2026-09-23 | 5,112 |
| 2026-09-24 | 11,387 |
| 2026-09-25 | 5,462 |
| 2026-09-26 | 623,837 |
| 2026-09-27 | 6,286 |
| 2026-09-28 | 774 |
| 2026-09-30 | 59,698 |
| 2026-10-01 | 7,657 |
| 2026-10-02 | 1,307,396 |
| 2026-10-03 | 2,973 |
| 2026-10-04 | 6,927 |
| 2026-10-05 | 2,906 |
| 2026-10-06 | 8,281 |
| 2026-10-07 | 7,999 |
| 2026-10-08 | 7,320 |
| 2026-10-09 | 151,917 |
| 2026-10-10 | 8,209 |
| 2026-10-11 | 23,137 |
| 2026-10-12 | 33,293 |
| 2026-10-13 | 9,020 |
| 2026-10-14 | 8,084 |
| 2026-10-15 | 8,839 |
| 2026-10-16 | 16,237 |
| 2026-10-17 | 10,635 |
| 2026-10-18 | 9,388 |
| 2026-10-19 | 5,722 |
| 2026-10-20 | 10,374 |
| 2026-10-21 | 10,859 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **579,784** IPs. Brutto faellig in den naechsten 30 Tagen: **2,385,867**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,905,651**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-21 | 5,004 | 2,000 |
| 2026-09-22 | 11,134 | 2,000 |
| 2026-09-23 | 5,112 | 2,000 |
| 2026-09-24 | 11,387 | 2,000 |
| 2026-09-25 | 5,462 | 2,000 |
| 2026-09-26 | 623,837 | 2,000 |
| 2026-09-27 | 6,286 | 2,000 |
| 2026-09-28 | 774 | 2,000 |
| 2026-09-30 | 59,698 | 2,000 |
| 2026-10-01 | 7,657 | 2,000 |
| 2026-10-02 | 1,307,396 | 2,000 |
| 2026-10-03 | 2,973 | 2,000 |
| 2026-10-04 | 6,927 | 2,000 |
| 2026-10-05 | 2,906 | 2,000 |
| 2026-10-06 | 8,281 | 2,000 |
| 2026-10-07 | 7,999 | 2,000 |
| 2026-10-08 | 7,320 | 2,000 |
| 2026-10-09 | 151,917 | 2,000 |
| 2026-10-10 | 8,209 | 2,000 |
| 2026-10-11 | 23,137 | 2,000 |
| 2026-10-12 | 33,293 | 2,000 |
| 2026-10-13 | 9,020 | 2,000 |
| 2026-10-14 | 8,084 | 2,000 |
| 2026-10-15 | 8,839 | 2,000 |
| 2026-10-16 | 16,237 | 2,000 |
| 2026-10-17 | 10,635 | 2,000 |
| 2026-10-18 | 9,388 | 2,000 |
| 2026-10-19 | 5,722 | 2,000 |
| 2026-10-20 | 10,374 | 2,000 |
| 2026-10-21 | 10,859 | 2,000 |

> Hinweis: Der Rueckstau von 2,905,651 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,434 |
| 2026-09-23 | 13,057 |
| 2026-09-24 | 16,667 |
| 2026-09-25 | 20,932 |
| 2026-09-26 | 17,449 |
| 2026-09-27 | 15,039 |
| 2026-09-28 | 11,610 |
| 2026-09-29 | 9,360 |
| 2026-09-30 | 10,177 |
| 2026-10-01 | 16,606 |
| 2026-10-02 | 7,722 |
| 2026-10-03 | 7,336 |
| 2026-10-04 | 12,631 |
| 2026-10-05 | 17,548 |
| 2026-10-06 | 16,136 |
| 2026-10-07 | 15,071 |
| 2026-10-08 | 61,443 |
| 2026-10-09 | 223,188 |
| 2026-10-10 | 53,391 |
| 2026-10-11 | 16,061 |
| 2026-10-12 | 66,594 |
| 2026-10-13 | 1,585,778 |
| 2026-10-14 | 32,924 |
| 2026-10-15 | 41,351 |
| 2026-10-16 | 51,329 |
| 2026-10-17 | 24,330 |
| 2026-10-18 | 14,289 |
| 2026-10-19 | 22,389 |
| 2026-10-20 | 11,156 |
| 2026-10-21 | 11,131 |
| 2026-10-22 | 30,782 |
| 2026-10-23 | 50,456 |
| 2026-10-24 | 41,773 |
| 2026-10-25 | 21,651 |
| 2026-10-26 | 20,371 |
| 2026-10-27 | 20,740 |
| 2026-10-28 | 15,834 |
| 2026-10-29 | 9,707 |
| 2026-10-30 | 62,043 |
| 2026-10-31 | 88,276 |
| 2026-11-01 | 27,916 |
| 2026-11-02 | 28,882 |
| 2026-11-03 | 29,899 |
| 2026-11-04 | 29,717 |
| 2026-11-05 | 25,344 |
| 2026-11-06 | 36,759 |
| 2026-11-07 | 24,546 |
| 2026-11-08 | 26,192 |
| 2026-11-09 | 25,626 |
| 2026-11-10 | 32,821 |
| 2026-11-11 | 22,449 |
| 2026-11-12 | 20,558 |
| 2026-11-13 | 19,707 |
| 2026-11-14 | 23,039 |
| 2026-11-15 | 17,515 |
| 2026-11-16 | 18,029 |
| 2026-11-17 | 15,287 |
| 2026-11-18 | 19,562 |
| 2026-11-19 | 174,341 |
| 2026-11-20 | 26,282 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 194867 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
