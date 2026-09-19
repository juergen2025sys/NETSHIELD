# Seen-DB Expiry Forecast

Lauf: 2026-09-19 11:23 CEST (Europe/Berlin)
Gesamt: 11,527,431 IPs in seen_db.json (8,574,058 aktiv/180-Tage-Pfad, 2,953,373 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 74,611 |
| 8-14 Tage | 77,923 |
| 15-30 Tage | 2,255,636 |
| 31-60 Tage | 828,330 |
| 61-90 Tage | 1,093,336 |
| 91-180 Tage | 4,244,222 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 570,072 |
| 0-3 Tage | 26,332 |
| 4-7 Tage | 645,939 |
| 8-14 Tage | 1,385,206 |
| 15-30 Tage | 325,824 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-19 | 5,126 |
| 2026-09-20 | 5,038 |
| 2026-09-21 | 5,017 |
| 2026-09-22 | 11,151 |
| 2026-09-23 | 5,119 |
| 2026-09-24 | 11,407 |
| 2026-09-25 | 5,473 |
| 2026-09-26 | 623,940 |
| 2026-09-27 | 6,295 |
| 2026-09-28 | 777 |
| 2026-09-30 | 59,729 |
| 2026-10-01 | 7,672 |
| 2026-10-02 | 1,307,759 |
| 2026-10-03 | 2,974 |
| 2026-10-04 | 6,929 |
| 2026-10-05 | 2,912 |
| 2026-10-06 | 8,294 |
| 2026-10-07 | 8,012 |
| 2026-10-08 | 7,339 |
| 2026-10-09 | 152,020 |
| 2026-10-10 | 8,221 |
| 2026-10-11 | 23,192 |
| 2026-10-12 | 33,330 |
| 2026-10-13 | 9,056 |
| 2026-10-14 | 8,106 |
| 2026-10-15 | 8,871 |
| 2026-10-16 | 16,285 |
| 2026-10-17 | 10,665 |
| 2026-10-18 | 9,424 |
| 2026-10-19 | 6,155 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **570,072** IPs. Brutto faellig in den naechsten 30 Tagen: **2,376,288**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,886,360**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-19 | 5,126 | 2,000 |
| 2026-09-20 | 5,038 | 2,000 |
| 2026-09-21 | 5,017 | 2,000 |
| 2026-09-22 | 11,151 | 2,000 |
| 2026-09-23 | 5,119 | 2,000 |
| 2026-09-24 | 11,407 | 2,000 |
| 2026-09-25 | 5,473 | 2,000 |
| 2026-09-26 | 623,940 | 2,000 |
| 2026-09-27 | 6,295 | 2,000 |
| 2026-09-28 | 777 | 2,000 |
| 2026-09-30 | 59,729 | 2,000 |
| 2026-10-01 | 7,672 | 2,000 |
| 2026-10-02 | 1,307,759 | 2,000 |
| 2026-10-03 | 2,974 | 2,000 |
| 2026-10-04 | 6,929 | 2,000 |
| 2026-10-05 | 2,912 | 2,000 |
| 2026-10-06 | 8,294 | 2,000 |
| 2026-10-07 | 8,012 | 2,000 |
| 2026-10-08 | 7,339 | 2,000 |
| 2026-10-09 | 152,020 | 2,000 |
| 2026-10-10 | 8,221 | 2,000 |
| 2026-10-11 | 23,192 | 2,000 |
| 2026-10-12 | 33,330 | 2,000 |
| 2026-10-13 | 9,056 | 2,000 |
| 2026-10-14 | 8,106 | 2,000 |
| 2026-10-15 | 8,871 | 2,000 |
| 2026-10-16 | 16,285 | 2,000 |
| 2026-10-17 | 10,665 | 2,000 |
| 2026-10-18 | 9,424 | 2,000 |
| 2026-10-19 | 6,155 | 2,000 |

> Hinweis: Der Rueckstau von 2,886,360 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,436 |
| 2026-09-23 | 13,066 |
| 2026-09-24 | 16,685 |
| 2026-09-25 | 20,952 |
| 2026-09-26 | 17,472 |
| 2026-09-27 | 15,056 |
| 2026-09-28 | 11,620 |
| 2026-09-29 | 9,367 |
| 2026-09-30 | 10,191 |
| 2026-10-01 | 16,617 |
| 2026-10-02 | 7,731 |
| 2026-10-03 | 7,341 |
| 2026-10-04 | 12,642 |
| 2026-10-05 | 17,560 |
| 2026-10-06 | 16,150 |
| 2026-10-07 | 15,090 |
| 2026-10-08 | 61,500 |
| 2026-10-09 | 223,529 |
| 2026-10-10 | 53,412 |
| 2026-10-11 | 16,065 |
| 2026-10-12 | 66,604 |
| 2026-10-13 | 1,586,326 |
| 2026-10-14 | 32,926 |
| 2026-10-15 | 41,366 |
| 2026-10-16 | 51,386 |
| 2026-10-17 | 24,349 |
| 2026-10-18 | 14,302 |
| 2026-10-19 | 22,429 |
| 2026-10-20 | 11,163 |
| 2026-10-21 | 11,138 |
| 2026-10-22 | 30,809 |
| 2026-10-23 | 50,478 |
| 2026-10-24 | 41,792 |
| 2026-10-25 | 21,671 |
| 2026-10-26 | 20,396 |
| 2026-10-27 | 20,758 |
| 2026-10-28 | 15,841 |
| 2026-10-29 | 9,720 |
| 2026-10-30 | 62,089 |
| 2026-10-31 | 88,292 |
| 2026-11-01 | 27,937 |
| 2026-11-02 | 28,907 |
| 2026-11-03 | 29,936 |
| 2026-11-04 | 29,745 |
| 2026-11-05 | 25,365 |
| 2026-11-06 | 36,785 |
| 2026-11-07 | 24,555 |
| 2026-11-08 | 26,215 |
| 2026-11-09 | 25,643 |
| 2026-11-10 | 32,842 |
| 2026-11-11 | 22,465 |
| 2026-11-12 | 20,571 |
| 2026-11-13 | 19,720 |
| 2026-11-14 | 23,054 |
| 2026-11-15 | 17,523 |
| 2026-11-16 | 18,045 |
| 2026-11-17 | 15,297 |
| 2026-11-18 | 19,578 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 193597 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
