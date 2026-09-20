# Seen-DB Expiry Forecast

Lauf: 2026-09-20 16:21 CEST (Europe/Berlin)
Gesamt: 11,606,039 IPs in seen_db.json (8,641,279 aktiv/180-Tage-Pfad, 2,964,760 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 89,610 |
| 8-14 Tage | 75,468 |
| 15-30 Tage | 2,253,314 |
| 31-60 Tage | 991,104 |
| 61-90 Tage | 944,426 |
| 91-180 Tage | 4,287,357 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 574,863 |
| 0-3 Tage | 26,287 |
| 4-7 Tage | 647,002 |
| 8-14 Tage | 1,385,504 |
| 15-30 Tage | 331,104 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-20 | 5,029 |
| 2026-09-21 | 5,006 |
| 2026-09-22 | 11,138 |
| 2026-09-23 | 5,114 |
| 2026-09-24 | 11,392 |
| 2026-09-25 | 5,465 |
| 2026-09-26 | 623,857 |
| 2026-09-27 | 6,288 |
| 2026-09-28 | 774 |
| 2026-09-30 | 59,703 |
| 2026-10-01 | 7,660 |
| 2026-10-02 | 1,307,465 |
| 2026-10-03 | 2,974 |
| 2026-10-04 | 6,928 |
| 2026-10-05 | 2,907 |
| 2026-10-06 | 8,283 |
| 2026-10-07 | 8,003 |
| 2026-10-08 | 7,326 |
| 2026-10-09 | 151,949 |
| 2026-10-10 | 8,210 |
| 2026-10-11 | 23,149 |
| 2026-10-12 | 33,303 |
| 2026-10-13 | 9,028 |
| 2026-10-14 | 8,094 |
| 2026-10-15 | 8,846 |
| 2026-10-16 | 16,253 |
| 2026-10-17 | 10,647 |
| 2026-10-18 | 9,400 |
| 2026-10-19 | 5,731 |
| 2026-10-20 | 10,463 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **574,863** IPs. Brutto faellig in den naechsten 30 Tagen: **2,380,385**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,895,248**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-20 | 5,029 | 2,000 |
| 2026-09-21 | 5,006 | 2,000 |
| 2026-09-22 | 11,138 | 2,000 |
| 2026-09-23 | 5,114 | 2,000 |
| 2026-09-24 | 11,392 | 2,000 |
| 2026-09-25 | 5,465 | 2,000 |
| 2026-09-26 | 623,857 | 2,000 |
| 2026-09-27 | 6,288 | 2,000 |
| 2026-09-28 | 774 | 2,000 |
| 2026-09-30 | 59,703 | 2,000 |
| 2026-10-01 | 7,660 | 2,000 |
| 2026-10-02 | 1,307,465 | 2,000 |
| 2026-10-03 | 2,974 | 2,000 |
| 2026-10-04 | 6,928 | 2,000 |
| 2026-10-05 | 2,907 | 2,000 |
| 2026-10-06 | 8,283 | 2,000 |
| 2026-10-07 | 8,003 | 2,000 |
| 2026-10-08 | 7,326 | 2,000 |
| 2026-10-09 | 151,949 | 2,000 |
| 2026-10-10 | 8,210 | 2,000 |
| 2026-10-11 | 23,149 | 2,000 |
| 2026-10-12 | 33,303 | 2,000 |
| 2026-10-13 | 9,028 | 2,000 |
| 2026-10-14 | 8,094 | 2,000 |
| 2026-10-15 | 8,846 | 2,000 |
| 2026-10-16 | 16,253 | 2,000 |
| 2026-10-17 | 10,647 | 2,000 |
| 2026-10-18 | 9,400 | 2,000 |
| 2026-10-19 | 5,731 | 2,000 |
| 2026-10-20 | 10,463 | 2,000 |

> Hinweis: Der Rueckstau von 2,895,248 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,436 |
| 2026-09-23 | 13,064 |
| 2026-09-24 | 16,674 |
| 2026-09-25 | 20,937 |
| 2026-09-26 | 17,457 |
| 2026-09-27 | 15,042 |
| 2026-09-28 | 11,612 |
| 2026-09-29 | 9,363 |
| 2026-09-30 | 10,182 |
| 2026-10-01 | 16,609 |
| 2026-10-02 | 7,728 |
| 2026-10-03 | 7,338 |
| 2026-10-04 | 12,636 |
| 2026-10-05 | 17,551 |
| 2026-10-06 | 16,142 |
| 2026-10-07 | 15,073 |
| 2026-10-08 | 61,460 |
| 2026-10-09 | 223,295 |
| 2026-10-10 | 53,395 |
| 2026-10-11 | 16,062 |
| 2026-10-12 | 66,597 |
| 2026-10-13 | 1,585,930 |
| 2026-10-14 | 32,924 |
| 2026-10-15 | 41,358 |
| 2026-10-16 | 51,336 |
| 2026-10-17 | 24,333 |
| 2026-10-18 | 14,291 |
| 2026-10-19 | 22,408 |
| 2026-10-20 | 11,159 |
| 2026-10-21 | 11,133 |
| 2026-10-22 | 30,786 |
| 2026-10-23 | 50,462 |
| 2026-10-24 | 41,780 |
| 2026-10-25 | 21,658 |
| 2026-10-26 | 20,375 |
| 2026-10-27 | 20,750 |
| 2026-10-28 | 15,836 |
| 2026-10-29 | 9,710 |
| 2026-10-30 | 62,055 |
| 2026-10-31 | 88,281 |
| 2026-11-01 | 27,921 |
| 2026-11-02 | 28,887 |
| 2026-11-03 | 29,908 |
| 2026-11-04 | 29,722 |
| 2026-11-05 | 25,351 |
| 2026-11-06 | 36,765 |
| 2026-11-07 | 24,549 |
| 2026-11-08 | 26,195 |
| 2026-11-09 | 25,627 |
| 2026-11-10 | 32,825 |
| 2026-11-11 | 22,452 |
| 2026-11-12 | 20,561 |
| 2026-11-13 | 19,708 |
| 2026-11-14 | 23,042 |
| 2026-11-15 | 17,518 |
| 2026-11-16 | 18,031 |
| 2026-11-17 | 15,290 |
| 2026-11-18 | 19,567 |
| 2026-11-19 | 174,359 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 194444 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
