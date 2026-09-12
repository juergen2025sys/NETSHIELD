# Seen-DB Expiry Forecast

Lauf: 2026-09-12 13:11 CEST (Europe/Berlin)
Gesamt: 11,044,348 IPs in seen_db.json (8,155,430 aktiv/180-Tage-Pfad, 2,888,918 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 0 |
| 8-14 Tage | 74,927 |
| 15-30 Tage | 562,758 |
| 31-60 Tage | 2,472,429 |
| 61-90 Tage | 1,066,233 |
| 91-180 Tage | 3,979,083 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 499,658 |
| 0-3 Tage | 52,448 |
| 4-7 Tage | 26,005 |
| 8-14 Tage | 667,771 |
| 15-30 Tage | 1,643,036 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-12 | 11,911 |
| 2026-09-13 | 12,054 |
| 2026-09-14 | 12,863 |
| 2026-09-15 | 15,620 |
| 2026-09-16 | 6,252 |
| 2026-09-17 | 5,786 |
| 2026-09-18 | 8,807 |
| 2026-09-19 | 5,160 |
| 2026-09-20 | 5,069 |
| 2026-09-21 | 5,057 |
| 2026-09-22 | 11,206 |
| 2026-09-23 | 5,167 |
| 2026-09-24 | 11,442 |
| 2026-09-25 | 5,509 |
| 2026-09-26 | 624,321 |
| 2026-09-27 | 6,348 |
| 2026-09-28 | 784 |
| 2026-09-30 | 59,904 |
| 2026-10-01 | 7,724 |
| 2026-10-02 | 1,309,467 |
| 2026-10-03 | 2,999 |
| 2026-10-04 | 6,982 |
| 2026-10-05 | 2,938 |
| 2026-10-06 | 8,347 |
| 2026-10-07 | 8,103 |
| 2026-10-08 | 7,388 |
| 2026-10-09 | 152,539 |
| 2026-10-10 | 8,312 |
| 2026-10-11 | 23,435 |
| 2026-10-12 | 33,848 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **499,658** IPs. Brutto faellig in den naechsten 30 Tagen: **2,385,342**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,825,000**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-12 | 11,911 | 2,000 |
| 2026-09-13 | 12,054 | 2,000 |
| 2026-09-14 | 12,863 | 2,000 |
| 2026-09-15 | 15,620 | 2,000 |
| 2026-09-16 | 6,252 | 2,000 |
| 2026-09-17 | 5,786 | 2,000 |
| 2026-09-18 | 8,807 | 2,000 |
| 2026-09-19 | 5,160 | 2,000 |
| 2026-09-20 | 5,069 | 2,000 |
| 2026-09-21 | 5,057 | 2,000 |
| 2026-09-22 | 11,206 | 2,000 |
| 2026-09-23 | 5,167 | 2,000 |
| 2026-09-24 | 11,442 | 2,000 |
| 2026-09-25 | 5,509 | 2,000 |
| 2026-09-26 | 624,321 | 2,000 |
| 2026-09-27 | 6,348 | 2,000 |
| 2026-09-28 | 784 | 2,000 |
| 2026-09-30 | 59,904 | 2,000 |
| 2026-10-01 | 7,724 | 2,000 |
| 2026-10-02 | 1,309,467 | 2,000 |
| 2026-10-03 | 2,999 | 2,000 |
| 2026-10-04 | 6,982 | 2,000 |
| 2026-10-05 | 2,938 | 2,000 |
| 2026-10-06 | 8,347 | 2,000 |
| 2026-10-07 | 8,103 | 2,000 |
| 2026-10-08 | 7,388 | 2,000 |
| 2026-10-09 | 152,539 | 2,000 |
| 2026-10-10 | 8,312 | 2,000 |
| 2026-10-11 | 23,435 | 2,000 |
| 2026-10-12 | 33,848 | 2,000 |

> Hinweis: Der Rueckstau von 2,825,000 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,454 |
| 2026-09-23 | 13,112 |
| 2026-09-24 | 16,767 |
| 2026-09-25 | 21,040 |
| 2026-09-26 | 17,554 |
| 2026-09-27 | 15,148 |
| 2026-09-28 | 11,641 |
| 2026-09-29 | 9,400 |
| 2026-09-30 | 10,250 |
| 2026-10-01 | 16,674 |
| 2026-10-02 | 7,769 |
| 2026-10-03 | 7,378 |
| 2026-10-04 | 12,724 |
| 2026-10-05 | 17,641 |
| 2026-10-06 | 16,218 |
| 2026-10-07 | 15,145 |
| 2026-10-08 | 61,851 |
| 2026-10-09 | 224,696 |
| 2026-10-10 | 53,477 |
| 2026-10-11 | 16,090 |
| 2026-10-12 | 66,656 |
| 2026-10-13 | 1,588,733 |
| 2026-10-14 | 32,947 |
| 2026-10-15 | 41,430 |
| 2026-10-16 | 51,465 |
| 2026-10-17 | 24,425 |
| 2026-10-18 | 14,353 |
| 2026-10-19 | 22,574 |
| 2026-10-20 | 11,196 |
| 2026-10-21 | 11,172 |
| 2026-10-22 | 30,905 |
| 2026-10-23 | 50,570 |
| 2026-10-24 | 41,873 |
| 2026-10-25 | 21,738 |
| 2026-10-26 | 20,483 |
| 2026-10-27 | 20,834 |
| 2026-10-28 | 15,898 |
| 2026-10-29 | 9,778 |
| 2026-10-30 | 62,268 |
| 2026-10-31 | 88,390 |
| 2026-11-01 | 28,015 |
| 2026-11-02 | 29,008 |
| 2026-11-03 | 30,060 |
| 2026-11-04 | 29,846 |
| 2026-11-05 | 25,444 |
| 2026-11-06 | 36,881 |
| 2026-11-07 | 24,619 |
| 2026-11-08 | 26,295 |
| 2026-11-09 | 25,745 |
| 2026-11-10 | 32,948 |
| 2026-11-11 | 22,536 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 190242 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
