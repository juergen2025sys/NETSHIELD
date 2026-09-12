# Seen-DB Expiry Forecast

Lauf: 2026-09-12 16:20 CEST (Europe/Berlin)
Gesamt: 11,055,868 IPs in seen_db.json (8,166,700 aktiv/180-Tage-Pfad, 2,889,168 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 0 |
| 8-14 Tage | 74,915 |
| 15-30 Tage | 562,691 |
| 31-60 Tage | 2,472,325 |
| 61-90 Tage | 1,066,167 |
| 91-180 Tage | 3,990,602 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 499,634 |
| 0-3 Tage | 52,443 |
| 4-7 Tage | 26,000 |
| 8-14 Tage | 667,757 |
| 15-30 Tage | 1,643,334 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-12 | 11,909 |
| 2026-09-13 | 12,053 |
| 2026-09-14 | 12,862 |
| 2026-09-15 | 15,619 |
| 2026-09-16 | 6,250 |
| 2026-09-17 | 5,784 |
| 2026-09-18 | 8,806 |
| 2026-09-19 | 5,160 |
| 2026-09-20 | 5,068 |
| 2026-09-21 | 5,055 |
| 2026-09-22 | 11,205 |
| 2026-09-23 | 5,164 |
| 2026-09-24 | 11,440 |
| 2026-09-25 | 5,509 |
| 2026-09-26 | 624,316 |
| 2026-09-27 | 6,347 |
| 2026-09-28 | 784 |
| 2026-09-30 | 59,902 |
| 2026-10-01 | 7,723 |
| 2026-10-02 | 1,309,433 |
| 2026-10-03 | 2,999 |
| 2026-10-04 | 6,982 |
| 2026-10-05 | 2,937 |
| 2026-10-06 | 8,344 |
| 2026-10-07 | 8,101 |
| 2026-10-08 | 7,388 |
| 2026-10-09 | 152,534 |
| 2026-10-10 | 8,310 |
| 2026-10-11 | 23,428 |
| 2026-10-12 | 33,798 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **499,634** IPs. Brutto faellig in den naechsten 30 Tagen: **2,385,210**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,824,844**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-12 | 11,909 | 2,000 |
| 2026-09-13 | 12,053 | 2,000 |
| 2026-09-14 | 12,862 | 2,000 |
| 2026-09-15 | 15,619 | 2,000 |
| 2026-09-16 | 6,250 | 2,000 |
| 2026-09-17 | 5,784 | 2,000 |
| 2026-09-18 | 8,806 | 2,000 |
| 2026-09-19 | 5,160 | 2,000 |
| 2026-09-20 | 5,068 | 2,000 |
| 2026-09-21 | 5,055 | 2,000 |
| 2026-09-22 | 11,205 | 2,000 |
| 2026-09-23 | 5,164 | 2,000 |
| 2026-09-24 | 11,440 | 2,000 |
| 2026-09-25 | 5,509 | 2,000 |
| 2026-09-26 | 624,316 | 2,000 |
| 2026-09-27 | 6,347 | 2,000 |
| 2026-09-28 | 784 | 2,000 |
| 2026-09-30 | 59,902 | 2,000 |
| 2026-10-01 | 7,723 | 2,000 |
| 2026-10-02 | 1,309,433 | 2,000 |
| 2026-10-03 | 2,999 | 2,000 |
| 2026-10-04 | 6,982 | 2,000 |
| 2026-10-05 | 2,937 | 2,000 |
| 2026-10-06 | 8,344 | 2,000 |
| 2026-10-07 | 8,101 | 2,000 |
| 2026-10-08 | 7,388 | 2,000 |
| 2026-10-09 | 152,534 | 2,000 |
| 2026-10-10 | 8,310 | 2,000 |
| 2026-10-11 | 23,428 | 2,000 |
| 2026-10-12 | 33,798 | 2,000 |

> Hinweis: Der Rueckstau von 2,824,844 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,454 |
| 2026-09-23 | 13,109 |
| 2026-09-24 | 16,764 |
| 2026-09-25 | 21,039 |
| 2026-09-26 | 17,549 |
| 2026-09-27 | 15,146 |
| 2026-09-28 | 11,640 |
| 2026-09-29 | 9,400 |
| 2026-09-30 | 10,249 |
| 2026-10-01 | 16,673 |
| 2026-10-02 | 7,767 |
| 2026-10-03 | 7,378 |
| 2026-10-04 | 12,719 |
| 2026-10-05 | 17,637 |
| 2026-10-06 | 16,218 |
| 2026-10-07 | 15,144 |
| 2026-10-08 | 61,837 |
| 2026-10-09 | 224,666 |
| 2026-10-10 | 53,473 |
| 2026-10-11 | 16,089 |
| 2026-10-12 | 66,655 |
| 2026-10-13 | 1,588,675 |
| 2026-10-14 | 32,947 |
| 2026-10-15 | 41,429 |
| 2026-10-16 | 51,463 |
| 2026-10-17 | 24,425 |
| 2026-10-18 | 14,352 |
| 2026-10-19 | 22,572 |
| 2026-10-20 | 11,195 |
| 2026-10-21 | 11,170 |
| 2026-10-22 | 30,904 |
| 2026-10-23 | 50,569 |
| 2026-10-24 | 41,873 |
| 2026-10-25 | 21,737 |
| 2026-10-26 | 20,483 |
| 2026-10-27 | 20,831 |
| 2026-10-28 | 15,896 |
| 2026-10-29 | 9,778 |
| 2026-10-30 | 62,265 |
| 2026-10-31 | 88,386 |
| 2026-11-01 | 28,013 |
| 2026-11-02 | 29,006 |
| 2026-11-03 | 30,056 |
| 2026-11-04 | 29,846 |
| 2026-11-05 | 25,444 |
| 2026-11-06 | 36,878 |
| 2026-11-07 | 24,617 |
| 2026-11-08 | 26,292 |
| 2026-11-09 | 25,744 |
| 2026-11-10 | 32,945 |
| 2026-11-11 | 22,534 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 190333 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
