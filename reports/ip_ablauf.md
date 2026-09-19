# Seen-DB Expiry Forecast

Lauf: 2026-09-19 21:22 CEST (Europe/Berlin)
Gesamt: 11,560,330 IPs in seen_db.json (8,605,229 aktiv/180-Tage-Pfad, 2,955,101 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 74,588 |
| 8-14 Tage | 77,898 |
| 15-30 Tage | 2,255,208 |
| 31-60 Tage | 828,127 |
| 61-90 Tage | 1,093,079 |
| 91-180 Tage | 4,276,329 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 569,873 |
| 0-3 Tage | 26,307 |
| 4-7 Tage | 645,855 |
| 8-14 Tage | 1,384,995 |
| 15-30 Tage | 328,071 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-19 | 5,121 |
| 2026-09-20 | 5,030 |
| 2026-09-21 | 5,011 |
| 2026-09-22 | 11,145 |
| 2026-09-23 | 5,114 |
| 2026-09-24 | 11,395 |
| 2026-09-25 | 5,468 |
| 2026-09-26 | 623,878 |
| 2026-09-27 | 6,291 |
| 2026-09-28 | 776 |
| 2026-09-30 | 59,715 |
| 2026-10-01 | 7,663 |
| 2026-10-02 | 1,307,576 |
| 2026-10-03 | 2,974 |
| 2026-10-04 | 6,928 |
| 2026-10-05 | 2,910 |
| 2026-10-06 | 8,287 |
| 2026-10-07 | 8,008 |
| 2026-10-08 | 7,335 |
| 2026-10-09 | 151,986 |
| 2026-10-10 | 8,216 |
| 2026-10-11 | 23,168 |
| 2026-10-12 | 33,326 |
| 2026-10-13 | 9,045 |
| 2026-10-14 | 8,099 |
| 2026-10-15 | 8,867 |
| 2026-10-16 | 16,274 |
| 2026-10-17 | 10,659 |
| 2026-10-18 | 9,416 |
| 2026-10-19 | 5,770 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **569,873** IPs. Brutto faellig in den naechsten 30 Tagen: **2,375,451**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,885,324**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-19 | 5,121 | 2,000 |
| 2026-09-20 | 5,030 | 2,000 |
| 2026-09-21 | 5,011 | 2,000 |
| 2026-09-22 | 11,145 | 2,000 |
| 2026-09-23 | 5,114 | 2,000 |
| 2026-09-24 | 11,395 | 2,000 |
| 2026-09-25 | 5,468 | 2,000 |
| 2026-09-26 | 623,878 | 2,000 |
| 2026-09-27 | 6,291 | 2,000 |
| 2026-09-28 | 776 | 2,000 |
| 2026-09-30 | 59,715 | 2,000 |
| 2026-10-01 | 7,663 | 2,000 |
| 2026-10-02 | 1,307,576 | 2,000 |
| 2026-10-03 | 2,974 | 2,000 |
| 2026-10-04 | 6,928 | 2,000 |
| 2026-10-05 | 2,910 | 2,000 |
| 2026-10-06 | 8,287 | 2,000 |
| 2026-10-07 | 8,008 | 2,000 |
| 2026-10-08 | 7,335 | 2,000 |
| 2026-10-09 | 151,986 | 2,000 |
| 2026-10-10 | 8,216 | 2,000 |
| 2026-10-11 | 23,168 | 2,000 |
| 2026-10-12 | 33,326 | 2,000 |
| 2026-10-13 | 9,045 | 2,000 |
| 2026-10-14 | 8,099 | 2,000 |
| 2026-10-15 | 8,867 | 2,000 |
| 2026-10-16 | 16,274 | 2,000 |
| 2026-10-17 | 10,659 | 2,000 |
| 2026-10-18 | 9,416 | 2,000 |
| 2026-10-19 | 5,770 | 2,000 |

> Hinweis: Der Rueckstau von 2,885,324 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,436 |
| 2026-09-23 | 13,065 |
| 2026-09-24 | 16,677 |
| 2026-09-25 | 20,942 |
| 2026-09-26 | 17,468 |
| 2026-09-27 | 15,046 |
| 2026-09-28 | 11,616 |
| 2026-09-29 | 9,366 |
| 2026-09-30 | 10,187 |
| 2026-10-01 | 16,613 |
| 2026-10-02 | 7,730 |
| 2026-10-03 | 7,340 |
| 2026-10-04 | 12,640 |
| 2026-10-05 | 17,556 |
| 2026-10-06 | 16,147 |
| 2026-10-07 | 15,079 |
| 2026-10-08 | 61,473 |
| 2026-10-09 | 223,427 |
| 2026-10-10 | 53,399 |
| 2026-10-11 | 16,063 |
| 2026-10-12 | 66,601 |
| 2026-10-13 | 1,586,142 |
| 2026-10-14 | 32,924 |
| 2026-10-15 | 41,361 |
| 2026-10-16 | 51,343 |
| 2026-10-17 | 24,344 |
| 2026-10-18 | 14,294 |
| 2026-10-19 | 22,415 |
| 2026-10-20 | 11,160 |
| 2026-10-21 | 11,137 |
| 2026-10-22 | 30,794 |
| 2026-10-23 | 50,467 |
| 2026-10-24 | 41,785 |
| 2026-10-25 | 21,668 |
| 2026-10-26 | 20,387 |
| 2026-10-27 | 20,754 |
| 2026-10-28 | 15,838 |
| 2026-10-29 | 9,715 |
| 2026-10-30 | 62,065 |
| 2026-10-31 | 88,285 |
| 2026-11-01 | 27,927 |
| 2026-11-02 | 28,898 |
| 2026-11-03 | 29,929 |
| 2026-11-04 | 29,737 |
| 2026-11-05 | 25,357 |
| 2026-11-06 | 36,775 |
| 2026-11-07 | 24,553 |
| 2026-11-08 | 26,209 |
| 2026-11-09 | 25,636 |
| 2026-11-10 | 32,834 |
| 2026-11-11 | 22,463 |
| 2026-11-12 | 20,566 |
| 2026-11-13 | 19,713 |
| 2026-11-14 | 23,045 |
| 2026-11-15 | 17,523 |
| 2026-11-16 | 18,039 |
| 2026-11-17 | 15,295 |
| 2026-11-18 | 19,573 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 193687 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
