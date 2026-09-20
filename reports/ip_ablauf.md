# Seen-DB Expiry Forecast

Lauf: 2026-09-20 07:19 CEST (Europe/Berlin)
Gesamt: 11,584,609 IPs in seen_db.json (8,621,680 aktiv/180-Tage-Pfad, 2,962,929 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 89,628 |
| 8-14 Tage | 75,484 |
| 15-30 Tage | 2,253,544 |
| 31-60 Tage | 991,233 |
| 61-90 Tage | 944,548 |
| 91-180 Tage | 4,267,243 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 574,960 |
| 0-3 Tage | 26,294 |
| 4-7 Tage | 647,015 |
| 8-14 Tage | 1,385,577 |
| 15-30 Tage | 329,083 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-20 | 5,029 |
| 2026-09-21 | 5,011 |
| 2026-09-22 | 11,140 |
| 2026-09-23 | 5,114 |
| 2026-09-24 | 11,392 |
| 2026-09-25 | 5,465 |
| 2026-09-26 | 623,868 |
| 2026-09-27 | 6,290 |
| 2026-09-28 | 774 |
| 2026-09-30 | 59,713 |
| 2026-10-01 | 7,662 |
| 2026-10-02 | 1,307,526 |
| 2026-10-03 | 2,974 |
| 2026-10-04 | 6,928 |
| 2026-10-05 | 2,910 |
| 2026-10-06 | 8,285 |
| 2026-10-07 | 8,007 |
| 2026-10-08 | 7,328 |
| 2026-10-09 | 151,973 |
| 2026-10-10 | 8,211 |
| 2026-10-11 | 23,158 |
| 2026-10-12 | 33,311 |
| 2026-10-13 | 9,036 |
| 2026-10-14 | 8,095 |
| 2026-10-15 | 8,857 |
| 2026-10-16 | 16,264 |
| 2026-10-17 | 10,656 |
| 2026-10-18 | 9,411 |
| 2026-10-19 | 5,765 |
| 2026-10-20 | 10,784 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **574,960** IPs. Brutto faellig in den naechsten 30 Tagen: **2,380,937**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,895,897**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-20 | 5,029 | 2,000 |
| 2026-09-21 | 5,011 | 2,000 |
| 2026-09-22 | 11,140 | 2,000 |
| 2026-09-23 | 5,114 | 2,000 |
| 2026-09-24 | 11,392 | 2,000 |
| 2026-09-25 | 5,465 | 2,000 |
| 2026-09-26 | 623,868 | 2,000 |
| 2026-09-27 | 6,290 | 2,000 |
| 2026-09-28 | 774 | 2,000 |
| 2026-09-30 | 59,713 | 2,000 |
| 2026-10-01 | 7,662 | 2,000 |
| 2026-10-02 | 1,307,526 | 2,000 |
| 2026-10-03 | 2,974 | 2,000 |
| 2026-10-04 | 6,928 | 2,000 |
| 2026-10-05 | 2,910 | 2,000 |
| 2026-10-06 | 8,285 | 2,000 |
| 2026-10-07 | 8,007 | 2,000 |
| 2026-10-08 | 7,328 | 2,000 |
| 2026-10-09 | 151,973 | 2,000 |
| 2026-10-10 | 8,211 | 2,000 |
| 2026-10-11 | 23,158 | 2,000 |
| 2026-10-12 | 33,311 | 2,000 |
| 2026-10-13 | 9,036 | 2,000 |
| 2026-10-14 | 8,095 | 2,000 |
| 2026-10-15 | 8,857 | 2,000 |
| 2026-10-16 | 16,264 | 2,000 |
| 2026-10-17 | 10,656 | 2,000 |
| 2026-10-18 | 9,411 | 2,000 |
| 2026-10-19 | 5,765 | 2,000 |
| 2026-10-20 | 10,784 | 2,000 |

> Hinweis: Der Rueckstau von 2,895,897 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,436 |
| 2026-09-23 | 13,064 |
| 2026-09-24 | 16,677 |
| 2026-09-25 | 20,941 |
| 2026-09-26 | 17,464 |
| 2026-09-27 | 15,046 |
| 2026-09-28 | 11,616 |
| 2026-09-29 | 9,365 |
| 2026-09-30 | 10,185 |
| 2026-10-01 | 16,611 |
| 2026-10-02 | 7,730 |
| 2026-10-03 | 7,338 |
| 2026-10-04 | 12,639 |
| 2026-10-05 | 17,554 |
| 2026-10-06 | 16,144 |
| 2026-10-07 | 15,076 |
| 2026-10-08 | 61,469 |
| 2026-10-09 | 223,379 |
| 2026-10-10 | 53,397 |
| 2026-10-11 | 16,063 |
| 2026-10-12 | 66,600 |
| 2026-10-13 | 1,586,042 |
| 2026-10-14 | 32,924 |
| 2026-10-15 | 41,360 |
| 2026-10-16 | 51,338 |
| 2026-10-17 | 24,335 |
| 2026-10-18 | 14,293 |
| 2026-10-19 | 22,411 |
| 2026-10-20 | 11,159 |
| 2026-10-21 | 11,135 |
| 2026-10-22 | 30,791 |
| 2026-10-23 | 50,466 |
| 2026-10-24 | 41,784 |
| 2026-10-25 | 21,664 |
| 2026-10-26 | 20,382 |
| 2026-10-27 | 20,751 |
| 2026-10-28 | 15,837 |
| 2026-10-29 | 9,714 |
| 2026-10-30 | 62,062 |
| 2026-10-31 | 88,284 |
| 2026-11-01 | 27,925 |
| 2026-11-02 | 28,894 |
| 2026-11-03 | 29,916 |
| 2026-11-04 | 29,733 |
| 2026-11-05 | 25,353 |
| 2026-11-06 | 36,770 |
| 2026-11-07 | 24,552 |
| 2026-11-08 | 26,199 |
| 2026-11-09 | 25,632 |
| 2026-11-10 | 32,834 |
| 2026-11-11 | 22,457 |
| 2026-11-12 | 20,561 |
| 2026-11-13 | 19,710 |
| 2026-11-14 | 23,043 |
| 2026-11-15 | 17,520 |
| 2026-11-16 | 18,031 |
| 2026-11-17 | 15,293 |
| 2026-11-18 | 19,572 |
| 2026-11-19 | 174,368 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 194074 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
