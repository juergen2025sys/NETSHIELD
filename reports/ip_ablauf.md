# Seen-DB Expiry Forecast

Lauf: 2026-09-21 01:09 CEST (Europe/Berlin)
Gesamt: 11,622,871 IPs in seen_db.json (8,656,736 aktiv/180-Tage-Pfad, 2,966,135 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 89,601 |
| 8-14 Tage | 75,452 |
| 15-30 Tage | 2,253,153 |
| 31-60 Tage | 991,023 |
| 61-90 Tage | 944,361 |
| 91-180 Tage | 4,303,146 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 574,804 |
| 0-3 Tage | 26,283 |
| 4-7 Tage | 646,986 |
| 8-14 Tage | 1,385,467 |
| 15-30 Tage | 332,595 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-20 | 5,029 |
| 2026-09-21 | 5,006 |
| 2026-09-22 | 11,134 |
| 2026-09-23 | 5,114 |
| 2026-09-24 | 11,390 |
| 2026-09-25 | 5,464 |
| 2026-09-26 | 623,844 |
| 2026-09-27 | 6,288 |
| 2026-09-28 | 774 |
| 2026-09-30 | 59,701 |
| 2026-10-01 | 7,659 |
| 2026-10-02 | 1,307,432 |
| 2026-10-03 | 2,973 |
| 2026-10-04 | 6,928 |
| 2026-10-05 | 2,907 |
| 2026-10-06 | 8,281 |
| 2026-10-07 | 7,999 |
| 2026-10-08 | 7,324 |
| 2026-10-09 | 151,933 |
| 2026-10-10 | 8,210 |
| 2026-10-11 | 23,141 |
| 2026-10-12 | 33,302 |
| 2026-10-13 | 9,026 |
| 2026-10-14 | 8,090 |
| 2026-10-15 | 8,844 |
| 2026-10-16 | 16,245 |
| 2026-10-17 | 10,644 |
| 2026-10-18 | 9,392 |
| 2026-10-19 | 5,726 |
| 2026-10-20 | 10,450 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **574,804** IPs. Brutto faellig in den naechsten 30 Tagen: **2,380,250**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,895,054**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-20 | 5,029 | 2,000 |
| 2026-09-21 | 5,006 | 2,000 |
| 2026-09-22 | 11,134 | 2,000 |
| 2026-09-23 | 5,114 | 2,000 |
| 2026-09-24 | 11,390 | 2,000 |
| 2026-09-25 | 5,464 | 2,000 |
| 2026-09-26 | 623,844 | 2,000 |
| 2026-09-27 | 6,288 | 2,000 |
| 2026-09-28 | 774 | 2,000 |
| 2026-09-30 | 59,701 | 2,000 |
| 2026-10-01 | 7,659 | 2,000 |
| 2026-10-02 | 1,307,432 | 2,000 |
| 2026-10-03 | 2,973 | 2,000 |
| 2026-10-04 | 6,928 | 2,000 |
| 2026-10-05 | 2,907 | 2,000 |
| 2026-10-06 | 8,281 | 2,000 |
| 2026-10-07 | 7,999 | 2,000 |
| 2026-10-08 | 7,324 | 2,000 |
| 2026-10-09 | 151,933 | 2,000 |
| 2026-10-10 | 8,210 | 2,000 |
| 2026-10-11 | 23,141 | 2,000 |
| 2026-10-12 | 33,302 | 2,000 |
| 2026-10-13 | 9,026 | 2,000 |
| 2026-10-14 | 8,090 | 2,000 |
| 2026-10-15 | 8,844 | 2,000 |
| 2026-10-16 | 16,245 | 2,000 |
| 2026-10-17 | 10,644 | 2,000 |
| 2026-10-18 | 9,392 | 2,000 |
| 2026-10-19 | 5,726 | 2,000 |
| 2026-10-20 | 10,450 | 2,000 |

> Hinweis: Der Rueckstau von 2,895,054 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,435 |
| 2026-09-23 | 13,063 |
| 2026-09-24 | 16,670 |
| 2026-09-25 | 20,936 |
| 2026-09-26 | 17,456 |
| 2026-09-27 | 15,041 |
| 2026-09-28 | 11,611 |
| 2026-09-29 | 9,361 |
| 2026-09-30 | 10,180 |
| 2026-10-01 | 16,607 |
| 2026-10-02 | 7,724 |
| 2026-10-03 | 7,336 |
| 2026-10-04 | 12,633 |
| 2026-10-05 | 17,549 |
| 2026-10-06 | 16,138 |
| 2026-10-07 | 15,073 |
| 2026-10-08 | 61,451 |
| 2026-10-09 | 223,232 |
| 2026-10-10 | 53,393 |
| 2026-10-11 | 16,062 |
| 2026-10-12 | 66,594 |
| 2026-10-13 | 1,585,867 |
| 2026-10-14 | 32,924 |
| 2026-10-15 | 41,357 |
| 2026-10-16 | 51,333 |
| 2026-10-17 | 24,331 |
| 2026-10-18 | 14,291 |
| 2026-10-19 | 22,401 |
| 2026-10-20 | 11,157 |
| 2026-10-21 | 11,132 |
| 2026-10-22 | 30,784 |
| 2026-10-23 | 50,457 |
| 2026-10-24 | 41,775 |
| 2026-10-25 | 21,654 |
| 2026-10-26 | 20,372 |
| 2026-10-27 | 20,744 |
| 2026-10-28 | 15,835 |
| 2026-10-29 | 9,708 |
| 2026-10-30 | 62,047 |
| 2026-10-31 | 88,280 |
| 2026-11-01 | 27,919 |
| 2026-11-02 | 28,884 |
| 2026-11-03 | 29,903 |
| 2026-11-04 | 29,720 |
| 2026-11-05 | 25,348 |
| 2026-11-06 | 36,761 |
| 2026-11-07 | 24,548 |
| 2026-11-08 | 26,194 |
| 2026-11-09 | 25,627 |
| 2026-11-10 | 32,823 |
| 2026-11-11 | 22,450 |
| 2026-11-12 | 20,558 |
| 2026-11-13 | 19,708 |
| 2026-11-14 | 23,040 |
| 2026-11-15 | 17,516 |
| 2026-11-16 | 18,030 |
| 2026-11-17 | 15,289 |
| 2026-11-18 | 19,562 |
| 2026-11-19 | 174,355 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 194472 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
