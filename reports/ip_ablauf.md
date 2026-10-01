# Seen-DB Expiry Forecast

Lauf: 2026-09-30 22:16 CEST (Europe/Berlin)
Gesamt: 11,968,023 IPs in seen_db.json (9,053,061 aktiv/180-Tage-Pfad, 2,914,962 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 92,656 |
| 8-14 Tage | 2,034,695 |
| 15-30 Tage | 448,084 |
| 31-60 Tage | 1,096,447 |
| 61-90 Tage | 766,626 |
| 91-180 Tage | 4,614,553 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 1,245,310 |
| 0-3 Tage | 1,375,767 |
| 4-7 Tage | 25,563 |
| 8-14 Tage | 50,785 |
| 15-30 Tage | 217,537 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-30 | 59,425 |
| 2026-10-01 | 7,601 |
| 2026-10-02 | 1,305,792 |
| 2026-10-03 | 2,949 |
| 2026-10-04 | 6,842 |
| 2026-10-05 | 2,864 |
| 2026-10-06 | 7,946 |
| 2026-10-07 | 7,911 |
| 2026-10-08 | 7,265 |
| 2026-10-09 | 10,146 |
| 2026-10-10 | 7,546 |
| 2026-10-11 | 6,249 |
| 2026-10-12 | 3,870 |
| 2026-10-13 | 8,274 |
| 2026-10-14 | 7,435 |
| 2026-10-15 | 8,316 |
| 2026-10-16 | 15,487 |
| 2026-10-17 | 9,950 |
| 2026-10-18 | 8,669 |
| 2026-10-19 | 5,165 |
| 2026-10-20 | 9,630 |
| 2026-10-21 | 9,568 |
| 2026-10-22 | 10,437 |
| 2026-10-23 | 12,477 |
| 2026-10-24 | 15,141 |
| 2026-10-25 | 11,146 |
| 2026-10-26 | 9,507 |
| 2026-10-27 | 35,376 |
| 2026-10-28 | 11,352 |
| 2026-10-29 | 9,929 |
| 2026-10-30 | 20,339 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **1,245,310** IPs. Brutto faellig in den naechsten 30 Tagen: **1,654,604**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **2,837,914**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-30 | 59,425 | 2,000 |
| 2026-10-01 | 7,601 | 2,000 |
| 2026-10-02 | 1,305,792 | 2,000 |
| 2026-10-03 | 2,949 | 2,000 |
| 2026-10-04 | 6,842 | 2,000 |
| 2026-10-05 | 2,864 | 2,000 |
| 2026-10-06 | 7,946 | 2,000 |
| 2026-10-07 | 7,911 | 2,000 |
| 2026-10-08 | 7,265 | 2,000 |
| 2026-10-09 | 10,146 | 2,000 |
| 2026-10-10 | 7,546 | 2,000 |
| 2026-10-11 | 6,249 | 2,000 |
| 2026-10-12 | 3,870 | 2,000 |
| 2026-10-13 | 8,274 | 2,000 |
| 2026-10-14 | 7,435 | 2,000 |
| 2026-10-15 | 8,316 | 2,000 |
| 2026-10-16 | 15,487 | 2,000 |
| 2026-10-17 | 9,950 | 2,000 |
| 2026-10-18 | 8,669 | 2,000 |
| 2026-10-19 | 5,165 | 2,000 |
| 2026-10-20 | 9,630 | 2,000 |
| 2026-10-21 | 9,568 | 2,000 |
| 2026-10-22 | 10,437 | 2,000 |
| 2026-10-23 | 12,477 | 2,000 |
| 2026-10-24 | 15,141 | 2,000 |
| 2026-10-25 | 11,146 | 2,000 |
| 2026-10-26 | 9,507 | 2,000 |
| 2026-10-27 | 35,376 | 2,000 |
| 2026-10-28 | 11,352 | 2,000 |
| 2026-10-29 | 9,929 | 2,000 |
| 2026-10-30 | 20,339 | 2,000 |

> Hinweis: Der Rueckstau von 2,837,914 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-01 | 16,547 |
| 2026-10-02 | 7,694 |
| 2026-10-03 | 7,302 |
| 2026-10-04 | 12,564 |
| 2026-10-05 | 17,490 |
| 2026-10-06 | 16,057 |
| 2026-10-07 | 15,002 |
| 2026-10-08 | 61,176 |
| 2026-10-09 | 221,772 |
| 2026-10-10 | 53,319 |
| 2026-10-11 | 16,020 |
| 2026-10-12 | 66,539 |
| 2026-10-13 | 1,582,957 |
| 2026-10-14 | 32,912 |
| 2026-10-15 | 41,314 |
| 2026-10-16 | 51,257 |
| 2026-10-17 | 24,237 |
| 2026-10-18 | 14,248 |
| 2026-10-19 | 22,245 |
| 2026-10-20 | 11,122 |
| 2026-10-21 | 11,090 |
| 2026-10-22 | 30,702 |
| 2026-10-23 | 50,366 |
| 2026-10-24 | 41,684 |
| 2026-10-25 | 21,584 |
| 2026-10-26 | 20,299 |
| 2026-10-27 | 20,645 |
| 2026-10-28 | 15,761 |
| 2026-10-29 | 9,656 |
| 2026-10-30 | 61,874 |
| 2026-10-31 | 88,191 |
| 2026-11-01 | 27,847 |
| 2026-11-02 | 28,796 |
| 2026-11-03 | 29,777 |
| 2026-11-04 | 29,613 |
| 2026-11-05 | 25,262 |
| 2026-11-06 | 36,366 |
| 2026-11-07 | 24,472 |
| 2026-11-08 | 26,120 |
| 2026-11-09 | 25,559 |
| 2026-11-10 | 32,737 |
| 2026-11-11 | 22,379 |
| 2026-11-12 | 20,514 |
| 2026-11-13 | 19,664 |
| 2026-11-14 | 22,984 |
| 2026-11-15 | 17,466 |
| 2026-11-16 | 17,982 |
| 2026-11-17 | 15,268 |
| 2026-11-18 | 19,517 |
| 2026-11-19 | 173,920 |
| 2026-11-20 | 26,194 |
| 2026-11-21 | 61,459 |
| 2026-11-22 | 30,471 |
| 2026-11-23 | 25,713 |
| 2026-11-24 | 26,506 |
| 2026-11-25 | 27,588 |
| 2026-11-26 | 28,702 |
| 2026-11-27 | 27,877 |
| 2026-11-28 | 109,275 |
| 2026-11-29 | 28,228 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
