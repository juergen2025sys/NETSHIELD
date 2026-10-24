# Seen-DB Expiry Forecast

Lauf: 2026-10-24 18:17 CEST (Europe/Berlin)
Gesamt: 11,128,168 IPs in seen_db.json (7,987,819 aktiv/180-Tage-Pfad, 3,140,349 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 236,467 |
| 8-14 Tage | 201,020 |
| 15-30 Tage | 555,496 |
| 31-60 Tage | 880,254 |
| 61-90 Tage | 725,613 |
| 91-180 Tage | 5,388,969 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,746,863 |
| 0-3 Tage | 70,446 |
| 4-7 Tage | 57,952 |
| 8-14 Tage | 86,342 |
| 15-30 Tage | 178,746 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-24 | 14,977 |
| 2026-10-25 | 11,042 |
| 2026-10-26 | 9,394 |
| 2026-10-27 | 35,033 |
| 2026-10-28 | 11,239 |
| 2026-10-29 | 9,796 |
| 2026-10-30 | 20,030 |
| 2026-10-31 | 16,887 |
| 2026-11-01 | 15,307 |
| 2026-11-02 | 11,864 |
| 2026-11-03 | 16,570 |
| 2026-11-04 | 10,030 |
| 2026-11-05 | 7,210 |
| 2026-11-06 | 12,037 |
| 2026-11-07 | 13,324 |
| 2026-11-08 | 6,248 |
| 2026-11-09 | 11,446 |
| 2026-11-10 | 23,635 |
| 2026-11-11 | 9,870 |
| 2026-11-12 | 8,021 |
| 2026-11-13 | 3,322 |
| 2026-11-14 | 11,585 |
| 2026-11-15 | 14,311 |
| 2026-11-16 | 18,891 |
| 2026-11-17 | 9,325 |
| 2026-11-18 | 3,498 |
| 2026-11-19 | 8,836 |
| 2026-11-20 | 10,927 |
| 2026-11-21 | 10,048 |
| 2026-11-22 | 10,070 |
| 2026-11-23 | 10,134 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,746,863** IPs. Brutto faellig in den naechsten 30 Tagen: **384,907**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,069,770**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-24 | 14,977 | 2,000 |
| 2026-10-25 | 11,042 | 2,000 |
| 2026-10-26 | 9,394 | 2,000 |
| 2026-10-27 | 35,033 | 2,000 |
| 2026-10-28 | 11,239 | 2,000 |
| 2026-10-29 | 9,796 | 2,000 |
| 2026-10-30 | 20,030 | 2,000 |
| 2026-10-31 | 16,887 | 2,000 |
| 2026-11-01 | 15,307 | 2,000 |
| 2026-11-02 | 11,864 | 2,000 |
| 2026-11-03 | 16,570 | 2,000 |
| 2026-11-04 | 10,030 | 2,000 |
| 2026-11-05 | 7,210 | 2,000 |
| 2026-11-06 | 12,037 | 2,000 |
| 2026-11-07 | 13,324 | 2,000 |
| 2026-11-08 | 6,248 | 2,000 |
| 2026-11-09 | 11,446 | 2,000 |
| 2026-11-10 | 23,635 | 2,000 |
| 2026-11-11 | 9,870 | 2,000 |
| 2026-11-12 | 8,021 | 2,000 |
| 2026-11-13 | 3,322 | 2,000 |
| 2026-11-14 | 11,585 | 2,000 |
| 2026-11-15 | 14,311 | 2,000 |
| 2026-11-16 | 18,891 | 2,000 |
| 2026-11-17 | 9,325 | 2,000 |
| 2026-11-18 | 3,498 | 2,000 |
| 2026-11-19 | 8,836 | 2,000 |
| 2026-11-20 | 10,927 | 2,000 |
| 2026-11-21 | 10,048 | 2,000 |
| 2026-11-22 | 10,070 | 2,000 |
| 2026-11-23 | 10,134 | 2,000 |

> Hinweis: Der Rueckstau von 3,069,770 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-25 | 21,450 |
| 2026-10-26 | 20,157 |
| 2026-10-27 | 20,375 |
| 2026-10-28 | 15,478 |
| 2026-10-29 | 9,479 |
| 2026-10-30 | 61,521 |
| 2026-10-31 | 88,007 |
| 2026-11-01 | 27,701 |
| 2026-11-02 | 28,642 |
| 2026-11-03 | 29,587 |
| 2026-11-04 | 29,450 |
| 2026-11-05 | 25,131 |
| 2026-11-06 | 36,179 |
| 2026-11-07 | 24,330 |
| 2026-11-08 | 25,998 |
| 2026-11-09 | 25,417 |
| 2026-11-10 | 32,575 |
| 2026-11-11 | 22,244 |
| 2026-11-12 | 20,428 |
| 2026-11-13 | 19,571 |
| 2026-11-14 | 22,861 |
| 2026-11-15 | 17,393 |
| 2026-11-16 | 17,879 |
| 2026-11-17 | 15,177 |
| 2026-11-18 | 19,427 |
| 2026-11-19 | 173,376 |
| 2026-11-20 | 26,053 |
| 2026-11-21 | 61,210 |
| 2026-11-22 | 30,314 |
| 2026-11-23 | 25,573 |
| 2026-11-24 | 26,380 |
| 2026-11-25 | 27,436 |
| 2026-11-26 | 28,584 |
| 2026-11-27 | 27,772 |
| 2026-11-28 | 109,093 |
| 2026-11-29 | 28,103 |
| 2026-11-30 | 25,464 |
| 2026-12-01 | 26,476 |
| 2026-12-02 | 26,121 |
| 2026-12-03 | 25,944 |
| 2026-12-04 | 27,860 |
| 2026-12-05 | 25,902 |
| 2026-12-06 | 30,075 |
| 2026-12-07 | 23,690 |
| 2026-12-08 | 39,313 |
| 2026-12-09 | 54,980 |
| 2026-12-10 | 25,047 |
| 2026-12-11 | 27,721 |
| 2026-12-12 | 24,344 |
| 2026-12-13 | 23,817 |
| 2026-12-14 | 23,435 |
| 2026-12-15 | 26,211 |
| 2026-12-16 | 16,613 |
| 2026-12-17 | 24,984 |
| 2026-12-18 | 22,484 |
| 2026-12-19 | 25,572 |
| 2026-12-20 | 14,304 |
| 2026-12-21 | 27,321 |
| 2026-12-22 | 24,098 |
| 2026-12-23 | 21,110 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
