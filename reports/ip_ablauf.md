# Seen-DB Expiry Forecast

Lauf: 2026-09-26 03:26 CEST (Europe/Berlin)
Gesamt: 11,687,860 IPs in seen_db.json (8,861,890 aktiv/180-Tage-Pfad, 2,825,970 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 77,680 |
| 8-14 Tage | 398,291 |
| 15-30 Tage | 2,040,341 |
| 31-60 Tage | 1,011,595 |
| 61-90 Tage | 874,571 |
| 91-180 Tage | 4,459,412 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 614,497 |
| 0-3 Tage | 630,678 |
| 4-7 Tage | 1,376,780 |
| 8-14 Tage | 50,785 |
| 15-30 Tage | 153,230 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-26 | 623,651 |
| 2026-09-27 | 6,257 |
| 2026-09-28 | 770 |
| 2026-09-30 | 59,621 |
| 2026-10-01 | 7,630 |
| 2026-10-02 | 1,306,567 |
| 2026-10-03 | 2,962 |
| 2026-10-04 | 6,910 |
| 2026-10-05 | 2,898 |
| 2026-10-06 | 8,014 |
| 2026-10-07 | 7,938 |
| 2026-10-08 | 7,282 |
| 2026-10-09 | 10,169 |
| 2026-10-10 | 7,574 |
| 2026-10-11 | 6,264 |
| 2026-10-12 | 3,879 |
| 2026-10-13 | 8,318 |
| 2026-10-14 | 7,458 |
| 2026-10-15 | 8,337 |
| 2026-10-16 | 15,518 |
| 2026-10-17 | 9,970 |
| 2026-10-18 | 8,704 |
| 2026-10-19 | 5,179 |
| 2026-10-20 | 9,680 |
| 2026-10-21 | 9,622 |
| 2026-10-22 | 10,507 |
| 2026-10-23 | 12,554 |
| 2026-10-24 | 15,256 |
| 2026-10-25 | 11,215 |
| 2026-10-26 | 10,135 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **614,497** IPs. Brutto faellig in den naechsten 30 Tagen: **2,210,839**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,765,336**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-26 | 623,651 | 2,000 |
| 2026-09-27 | 6,257 | 2,000 |
| 2026-09-28 | 770 | 2,000 |
| 2026-09-30 | 59,621 | 2,000 |
| 2026-10-01 | 7,630 | 2,000 |
| 2026-10-02 | 1,306,567 | 2,000 |
| 2026-10-03 | 2,962 | 2,000 |
| 2026-10-04 | 6,910 | 2,000 |
| 2026-10-05 | 2,898 | 2,000 |
| 2026-10-06 | 8,014 | 2,000 |
| 2026-10-07 | 7,938 | 2,000 |
| 2026-10-08 | 7,282 | 2,000 |
| 2026-10-09 | 10,169 | 2,000 |
| 2026-10-10 | 7,574 | 2,000 |
| 2026-10-11 | 6,264 | 2,000 |
| 2026-10-12 | 3,879 | 2,000 |
| 2026-10-13 | 8,318 | 2,000 |
| 2026-10-14 | 7,458 | 2,000 |
| 2026-10-15 | 8,337 | 2,000 |
| 2026-10-16 | 15,518 | 2,000 |
| 2026-10-17 | 9,970 | 2,000 |
| 2026-10-18 | 8,704 | 2,000 |
| 2026-10-19 | 5,179 | 2,000 |
| 2026-10-20 | 9,680 | 2,000 |
| 2026-10-21 | 9,622 | 2,000 |
| 2026-10-22 | 10,507 | 2,000 |
| 2026-10-23 | 12,554 | 2,000 |
| 2026-10-24 | 15,256 | 2,000 |
| 2026-10-25 | 11,215 | 2,000 |
| 2026-10-26 | 10,135 | 2,000 |

> Hinweis: Der Rueckstau von 2,765,336 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-27 | 14,995 |
| 2026-09-28 | 11,592 |
| 2026-09-29 | 9,337 |
| 2026-09-30 | 10,153 |
| 2026-10-01 | 16,574 |
| 2026-10-02 | 7,711 |
| 2026-10-03 | 7,318 |
| 2026-10-04 | 12,594 |
| 2026-10-05 | 17,515 |
| 2026-10-06 | 16,096 |
| 2026-10-07 | 15,026 |
| 2026-10-08 | 61,318 |
| 2026-10-09 | 222,390 |
| 2026-10-10 | 53,352 |
| 2026-10-11 | 16,042 |
| 2026-10-12 | 66,568 |
| 2026-10-13 | 1,584,254 |
| 2026-10-14 | 32,918 |
| 2026-10-15 | 41,333 |
| 2026-10-16 | 51,290 |
| 2026-10-17 | 24,270 |
| 2026-10-18 | 14,264 |
| 2026-10-19 | 22,325 |
| 2026-10-20 | 11,138 |
| 2026-10-21 | 11,108 |
| 2026-10-22 | 30,736 |
| 2026-10-23 | 50,416 |
| 2026-10-24 | 41,720 |
| 2026-10-25 | 21,618 |
| 2026-10-26 | 20,341 |
| 2026-10-27 | 20,698 |
| 2026-10-28 | 15,803 |
| 2026-10-29 | 9,684 |
| 2026-10-30 | 61,952 |
| 2026-10-31 | 88,238 |
| 2026-11-01 | 27,876 |
| 2026-11-02 | 28,841 |
| 2026-11-03 | 29,822 |
| 2026-11-04 | 29,658 |
| 2026-11-05 | 25,305 |
| 2026-11-06 | 36,434 |
| 2026-11-07 | 24,496 |
| 2026-11-08 | 26,153 |
| 2026-11-09 | 25,590 |
| 2026-11-10 | 32,779 |
| 2026-11-11 | 22,416 |
| 2026-11-12 | 20,532 |
| 2026-11-13 | 19,689 |
| 2026-11-14 | 23,005 |
| 2026-11-15 | 17,489 |
| 2026-11-16 | 18,000 |
| 2026-11-17 | 15,275 |
| 2026-11-18 | 19,538 |
| 2026-11-19 | 174,103 |
| 2026-11-20 | 26,232 |
| 2026-11-21 | 61,545 |
| 2026-11-22 | 30,520 |
| 2026-11-23 | 25,757 |
| 2026-11-24 | 26,538 |
| 2026-11-25 | 27,627 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
