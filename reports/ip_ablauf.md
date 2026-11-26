# Seen-DB Expiry Forecast

Lauf: 2026-11-26 19:57 CET (Europe/Berlin)
Gesamt: 11,311,169 IPs in seen_db.json (7,912,347 aktiv/180-Tage-Pfad, 3,398,822 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 268,343 |
| 8-14 Tage | 225,970 |
| 15-30 Tage | 360,185 |
| 31-60 Tage | 755,606 |
| 61-90 Tage | 1,584,099 |
| 91-180 Tage | 4,718,144 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 3,113,093 |
| 0-3 Tage | 18,800 |
| 4-7 Tage | 27,398 |
| 8-14 Tage | 41,402 |
| 15-30 Tage | 198,129 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-26 | 3,322 |
| 2026-11-27 | 3,846 |
| 2026-11-28 | 3,523 |
| 2026-11-29 | 8,109 |
| 2026-11-30 | 7,086 |
| 2026-12-01 | 8,055 |
| 2026-12-02 | 4,555 |
| 2026-12-03 | 7,702 |
| 2026-12-04 | 5,742 |
| 2026-12-05 | 5,379 |
| 2026-12-06 | 3,079 |
| 2026-12-07 | 7,770 |
| 2026-12-08 | 4,439 |
| 2026-12-09 | 8,998 |
| 2026-12-10 | 5,995 |
| 2026-12-11 | 4,636 |
| 2026-12-12 | 2,574 |
| 2026-12-13 | 2,991 |
| 2026-12-14 | 7,590 |
| 2026-12-15 | 8,079 |
| 2026-12-16 | 7,484 |
| 2026-12-17 | 7,622 |
| 2026-12-18 | 9,341 |
| 2026-12-19 | 1,627 |
| 2026-12-20 | 10,063 |
| 2026-12-21 | 8,999 |
| 2026-12-22 | 31,706 |
| 2026-12-23 | 14,726 |
| 2026-12-24 | 19,450 |
| 2026-12-25 | 15,229 |
| 2026-12-26 | 18,593 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **3,113,093** IPs. Brutto faellig in den naechsten 30 Tagen: **258,310**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,309,403**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-26 | 3,322 | 2,000 |
| 2026-11-27 | 3,846 | 2,000 |
| 2026-11-28 | 3,523 | 2,000 |
| 2026-11-29 | 8,109 | 2,000 |
| 2026-11-30 | 7,086 | 2,000 |
| 2026-12-01 | 8,055 | 2,000 |
| 2026-12-02 | 4,555 | 2,000 |
| 2026-12-03 | 7,702 | 2,000 |
| 2026-12-04 | 5,742 | 2,000 |
| 2026-12-05 | 5,379 | 2,000 |
| 2026-12-06 | 3,079 | 2,000 |
| 2026-12-07 | 7,770 | 2,000 |
| 2026-12-08 | 4,439 | 2,000 |
| 2026-12-09 | 8,998 | 2,000 |
| 2026-12-10 | 5,995 | 2,000 |
| 2026-12-11 | 4,636 | 2,000 |
| 2026-12-12 | 2,574 | 2,000 |
| 2026-12-13 | 2,991 | 2,000 |
| 2026-12-14 | 7,590 | 2,000 |
| 2026-12-15 | 8,079 | 2,000 |
| 2026-12-16 | 7,484 | 2,000 |
| 2026-12-17 | 7,622 | 2,000 |
| 2026-12-18 | 9,341 | 2,000 |
| 2026-12-19 | 1,627 | 2,000 |
| 2026-12-20 | 10,063 | 2,000 |
| 2026-12-21 | 8,999 | 2,000 |
| 2026-12-22 | 31,706 | 2,000 |
| 2026-12-23 | 14,726 | 2,000 |
| 2026-12-24 | 19,450 | 2,000 |
| 2026-12-25 | 15,229 | 2,000 |
| 2026-12-26 | 18,593 | 2,000 |

> Hinweis: Der Rueckstau von 3,309,403 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-27 | 27,695 |
| 2026-11-28 | 108,938 |
| 2026-11-29 | 28,032 |
| 2026-11-30 | 25,387 |
| 2026-12-01 | 26,412 |
| 2026-12-02 | 26,034 |
| 2026-12-03 | 25,845 |
| 2026-12-04 | 27,788 |
| 2026-12-05 | 25,826 |
| 2026-12-06 | 29,972 |
| 2026-12-07 | 23,627 |
| 2026-12-08 | 39,210 |
| 2026-12-09 | 54,588 |
| 2026-12-10 | 24,959 |
| 2026-12-11 | 27,620 |
| 2026-12-12 | 24,255 |
| 2026-12-13 | 23,701 |
| 2026-12-14 | 23,326 |
| 2026-12-15 | 26,099 |
| 2026-12-16 | 16,511 |
| 2026-12-17 | 24,873 |
| 2026-12-18 | 22,392 |
| 2026-12-19 | 25,450 |
| 2026-12-20 | 14,221 |
| 2026-12-21 | 27,200 |
| 2026-12-22 | 23,974 |
| 2026-12-23 | 21,006 |
| 2026-12-24 | 20,310 |
| 2026-12-25 | 21,529 |
| 2026-12-26 | 17,718 |
| 2026-12-27 | 24,540 |
| 2026-12-28 | 21,647 |
| 2026-12-29 | 22,486 |
| 2026-12-30 | 26,425 |
| 2026-12-31 | 20,085 |
| 2027-01-01 | 18,436 |
| 2027-01-02 | 26,028 |
| 2027-01-03 | 14,751 |
| 2027-01-04 | 28,379 |
| 2027-01-05 | 22,302 |
| 2027-01-06 | 35,478 |
| 2027-01-07 | 23,884 |
| 2027-01-08 | 25,779 |
| 2027-01-09 | 21,546 |
| 2027-01-10 | 24,660 |
| 2027-01-11 | 24,063 |
| 2027-01-12 | 22,940 |
| 2027-01-13 | 23,231 |
| 2027-01-14 | 21,838 |
| 2027-01-15 | 22,671 |
| 2027-01-16 | 26,728 |
| 2027-01-17 | 20,503 |
| 2027-01-18 | 24,820 |
| 2027-01-19 | 22,469 |
| 2027-01-20 | 23,149 |
| 2027-01-21 | 45,457 |
| 2027-01-22 | 28,524 |
| 2027-01-23 | 25,815 |
| 2027-01-24 | 25,121 |
| 2027-01-25 | 41,851 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
