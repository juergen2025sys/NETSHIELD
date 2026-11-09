# Seen-DB Expiry Forecast

Lauf: 2026-11-09 12:17 CET (Europe/Berlin)
Gesamt: 11,201,610 IPs in seen_db.json (7,979,015 aktiv/180-Tage-Pfad, 3,222,595 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 152,673 |
| 8-14 Tage | 350,681 |
| 15-30 Tage | 552,350 |
| 31-60 Tage | 696,984 |
| 61-90 Tage | 1,146,062 |
| 91-180 Tage | 5,080,265 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,955,098 |
| 0-3 Tage | 52,770 |
| 4-7 Tage | 47,884 |
| 8-14 Tage | 62,299 |
| 15-30 Tage | 104,544 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-09 | 11,399 |
| 2026-11-10 | 23,571 |
| 2026-11-11 | 9,829 |
| 2026-11-12 | 7,971 |
| 2026-11-13 | 3,302 |
| 2026-11-14 | 11,534 |
| 2026-11-15 | 14,253 |
| 2026-11-16 | 18,795 |
| 2026-11-17 | 9,278 |
| 2026-11-18 | 3,463 |
| 2026-11-19 | 8,765 |
| 2026-11-20 | 10,846 |
| 2026-11-21 | 9,938 |
| 2026-11-22 | 9,980 |
| 2026-11-23 | 10,029 |
| 2026-11-24 | 10,104 |
| 2026-11-25 | 7,612 |
| 2026-11-26 | 3,339 |
| 2026-11-27 | 3,863 |
| 2026-11-28 | 3,546 |
| 2026-11-29 | 8,140 |
| 2026-11-30 | 7,125 |
| 2026-12-01 | 8,087 |
| 2026-12-02 | 4,597 |
| 2026-12-03 | 7,734 |
| 2026-12-04 | 5,772 |
| 2026-12-05 | 5,423 |
| 2026-12-06 | 3,120 |
| 2026-12-07 | 7,836 |
| 2026-12-08 | 4,552 |
| 2026-12-09 | 9,109 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,955,098** IPs. Brutto faellig in den naechsten 30 Tagen: **262,912**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,156,010**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-09 | 11,399 | 2,000 |
| 2026-11-10 | 23,571 | 2,000 |
| 2026-11-11 | 9,829 | 2,000 |
| 2026-11-12 | 7,971 | 2,000 |
| 2026-11-13 | 3,302 | 2,000 |
| 2026-11-14 | 11,534 | 2,000 |
| 2026-11-15 | 14,253 | 2,000 |
| 2026-11-16 | 18,795 | 2,000 |
| 2026-11-17 | 9,278 | 2,000 |
| 2026-11-18 | 3,463 | 2,000 |
| 2026-11-19 | 8,765 | 2,000 |
| 2026-11-20 | 10,846 | 2,000 |
| 2026-11-21 | 9,938 | 2,000 |
| 2026-11-22 | 9,980 | 2,000 |
| 2026-11-23 | 10,029 | 2,000 |
| 2026-11-24 | 10,104 | 2,000 |
| 2026-11-25 | 7,612 | 2,000 |
| 2026-11-26 | 3,339 | 2,000 |
| 2026-11-27 | 3,863 | 2,000 |
| 2026-11-28 | 3,546 | 2,000 |
| 2026-11-29 | 8,140 | 2,000 |
| 2026-11-30 | 7,125 | 2,000 |
| 2026-12-01 | 8,087 | 2,000 |
| 2026-12-02 | 4,597 | 2,000 |
| 2026-12-03 | 7,734 | 2,000 |
| 2026-12-04 | 5,772 | 2,000 |
| 2026-12-05 | 5,423 | 2,000 |
| 2026-12-06 | 3,120 | 2,000 |
| 2026-12-07 | 7,836 | 2,000 |
| 2026-12-08 | 4,552 | 2,000 |
| 2026-12-09 | 9,109 | 2,000 |

> Hinweis: Der Rueckstau von 3,156,010 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-10 | 32,520 |
| 2026-11-11 | 22,198 |
| 2026-11-12 | 20,390 |
| 2026-11-13 | 19,531 |
| 2026-11-14 | 22,816 |
| 2026-11-15 | 17,372 |
| 2026-11-16 | 17,846 |
| 2026-11-17 | 15,154 |
| 2026-11-18 | 19,399 |
| 2026-11-19 | 173,233 |
| 2026-11-20 | 26,001 |
| 2026-11-21 | 61,116 |
| 2026-11-22 | 30,256 |
| 2026-11-23 | 25,522 |
| 2026-11-24 | 26,340 |
| 2026-11-25 | 27,377 |
| 2026-11-26 | 28,546 |
| 2026-11-27 | 27,734 |
| 2026-11-28 | 109,016 |
| 2026-11-29 | 28,077 |
| 2026-11-30 | 25,430 |
| 2026-12-01 | 26,450 |
| 2026-12-02 | 26,085 |
| 2026-12-03 | 25,893 |
| 2026-12-04 | 27,822 |
| 2026-12-05 | 25,863 |
| 2026-12-06 | 30,019 |
| 2026-12-07 | 23,658 |
| 2026-12-08 | 39,253 |
| 2026-12-09 | 54,787 |
| 2026-12-10 | 25,010 |
| 2026-12-11 | 27,678 |
| 2026-12-12 | 24,299 |
| 2026-12-13 | 23,766 |
| 2026-12-14 | 23,371 |
| 2026-12-15 | 26,150 |
| 2026-12-16 | 16,568 |
| 2026-12-17 | 24,941 |
| 2026-12-18 | 22,429 |
| 2026-12-19 | 25,516 |
| 2026-12-20 | 14,266 |
| 2026-12-21 | 27,255 |
| 2026-12-22 | 24,026 |
| 2026-12-23 | 21,066 |
| 2026-12-24 | 20,356 |
| 2026-12-25 | 21,573 |
| 2026-12-26 | 17,777 |
| 2026-12-27 | 24,597 |
| 2026-12-28 | 21,698 |
| 2026-12-29 | 22,533 |
| 2026-12-30 | 26,482 |
| 2026-12-31 | 20,129 |
| 2027-01-01 | 18,483 |
| 2027-01-02 | 26,084 |
| 2027-01-03 | 14,797 |
| 2027-01-04 | 28,426 |
| 2027-01-05 | 22,362 |
| 2027-01-06 | 35,552 |
| 2027-01-07 | 23,943 |
| 2027-01-08 | 25,851 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
