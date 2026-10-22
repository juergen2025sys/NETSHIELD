# Seen-DB Expiry Forecast

Lauf: 2026-10-22 23:54 CEST (Europe/Berlin)
Gesamt: 11,118,292 IPs in seen_db.json (7,995,822 aktiv/180-Tage-Pfad, 3,122,470 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 178,689 |
| 8-14 Tage | 290,095 |
| 15-30 Tage | 560,209 |
| 31-60 Tage | 891,136 |
| 61-90 Tage | 696,626 |
| 91-180 Tage | 5,379,067 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,724,594 |
| 0-3 Tage | 48,676 |
| 4-7 Tage | 65,490 |
| 8-14 Tage | 97,927 |
| 15-30 Tage | 185,783 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-22 | 10,325 |
| 2026-10-23 | 12,321 |
| 2026-10-24 | 14,984 |
| 2026-10-25 | 11,046 |
| 2026-10-26 | 9,399 |
| 2026-10-27 | 35,054 |
| 2026-10-28 | 11,240 |
| 2026-10-29 | 9,797 |
| 2026-10-30 | 20,036 |
| 2026-10-31 | 16,891 |
| 2026-11-01 | 15,307 |
| 2026-11-02 | 11,868 |
| 2026-11-03 | 16,577 |
| 2026-11-04 | 10,035 |
| 2026-11-05 | 7,213 |
| 2026-11-06 | 12,041 |
| 2026-11-07 | 13,328 |
| 2026-11-08 | 6,251 |
| 2026-11-09 | 11,451 |
| 2026-11-10 | 23,791 |
| 2026-11-11 | 9,877 |
| 2026-11-12 | 8,028 |
| 2026-11-13 | 3,326 |
| 2026-11-14 | 11,592 |
| 2026-11-15 | 14,320 |
| 2026-11-16 | 18,905 |
| 2026-11-17 | 9,336 |
| 2026-11-18 | 3,505 |
| 2026-11-19 | 8,858 |
| 2026-11-20 | 10,952 |
| 2026-11-21 | 10,097 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,724,594** IPs. Brutto faellig in den naechsten 30 Tagen: **387,751**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,050,345**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-22 | 10,325 | 2,000 |
| 2026-10-23 | 12,321 | 2,000 |
| 2026-10-24 | 14,984 | 2,000 |
| 2026-10-25 | 11,046 | 2,000 |
| 2026-10-26 | 9,399 | 2,000 |
| 2026-10-27 | 35,054 | 2,000 |
| 2026-10-28 | 11,240 | 2,000 |
| 2026-10-29 | 9,797 | 2,000 |
| 2026-10-30 | 20,036 | 2,000 |
| 2026-10-31 | 16,891 | 2,000 |
| 2026-11-01 | 15,307 | 2,000 |
| 2026-11-02 | 11,868 | 2,000 |
| 2026-11-03 | 16,577 | 2,000 |
| 2026-11-04 | 10,035 | 2,000 |
| 2026-11-05 | 7,213 | 2,000 |
| 2026-11-06 | 12,041 | 2,000 |
| 2026-11-07 | 13,328 | 2,000 |
| 2026-11-08 | 6,251 | 2,000 |
| 2026-11-09 | 11,451 | 2,000 |
| 2026-11-10 | 23,791 | 2,000 |
| 2026-11-11 | 9,877 | 2,000 |
| 2026-11-12 | 8,028 | 2,000 |
| 2026-11-13 | 3,326 | 2,000 |
| 2026-11-14 | 11,592 | 2,000 |
| 2026-11-15 | 14,320 | 2,000 |
| 2026-11-16 | 18,905 | 2,000 |
| 2026-11-17 | 9,336 | 2,000 |
| 2026-11-18 | 3,505 | 2,000 |
| 2026-11-19 | 8,858 | 2,000 |
| 2026-11-20 | 10,952 | 2,000 |
| 2026-11-21 | 10,097 | 2,000 |

> Hinweis: Der Rueckstau von 3,050,345 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-23 | 50,171 |
| 2026-10-24 | 41,539 |
| 2026-10-25 | 21,458 |
| 2026-10-26 | 20,162 |
| 2026-10-27 | 20,385 |
| 2026-10-28 | 15,488 |
| 2026-10-29 | 9,486 |
| 2026-10-30 | 61,538 |
| 2026-10-31 | 88,017 |
| 2026-11-01 | 27,706 |
| 2026-11-02 | 28,650 |
| 2026-11-03 | 29,593 |
| 2026-11-04 | 29,453 |
| 2026-11-05 | 25,138 |
| 2026-11-06 | 36,184 |
| 2026-11-07 | 24,336 |
| 2026-11-08 | 26,001 |
| 2026-11-09 | 25,426 |
| 2026-11-10 | 32,581 |
| 2026-11-11 | 22,252 |
| 2026-11-12 | 20,430 |
| 2026-11-13 | 19,574 |
| 2026-11-14 | 22,867 |
| 2026-11-15 | 17,396 |
| 2026-11-16 | 17,887 |
| 2026-11-17 | 15,179 |
| 2026-11-18 | 19,432 |
| 2026-11-19 | 173,390 |
| 2026-11-20 | 26,057 |
| 2026-11-21 | 61,217 |
| 2026-11-22 | 30,322 |
| 2026-11-23 | 25,578 |
| 2026-11-24 | 26,390 |
| 2026-11-25 | 27,440 |
| 2026-11-26 | 28,586 |
| 2026-11-27 | 27,774 |
| 2026-11-28 | 109,101 |
| 2026-11-29 | 28,114 |
| 2026-11-30 | 25,468 |
| 2026-12-01 | 26,481 |
| 2026-12-02 | 26,128 |
| 2026-12-03 | 25,948 |
| 2026-12-04 | 27,864 |
| 2026-12-05 | 25,907 |
| 2026-12-06 | 30,078 |
| 2026-12-07 | 23,693 |
| 2026-12-08 | 39,319 |
| 2026-12-09 | 55,004 |
| 2026-12-10 | 25,052 |
| 2026-12-11 | 27,731 |
| 2026-12-12 | 24,352 |
| 2026-12-13 | 23,823 |
| 2026-12-14 | 23,439 |
| 2026-12-15 | 26,217 |
| 2026-12-16 | 16,628 |
| 2026-12-17 | 24,986 |
| 2026-12-18 | 22,491 |
| 2026-12-19 | 25,583 |
| 2026-12-20 | 14,310 |
| 2026-12-21 | 27,329 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
