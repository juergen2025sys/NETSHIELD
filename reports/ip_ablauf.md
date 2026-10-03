# Seen-DB Expiry Forecast

Lauf: 2026-10-03 02:22 CEST (Europe/Berlin)
Gesamt: 12,113,245 IPs in seen_db.json (9,172,348 aktiv/180-Tage-Pfad, 2,940,897 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 404,171 |
| 8-14 Tage | 1,814,530 |
| 15-30 Tage | 475,707 |
| 31-60 Tage | 1,029,383 |
| 61-90 Tage | 753,121 |
| 91-180 Tage | 4,695,436 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,614,851 |
| 0-3 Tage | 20,573 |
| 4-7 Tage | 32,822 |
| 8-14 Tage | 59,508 |
| 15-30 Tage | 213,143 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-03 | 2,946 |
| 2026-10-04 | 6,828 |
| 2026-10-05 | 2,861 |
| 2026-10-06 | 7,938 |
| 2026-10-07 | 7,899 |
| 2026-10-08 | 7,255 |
| 2026-10-09 | 10,133 |
| 2026-10-10 | 7,535 |
| 2026-10-11 | 6,242 |
| 2026-10-12 | 3,865 |
| 2026-10-13 | 8,263 |
| 2026-10-14 | 7,422 |
| 2026-10-15 | 8,302 |
| 2026-10-16 | 15,472 |
| 2026-10-17 | 9,942 |
| 2026-10-18 | 8,658 |
| 2026-10-19 | 5,151 |
| 2026-10-20 | 9,596 |
| 2026-10-21 | 9,551 |
| 2026-10-22 | 10,400 |
| 2026-10-23 | 12,427 |
| 2026-10-24 | 15,093 |
| 2026-10-25 | 11,122 |
| 2026-10-26 | 9,483 |
| 2026-10-27 | 35,329 |
| 2026-10-28 | 11,319 |
| 2026-10-29 | 9,883 |
| 2026-10-30 | 20,216 |
| 2026-10-31 | 17,189 |
| 2026-11-01 | 15,493 |
| 2026-11-02 | 12,233 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,614,851** IPs. Brutto faellig in den naechsten 30 Tagen: **326,046**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **2,878,897**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-03 | 2,946 | 2,000 |
| 2026-10-04 | 6,828 | 2,000 |
| 2026-10-05 | 2,861 | 2,000 |
| 2026-10-06 | 7,938 | 2,000 |
| 2026-10-07 | 7,899 | 2,000 |
| 2026-10-08 | 7,255 | 2,000 |
| 2026-10-09 | 10,133 | 2,000 |
| 2026-10-10 | 7,535 | 2,000 |
| 2026-10-11 | 6,242 | 2,000 |
| 2026-10-12 | 3,865 | 2,000 |
| 2026-10-13 | 8,263 | 2,000 |
| 2026-10-14 | 7,422 | 2,000 |
| 2026-10-15 | 8,302 | 2,000 |
| 2026-10-16 | 15,472 | 2,000 |
| 2026-10-17 | 9,942 | 2,000 |
| 2026-10-18 | 8,658 | 2,000 |
| 2026-10-19 | 5,151 | 2,000 |
| 2026-10-20 | 9,596 | 2,000 |
| 2026-10-21 | 9,551 | 2,000 |
| 2026-10-22 | 10,400 | 2,000 |
| 2026-10-23 | 12,427 | 2,000 |
| 2026-10-24 | 15,093 | 2,000 |
| 2026-10-25 | 11,122 | 2,000 |
| 2026-10-26 | 9,483 | 2,000 |
| 2026-10-27 | 35,329 | 2,000 |
| 2026-10-28 | 11,319 | 2,000 |
| 2026-10-29 | 9,883 | 2,000 |
| 2026-10-30 | 20,216 | 2,000 |
| 2026-10-31 | 17,189 | 2,000 |
| 2026-11-01 | 15,493 | 2,000 |
| 2026-11-02 | 12,233 | 2,000 |

> Hinweis: Der Rueckstau von 2,878,897 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-03 | 7,291 |
| 2026-10-04 | 12,542 |
| 2026-10-05 | 17,466 |
| 2026-10-06 | 16,040 |
| 2026-10-07 | 14,974 |
| 2026-10-08 | 61,096 |
| 2026-10-09 | 221,466 |
| 2026-10-10 | 53,296 |
| 2026-10-11 | 16,013 |
| 2026-10-12 | 66,528 |
| 2026-10-13 | 1,582,336 |
| 2026-10-14 | 32,912 |
| 2026-10-15 | 41,301 |
| 2026-10-16 | 51,223 |
| 2026-10-17 | 24,217 |
| 2026-10-18 | 14,229 |
| 2026-10-19 | 22,189 |
| 2026-10-20 | 11,114 |
| 2026-10-21 | 11,075 |
| 2026-10-22 | 30,675 |
| 2026-10-23 | 50,344 |
| 2026-10-24 | 41,661 |
| 2026-10-25 | 21,565 |
| 2026-10-26 | 20,284 |
| 2026-10-27 | 20,614 |
| 2026-10-28 | 15,749 |
| 2026-10-29 | 9,641 |
| 2026-10-30 | 61,815 |
| 2026-10-31 | 88,157 |
| 2026-11-01 | 27,820 |
| 2026-11-02 | 28,775 |
| 2026-11-03 | 29,747 |
| 2026-11-04 | 29,587 |
| 2026-11-05 | 25,244 |
| 2026-11-06 | 36,342 |
| 2026-11-07 | 24,449 |
| 2026-11-08 | 26,098 |
| 2026-11-09 | 25,543 |
| 2026-11-10 | 32,711 |
| 2026-11-11 | 22,356 |
| 2026-11-12 | 20,499 |
| 2026-11-13 | 19,651 |
| 2026-11-14 | 22,968 |
| 2026-11-15 | 17,453 |
| 2026-11-16 | 17,967 |
| 2026-11-17 | 15,256 |
| 2026-11-18 | 19,505 |
| 2026-11-19 | 173,832 |
| 2026-11-20 | 26,170 |
| 2026-11-21 | 61,413 |
| 2026-11-22 | 30,442 |
| 2026-11-23 | 25,699 |
| 2026-11-24 | 26,492 |
| 2026-11-25 | 27,573 |
| 2026-11-26 | 28,685 |
| 2026-11-27 | 27,859 |
| 2026-11-28 | 109,240 |
| 2026-11-29 | 28,209 |
| 2026-11-30 | 25,576 |
| 2026-12-01 | 26,590 |
| 2026-12-02 | 26,227 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
