# Seen-DB Expiry Forecast

Lauf: 2026-11-15 21:59 CET (Europe/Berlin)
Gesamt: 11,359,050 IPs in seen_db.json (8,109,658 aktiv/180-Tage-Pfad, 3,249,392 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 342,815 |
| 8-14 Tage | 272,462 |
| 15-30 Tage | 455,204 |
| 31-60 Tage | 684,673 |
| 61-90 Tage | 1,377,104 |
| 91-180 Tage | 4,977,400 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 3,014,622 |
| 0-3 Tage | 45,721 |
| 4-7 Tage | 39,463 |
| 8-14 Tage | 46,539 |
| 15-30 Tage | 103,047 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-15 | 14,227 |
| 2026-11-16 | 18,778 |
| 2026-11-17 | 9,257 |
| 2026-11-18 | 3,459 |
| 2026-11-19 | 8,749 |
| 2026-11-20 | 10,823 |
| 2026-11-21 | 9,920 |
| 2026-11-22 | 9,971 |
| 2026-11-23 | 10,003 |
| 2026-11-24 | 10,089 |
| 2026-11-25 | 7,604 |
| 2026-11-26 | 3,335 |
| 2026-11-27 | 3,854 |
| 2026-11-28 | 3,533 |
| 2026-11-29 | 8,121 |
| 2026-11-30 | 7,104 |
| 2026-12-01 | 8,074 |
| 2026-12-02 | 4,574 |
| 2026-12-03 | 7,717 |
| 2026-12-04 | 5,755 |
| 2026-12-05 | 5,400 |
| 2026-12-06 | 3,093 |
| 2026-12-07 | 7,793 |
| 2026-12-08 | 4,472 |
| 2026-12-09 | 9,020 |
| 2026-12-10 | 6,021 |
| 2026-12-11 | 4,672 |
| 2026-12-12 | 2,602 |
| 2026-12-13 | 3,036 |
| 2026-12-14 | 7,693 |
| 2026-12-15 | 8,160 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **3,014,622** IPs. Brutto faellig in den naechsten 30 Tagen: **226,909**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,179,531**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-15 | 14,227 | 2,000 |
| 2026-11-16 | 18,778 | 2,000 |
| 2026-11-17 | 9,257 | 2,000 |
| 2026-11-18 | 3,459 | 2,000 |
| 2026-11-19 | 8,749 | 2,000 |
| 2026-11-20 | 10,823 | 2,000 |
| 2026-11-21 | 9,920 | 2,000 |
| 2026-11-22 | 9,971 | 2,000 |
| 2026-11-23 | 10,003 | 2,000 |
| 2026-11-24 | 10,089 | 2,000 |
| 2026-11-25 | 7,604 | 2,000 |
| 2026-11-26 | 3,335 | 2,000 |
| 2026-11-27 | 3,854 | 2,000 |
| 2026-11-28 | 3,533 | 2,000 |
| 2026-11-29 | 8,121 | 2,000 |
| 2026-11-30 | 7,104 | 2,000 |
| 2026-12-01 | 8,074 | 2,000 |
| 2026-12-02 | 4,574 | 2,000 |
| 2026-12-03 | 7,717 | 2,000 |
| 2026-12-04 | 5,755 | 2,000 |
| 2026-12-05 | 5,400 | 2,000 |
| 2026-12-06 | 3,093 | 2,000 |
| 2026-12-07 | 7,793 | 2,000 |
| 2026-12-08 | 4,472 | 2,000 |
| 2026-12-09 | 9,020 | 2,000 |
| 2026-12-10 | 6,021 | 2,000 |
| 2026-12-11 | 4,672 | 2,000 |
| 2026-12-12 | 2,602 | 2,000 |
| 2026-12-13 | 3,036 | 2,000 |
| 2026-12-14 | 7,693 | 2,000 |
| 2026-12-15 | 8,160 | 2,000 |

> Hinweis: Der Rueckstau von 3,179,531 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-16 | 17,836 |
| 2026-11-17 | 15,144 |
| 2026-11-18 | 19,386 |
| 2026-11-19 | 173,144 |
| 2026-11-20 | 25,986 |
| 2026-11-21 | 61,083 |
| 2026-11-22 | 30,236 |
| 2026-11-23 | 25,515 |
| 2026-11-24 | 26,316 |
| 2026-11-25 | 27,348 |
| 2026-11-26 | 28,525 |
| 2026-11-27 | 27,714 |
| 2026-11-28 | 108,987 |
| 2026-11-29 | 28,057 |
| 2026-11-30 | 25,414 |
| 2026-12-01 | 26,438 |
| 2026-12-02 | 26,063 |
| 2026-12-03 | 25,874 |
| 2026-12-04 | 27,803 |
| 2026-12-05 | 25,849 |
| 2026-12-06 | 30,006 |
| 2026-12-07 | 23,649 |
| 2026-12-08 | 39,231 |
| 2026-12-09 | 54,709 |
| 2026-12-10 | 24,992 |
| 2026-12-11 | 27,660 |
| 2026-12-12 | 24,284 |
| 2026-12-13 | 23,739 |
| 2026-12-14 | 23,360 |
| 2026-12-15 | 26,133 |
| 2026-12-16 | 16,552 |
| 2026-12-17 | 24,913 |
| 2026-12-18 | 22,414 |
| 2026-12-19 | 25,482 |
| 2026-12-20 | 14,253 |
| 2026-12-21 | 27,233 |
| 2026-12-22 | 24,001 |
| 2026-12-23 | 21,040 |
| 2026-12-24 | 20,338 |
| 2026-12-25 | 21,553 |
| 2026-12-26 | 17,757 |
| 2026-12-27 | 24,575 |
| 2026-12-28 | 21,679 |
| 2026-12-29 | 22,513 |
| 2026-12-30 | 26,463 |
| 2026-12-31 | 20,112 |
| 2027-01-01 | 18,465 |
| 2027-01-02 | 26,066 |
| 2027-01-03 | 14,786 |
| 2027-01-04 | 28,412 |
| 2027-01-05 | 22,343 |
| 2027-01-06 | 35,528 |
| 2027-01-07 | 23,923 |
| 2027-01-08 | 25,821 |
| 2027-01-09 | 21,579 |
| 2027-01-10 | 24,687 |
| 2027-01-11 | 24,096 |
| 2027-01-12 | 22,971 |
| 2027-01-13 | 23,256 |
| 2027-01-14 | 21,862 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
