# Seen-DB Expiry Forecast

Lauf: 2026-11-27 03:08 CET (Europe/Berlin)
Gesamt: 11,289,194 IPs in seen_db.json (7,890,885 aktiv/180-Tage-Pfad, 3,398,309 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 268,426 |
| 8-14 Tage | 225,789 |
| 15-30 Tage | 357,081 |
| 31-60 Tage | 794,412 |
| 61-90 Tage | 1,540,967 |
| 91-180 Tage | 4,704,210 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 3,114,310 |
| 0-3 Tage | 22,563 |
| 4-7 Tage | 26,050 |
| 8-14 Tage | 40,291 |
| 15-30 Tage | 195,095 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-27 | 3,846 |
| 2026-11-28 | 3,522 |
| 2026-11-29 | 8,109 |
| 2026-11-30 | 7,086 |
| 2026-12-01 | 8,055 |
| 2026-12-02 | 4,554 |
| 2026-12-03 | 7,700 |
| 2026-12-04 | 5,741 |
| 2026-12-05 | 5,378 |
| 2026-12-06 | 3,079 |
| 2026-12-07 | 7,769 |
| 2026-12-08 | 4,439 |
| 2026-12-09 | 8,997 |
| 2026-12-10 | 5,994 |
| 2026-12-11 | 4,635 |
| 2026-12-12 | 2,573 |
| 2026-12-13 | 2,990 |
| 2026-12-14 | 7,586 |
| 2026-12-15 | 8,078 |
| 2026-12-16 | 7,483 |
| 2026-12-17 | 7,621 |
| 2026-12-18 | 9,341 |
| 2026-12-19 | 1,625 |
| 2026-12-20 | 10,062 |
| 2026-12-21 | 8,995 |
| 2026-12-22 | 31,698 |
| 2026-12-23 | 14,721 |
| 2026-12-24 | 19,445 |
| 2026-12-25 | 15,218 |
| 2026-12-26 | 18,579 |
| 2026-12-27 | 28,764 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **3,114,310** IPs. Brutto faellig in den naechsten 30 Tagen: **283,683**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,335,993**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-27 | 3,846 | 2,000 |
| 2026-11-28 | 3,522 | 2,000 |
| 2026-11-29 | 8,109 | 2,000 |
| 2026-11-30 | 7,086 | 2,000 |
| 2026-12-01 | 8,055 | 2,000 |
| 2026-12-02 | 4,554 | 2,000 |
| 2026-12-03 | 7,700 | 2,000 |
| 2026-12-04 | 5,741 | 2,000 |
| 2026-12-05 | 5,378 | 2,000 |
| 2026-12-06 | 3,079 | 2,000 |
| 2026-12-07 | 7,769 | 2,000 |
| 2026-12-08 | 4,439 | 2,000 |
| 2026-12-09 | 8,997 | 2,000 |
| 2026-12-10 | 5,994 | 2,000 |
| 2026-12-11 | 4,635 | 2,000 |
| 2026-12-12 | 2,573 | 2,000 |
| 2026-12-13 | 2,990 | 2,000 |
| 2026-12-14 | 7,586 | 2,000 |
| 2026-12-15 | 8,078 | 2,000 |
| 2026-12-16 | 7,483 | 2,000 |
| 2026-12-17 | 7,621 | 2,000 |
| 2026-12-18 | 9,341 | 2,000 |
| 2026-12-19 | 1,625 | 2,000 |
| 2026-12-20 | 10,062 | 2,000 |
| 2026-12-21 | 8,995 | 2,000 |
| 2026-12-22 | 31,698 | 2,000 |
| 2026-12-23 | 14,721 | 2,000 |
| 2026-12-24 | 19,445 | 2,000 |
| 2026-12-25 | 15,218 | 2,000 |
| 2026-12-26 | 18,579 | 2,000 |
| 2026-12-27 | 28,764 | 2,000 |

> Hinweis: Der Rueckstau von 3,335,993 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-28 | 108,938 |
| 2026-11-29 | 28,030 |
| 2026-11-30 | 25,386 |
| 2026-12-01 | 26,411 |
| 2026-12-02 | 26,031 |
| 2026-12-03 | 25,844 |
| 2026-12-04 | 27,786 |
| 2026-12-05 | 25,825 |
| 2026-12-06 | 29,972 |
| 2026-12-07 | 23,626 |
| 2026-12-08 | 39,210 |
| 2026-12-09 | 54,580 |
| 2026-12-10 | 24,957 |
| 2026-12-11 | 27,619 |
| 2026-12-12 | 24,254 |
| 2026-12-13 | 23,698 |
| 2026-12-14 | 23,326 |
| 2026-12-15 | 26,098 |
| 2026-12-16 | 16,511 |
| 2026-12-17 | 24,870 |
| 2026-12-18 | 22,391 |
| 2026-12-19 | 25,447 |
| 2026-12-20 | 14,221 |
| 2026-12-21 | 27,200 |
| 2026-12-22 | 23,969 |
| 2026-12-23 | 21,006 |
| 2026-12-24 | 20,310 |
| 2026-12-25 | 21,528 |
| 2026-12-26 | 17,715 |
| 2026-12-27 | 24,537 |
| 2026-12-28 | 21,647 |
| 2026-12-29 | 22,485 |
| 2026-12-30 | 26,424 |
| 2026-12-31 | 20,083 |
| 2027-01-01 | 18,436 |
| 2027-01-02 | 26,028 |
| 2027-01-03 | 14,749 |
| 2027-01-04 | 28,378 |
| 2027-01-05 | 22,300 |
| 2027-01-06 | 35,477 |
| 2027-01-07 | 23,884 |
| 2027-01-08 | 25,777 |
| 2027-01-09 | 21,544 |
| 2027-01-10 | 24,659 |
| 2027-01-11 | 24,063 |
| 2027-01-12 | 22,939 |
| 2027-01-13 | 23,228 |
| 2027-01-14 | 21,836 |
| 2027-01-15 | 22,670 |
| 2027-01-16 | 26,728 |
| 2027-01-17 | 20,501 |
| 2027-01-18 | 24,819 |
| 2027-01-19 | 22,468 |
| 2027-01-20 | 23,147 |
| 2027-01-21 | 45,452 |
| 2027-01-22 | 28,522 |
| 2027-01-23 | 25,814 |
| 2027-01-24 | 25,115 |
| 2027-01-25 | 41,849 |
| 2027-01-26 | 63,390 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
