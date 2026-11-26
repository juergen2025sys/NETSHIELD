# Seen-DB Expiry Forecast

Lauf: 2026-11-26 09:50 CET (Europe/Berlin)
Gesamt: 11,277,998 IPs in seen_db.json (7,900,448 aktiv/180-Tage-Pfad, 3,377,550 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 268,348 |
| 8-14 Tage | 225,981 |
| 15-30 Tage | 360,200 |
| 31-60 Tage | 755,660 |
| 61-90 Tage | 1,584,240 |
| 91-180 Tage | 4,706,019 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 3,113,260 |
| 0-3 Tage | 18,801 |
| 4-7 Tage | 27,401 |
| 8-14 Tage | 41,405 |
| 15-30 Tage | 176,683 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-26 | 3,323 |
| 2026-11-27 | 3,846 |
| 2026-11-28 | 3,523 |
| 2026-11-29 | 8,109 |
| 2026-11-30 | 7,086 |
| 2026-12-01 | 8,057 |
| 2026-12-02 | 4,556 |
| 2026-12-03 | 7,702 |
| 2026-12-04 | 5,742 |
| 2026-12-05 | 5,380 |
| 2026-12-06 | 3,079 |
| 2026-12-07 | 7,770 |
| 2026-12-08 | 4,440 |
| 2026-12-09 | 8,998 |
| 2026-12-10 | 5,996 |
| 2026-12-11 | 4,637 |
| 2026-12-12 | 2,577 |
| 2026-12-13 | 2,992 |
| 2026-12-14 | 7,592 |
| 2026-12-15 | 8,080 |
| 2026-12-16 | 7,485 |
| 2026-12-17 | 7,624 |
| 2026-12-18 | 9,344 |
| 2026-12-19 | 1,629 |
| 2026-12-20 | 10,064 |
| 2026-12-21 | 9,003 |
| 2026-12-22 | 31,716 |
| 2026-12-23 | 14,730 |
| 2026-12-24 | 19,457 |
| 2026-12-25 | 15,244 |
| 2026-12-26 | 18,615 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **3,113,260** IPs. Brutto faellig in den naechsten 30 Tagen: **258,396**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,309,656**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-26 | 3,323 | 2,000 |
| 2026-11-27 | 3,846 | 2,000 |
| 2026-11-28 | 3,523 | 2,000 |
| 2026-11-29 | 8,109 | 2,000 |
| 2026-11-30 | 7,086 | 2,000 |
| 2026-12-01 | 8,057 | 2,000 |
| 2026-12-02 | 4,556 | 2,000 |
| 2026-12-03 | 7,702 | 2,000 |
| 2026-12-04 | 5,742 | 2,000 |
| 2026-12-05 | 5,380 | 2,000 |
| 2026-12-06 | 3,079 | 2,000 |
| 2026-12-07 | 7,770 | 2,000 |
| 2026-12-08 | 4,440 | 2,000 |
| 2026-12-09 | 8,998 | 2,000 |
| 2026-12-10 | 5,996 | 2,000 |
| 2026-12-11 | 4,637 | 2,000 |
| 2026-12-12 | 2,577 | 2,000 |
| 2026-12-13 | 2,992 | 2,000 |
| 2026-12-14 | 7,592 | 2,000 |
| 2026-12-15 | 8,080 | 2,000 |
| 2026-12-16 | 7,485 | 2,000 |
| 2026-12-17 | 7,624 | 2,000 |
| 2026-12-18 | 9,344 | 2,000 |
| 2026-12-19 | 1,629 | 2,000 |
| 2026-12-20 | 10,064 | 2,000 |
| 2026-12-21 | 9,003 | 2,000 |
| 2026-12-22 | 31,716 | 2,000 |
| 2026-12-23 | 14,730 | 2,000 |
| 2026-12-24 | 19,457 | 2,000 |
| 2026-12-25 | 15,244 | 2,000 |
| 2026-12-26 | 18,615 | 2,000 |

> Hinweis: Der Rueckstau von 3,309,656 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-27 | 27,695 |
| 2026-11-28 | 108,941 |
| 2026-11-29 | 28,032 |
| 2026-11-30 | 25,387 |
| 2026-12-01 | 26,412 |
| 2026-12-02 | 26,034 |
| 2026-12-03 | 25,847 |
| 2026-12-04 | 27,788 |
| 2026-12-05 | 25,826 |
| 2026-12-06 | 29,973 |
| 2026-12-07 | 23,628 |
| 2026-12-08 | 39,210 |
| 2026-12-09 | 54,594 |
| 2026-12-10 | 24,962 |
| 2026-12-11 | 27,620 |
| 2026-12-12 | 24,255 |
| 2026-12-13 | 23,703 |
| 2026-12-14 | 23,326 |
| 2026-12-15 | 26,102 |
| 2026-12-16 | 16,511 |
| 2026-12-17 | 24,874 |
| 2026-12-18 | 22,393 |
| 2026-12-19 | 25,451 |
| 2026-12-20 | 14,222 |
| 2026-12-21 | 27,202 |
| 2026-12-22 | 23,974 |
| 2026-12-23 | 21,007 |
| 2026-12-24 | 20,311 |
| 2026-12-25 | 21,530 |
| 2026-12-26 | 17,719 |
| 2026-12-27 | 24,543 |
| 2026-12-28 | 21,650 |
| 2026-12-29 | 22,487 |
| 2026-12-30 | 26,425 |
| 2026-12-31 | 20,085 |
| 2027-01-01 | 18,439 |
| 2027-01-02 | 26,030 |
| 2027-01-03 | 14,753 |
| 2027-01-04 | 28,380 |
| 2027-01-05 | 22,302 |
| 2027-01-06 | 35,480 |
| 2027-01-07 | 23,885 |
| 2027-01-08 | 25,782 |
| 2027-01-09 | 21,548 |
| 2027-01-10 | 24,661 |
| 2027-01-11 | 24,065 |
| 2027-01-12 | 22,941 |
| 2027-01-13 | 23,231 |
| 2027-01-14 | 21,840 |
| 2027-01-15 | 22,672 |
| 2027-01-16 | 26,730 |
| 2027-01-17 | 20,505 |
| 2027-01-18 | 24,821 |
| 2027-01-19 | 22,469 |
| 2027-01-20 | 23,150 |
| 2027-01-21 | 45,462 |
| 2027-01-22 | 28,529 |
| 2027-01-23 | 25,817 |
| 2027-01-24 | 25,124 |
| 2027-01-25 | 41,854 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
