# Seen-DB Expiry Forecast

Lauf: 2026-11-16 17:18 CET (Europe/Berlin)
Gesamt: 11,366,323 IPs in seen_db.json (8,110,280 aktiv/180-Tage-Pfad, 3,256,043 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 350,477 |
| 8-14 Tage | 272,345 |
| 15-30 Tage | 446,302 |
| 31-60 Tage | 690,758 |
| 61-90 Tage | 1,397,488 |
| 91-180 Tage | 4,952,910 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 3,027,541 |
| 0-3 Tage | 40,239 |
| 4-7 Tage | 40,711 |
| 8-14 Tage | 43,635 |
| 15-30 Tage | 103,917 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-16 | 18,776 |
| 2026-11-17 | 9,257 |
| 2026-11-18 | 3,457 |
| 2026-11-19 | 8,749 |
| 2026-11-20 | 10,823 |
| 2026-11-21 | 9,917 |
| 2026-11-22 | 9,970 |
| 2026-11-23 | 10,001 |
| 2026-11-24 | 10,088 |
| 2026-11-25 | 7,602 |
| 2026-11-26 | 3,334 |
| 2026-11-27 | 3,854 |
| 2026-11-28 | 3,533 |
| 2026-11-29 | 8,121 |
| 2026-11-30 | 7,103 |
| 2026-12-01 | 8,074 |
| 2026-12-02 | 4,574 |
| 2026-12-03 | 7,717 |
| 2026-12-04 | 5,755 |
| 2026-12-05 | 5,399 |
| 2026-12-06 | 3,090 |
| 2026-12-07 | 7,791 |
| 2026-12-08 | 4,465 |
| 2026-12-09 | 9,019 |
| 2026-12-10 | 6,011 |
| 2026-12-11 | 4,669 |
| 2026-12-12 | 2,600 |
| 2026-12-13 | 3,015 |
| 2026-12-14 | 7,673 |
| 2026-12-15 | 8,156 |
| 2026-12-16 | 8,151 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **3,027,541** IPs. Brutto faellig in den naechsten 30 Tagen: **220,744**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,186,285**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-16 | 18,776 | 2,000 |
| 2026-11-17 | 9,257 | 2,000 |
| 2026-11-18 | 3,457 | 2,000 |
| 2026-11-19 | 8,749 | 2,000 |
| 2026-11-20 | 10,823 | 2,000 |
| 2026-11-21 | 9,917 | 2,000 |
| 2026-11-22 | 9,970 | 2,000 |
| 2026-11-23 | 10,001 | 2,000 |
| 2026-11-24 | 10,088 | 2,000 |
| 2026-11-25 | 7,602 | 2,000 |
| 2026-11-26 | 3,334 | 2,000 |
| 2026-11-27 | 3,854 | 2,000 |
| 2026-11-28 | 3,533 | 2,000 |
| 2026-11-29 | 8,121 | 2,000 |
| 2026-11-30 | 7,103 | 2,000 |
| 2026-12-01 | 8,074 | 2,000 |
| 2026-12-02 | 4,574 | 2,000 |
| 2026-12-03 | 7,717 | 2,000 |
| 2026-12-04 | 5,755 | 2,000 |
| 2026-12-05 | 5,399 | 2,000 |
| 2026-12-06 | 3,090 | 2,000 |
| 2026-12-07 | 7,791 | 2,000 |
| 2026-12-08 | 4,465 | 2,000 |
| 2026-12-09 | 9,019 | 2,000 |
| 2026-12-10 | 6,011 | 2,000 |
| 2026-12-11 | 4,669 | 2,000 |
| 2026-12-12 | 2,600 | 2,000 |
| 2026-12-13 | 3,015 | 2,000 |
| 2026-12-14 | 7,673 | 2,000 |
| 2026-12-15 | 8,156 | 2,000 |
| 2026-12-16 | 8,151 | 2,000 |

> Hinweis: Der Rueckstau von 3,186,285 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-17 | 15,142 |
| 2026-11-18 | 19,386 |
| 2026-11-19 | 173,135 |
| 2026-11-20 | 25,986 |
| 2026-11-21 | 61,081 |
| 2026-11-22 | 30,234 |
| 2026-11-23 | 25,513 |
| 2026-11-24 | 26,316 |
| 2026-11-25 | 27,346 |
| 2026-11-26 | 28,523 |
| 2026-11-27 | 27,714 |
| 2026-11-28 | 108,980 |
| 2026-11-29 | 28,055 |
| 2026-11-30 | 25,411 |
| 2026-12-01 | 26,435 |
| 2026-12-02 | 26,063 |
| 2026-12-03 | 25,873 |
| 2026-12-04 | 27,802 |
| 2026-12-05 | 25,847 |
| 2026-12-06 | 30,003 |
| 2026-12-07 | 23,648 |
| 2026-12-08 | 39,230 |
| 2026-12-09 | 54,700 |
| 2026-12-10 | 24,990 |
| 2026-12-11 | 27,659 |
| 2026-12-12 | 24,282 |
| 2026-12-13 | 23,737 |
| 2026-12-14 | 23,358 |
| 2026-12-15 | 26,130 |
| 2026-12-16 | 16,545 |
| 2026-12-17 | 24,912 |
| 2026-12-18 | 22,413 |
| 2026-12-19 | 25,479 |
| 2026-12-20 | 14,253 |
| 2026-12-21 | 27,230 |
| 2026-12-22 | 24,001 |
| 2026-12-23 | 21,040 |
| 2026-12-24 | 20,336 |
| 2026-12-25 | 21,550 |
| 2026-12-26 | 17,753 |
| 2026-12-27 | 24,572 |
| 2026-12-28 | 21,676 |
| 2026-12-29 | 22,511 |
| 2026-12-30 | 26,458 |
| 2026-12-31 | 20,110 |
| 2027-01-01 | 18,463 |
| 2027-01-02 | 26,063 |
| 2027-01-03 | 14,785 |
| 2027-01-04 | 28,411 |
| 2027-01-05 | 22,340 |
| 2027-01-06 | 35,523 |
| 2027-01-07 | 23,919 |
| 2027-01-08 | 25,819 |
| 2027-01-09 | 21,578 |
| 2027-01-10 | 24,686 |
| 2027-01-11 | 24,095 |
| 2027-01-12 | 22,969 |
| 2027-01-13 | 23,256 |
| 2027-01-14 | 21,860 |
| 2027-01-15 | 22,697 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
