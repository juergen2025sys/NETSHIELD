# Seen-DB Expiry Forecast

Lauf: 2026-10-27 17:24 CET (Europe/Berlin)
Gesamt: 11,191,114 IPs in seen_db.json (8,035,636 aktiv/180-Tage-Pfad, 3,155,478 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 260,324 |
| 8-14 Tage | 198,997 |
| 15-30 Tage | 553,696 |
| 31-60 Tage | 857,288 |
| 61-90 Tage | 758,615 |
| 91-180 Tage | 5,406,716 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,781,663 |
| 0-3 Tage | 75,950 |
| 4-7 Tage | 60,603 |
| 8-14 Tage | 83,866 |
| 15-30 Tage | 153,396 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-27 | 34,915 |
| 2026-10-28 | 11,232 |
| 2026-10-29 | 9,788 |
| 2026-10-30 | 20,015 |
| 2026-10-31 | 16,878 |
| 2026-11-01 | 15,300 |
| 2026-11-02 | 11,861 |
| 2026-11-03 | 16,564 |
| 2026-11-04 | 10,025 |
| 2026-11-05 | 7,204 |
| 2026-11-06 | 12,029 |
| 2026-11-07 | 13,317 |
| 2026-11-08 | 6,237 |
| 2026-11-09 | 11,437 |
| 2026-11-10 | 23,617 |
| 2026-11-11 | 9,861 |
| 2026-11-12 | 8,012 |
| 2026-11-13 | 3,316 |
| 2026-11-14 | 11,571 |
| 2026-11-15 | 14,300 |
| 2026-11-16 | 18,869 |
| 2026-11-17 | 9,311 |
| 2026-11-18 | 3,486 |
| 2026-11-19 | 8,814 |
| 2026-11-20 | 10,893 |
| 2026-11-21 | 10,005 |
| 2026-11-22 | 10,033 |
| 2026-11-23 | 10,083 |
| 2026-11-24 | 10,175 |
| 2026-11-25 | 7,661 |
| 2026-11-26 | 3,390 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,781,663** IPs. Brutto faellig in den naechsten 30 Tagen: **370,199**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,089,862**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-27 | 34,915 | 2,000 |
| 2026-10-28 | 11,232 | 2,000 |
| 2026-10-29 | 9,788 | 2,000 |
| 2026-10-30 | 20,015 | 2,000 |
| 2026-10-31 | 16,878 | 2,000 |
| 2026-11-01 | 15,300 | 2,000 |
| 2026-11-02 | 11,861 | 2,000 |
| 2026-11-03 | 16,564 | 2,000 |
| 2026-11-04 | 10,025 | 2,000 |
| 2026-11-05 | 7,204 | 2,000 |
| 2026-11-06 | 12,029 | 2,000 |
| 2026-11-07 | 13,317 | 2,000 |
| 2026-11-08 | 6,237 | 2,000 |
| 2026-11-09 | 11,437 | 2,000 |
| 2026-11-10 | 23,617 | 2,000 |
| 2026-11-11 | 9,861 | 2,000 |
| 2026-11-12 | 8,012 | 2,000 |
| 2026-11-13 | 3,316 | 2,000 |
| 2026-11-14 | 11,571 | 2,000 |
| 2026-11-15 | 14,300 | 2,000 |
| 2026-11-16 | 18,869 | 2,000 |
| 2026-11-17 | 9,311 | 2,000 |
| 2026-11-18 | 3,486 | 2,000 |
| 2026-11-19 | 8,814 | 2,000 |
| 2026-11-20 | 10,893 | 2,000 |
| 2026-11-21 | 10,005 | 2,000 |
| 2026-11-22 | 10,033 | 2,000 |
| 2026-11-23 | 10,083 | 2,000 |
| 2026-11-24 | 10,175 | 2,000 |
| 2026-11-25 | 7,661 | 2,000 |
| 2026-11-26 | 3,390 | 2,000 |

> Hinweis: Der Rueckstau von 3,089,862 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-28 | 15,462 |
| 2026-10-29 | 9,474 |
| 2026-10-30 | 61,496 |
| 2026-10-31 | 87,994 |
| 2026-11-01 | 27,691 |
| 2026-11-02 | 28,634 |
| 2026-11-03 | 29,573 |
| 2026-11-04 | 29,435 |
| 2026-11-05 | 25,122 |
| 2026-11-06 | 36,154 |
| 2026-11-07 | 24,318 |
| 2026-11-08 | 25,990 |
| 2026-11-09 | 25,410 |
| 2026-11-10 | 32,568 |
| 2026-11-11 | 22,235 |
| 2026-11-12 | 20,416 |
| 2026-11-13 | 19,559 |
| 2026-11-14 | 22,856 |
| 2026-11-15 | 17,388 |
| 2026-11-16 | 17,871 |
| 2026-11-17 | 15,173 |
| 2026-11-18 | 19,420 |
| 2026-11-19 | 173,344 |
| 2026-11-20 | 26,037 |
| 2026-11-21 | 61,189 |
| 2026-11-22 | 30,295 |
| 2026-11-23 | 25,556 |
| 2026-11-24 | 26,371 |
| 2026-11-25 | 27,412 |
| 2026-11-26 | 28,574 |
| 2026-11-27 | 27,761 |
| 2026-11-28 | 109,078 |
| 2026-11-29 | 28,099 |
| 2026-11-30 | 25,450 |
| 2026-12-01 | 26,471 |
| 2026-12-02 | 26,111 |
| 2026-12-03 | 25,932 |
| 2026-12-04 | 27,854 |
| 2026-12-05 | 25,889 |
| 2026-12-06 | 30,063 |
| 2026-12-07 | 23,684 |
| 2026-12-08 | 39,300 |
| 2026-12-09 | 54,934 |
| 2026-12-10 | 25,038 |
| 2026-12-11 | 27,710 |
| 2026-12-12 | 24,331 |
| 2026-12-13 | 23,800 |
| 2026-12-14 | 23,421 |
| 2026-12-15 | 26,190 |
| 2026-12-16 | 16,603 |
| 2026-12-17 | 24,965 |
| 2026-12-18 | 22,465 |
| 2026-12-19 | 25,559 |
| 2026-12-20 | 14,294 |
| 2026-12-21 | 27,311 |
| 2026-12-22 | 24,075 |
| 2026-12-23 | 21,104 |
| 2026-12-24 | 20,389 |
| 2026-12-25 | 21,595 |
| 2026-12-26 | 17,812 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
