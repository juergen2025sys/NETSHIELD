# Seen-DB Expiry Forecast

Lauf: 2026-11-13 18:07 CET (Europe/Berlin)
Gesamt: 11,325,902 IPs in seen_db.json (8,090,176 aktiv/180-Tage-Pfad, 3,235,726 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 291,691 |
| 8-14 Tage | 226,770 |
| 15-30 Tage | 542,867 |
| 31-60 Tage | 689,196 |
| 61-90 Tage | 1,208,414 |
| 91-180 Tage | 5,131,238 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 3,002,458 |
| 0-3 Tage | 47,833 |
| 4-7 Tage | 32,304 |
| 8-14 Tage | 54,796 |
| 15-30 Tage | 98,335 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-13 | 3,299 |
| 2026-11-14 | 11,524 |
| 2026-11-15 | 14,229 |
| 2026-11-16 | 18,781 |
| 2026-11-17 | 9,265 |
| 2026-11-18 | 3,461 |
| 2026-11-19 | 8,750 |
| 2026-11-20 | 10,828 |
| 2026-11-21 | 9,923 |
| 2026-11-22 | 9,971 |
| 2026-11-23 | 10,010 |
| 2026-11-24 | 10,092 |
| 2026-11-25 | 7,606 |
| 2026-11-26 | 3,337 |
| 2026-11-27 | 3,857 |
| 2026-11-28 | 3,535 |
| 2026-11-29 | 8,126 |
| 2026-11-30 | 7,107 |
| 2026-12-01 | 8,076 |
| 2026-12-02 | 4,580 |
| 2026-12-03 | 7,720 |
| 2026-12-04 | 5,757 |
| 2026-12-05 | 5,409 |
| 2026-12-06 | 3,099 |
| 2026-12-07 | 7,799 |
| 2026-12-08 | 4,482 |
| 2026-12-09 | 9,029 |
| 2026-12-10 | 6,033 |
| 2026-12-11 | 4,693 |
| 2026-12-12 | 2,613 |
| 2026-12-13 | 3,044 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **3,002,458** IPs. Brutto faellig in den naechsten 30 Tagen: **226,035**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,166,493**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-13 | 3,299 | 2,000 |
| 2026-11-14 | 11,524 | 2,000 |
| 2026-11-15 | 14,229 | 2,000 |
| 2026-11-16 | 18,781 | 2,000 |
| 2026-11-17 | 9,265 | 2,000 |
| 2026-11-18 | 3,461 | 2,000 |
| 2026-11-19 | 8,750 | 2,000 |
| 2026-11-20 | 10,828 | 2,000 |
| 2026-11-21 | 9,923 | 2,000 |
| 2026-11-22 | 9,971 | 2,000 |
| 2026-11-23 | 10,010 | 2,000 |
| 2026-11-24 | 10,092 | 2,000 |
| 2026-11-25 | 7,606 | 2,000 |
| 2026-11-26 | 3,337 | 2,000 |
| 2026-11-27 | 3,857 | 2,000 |
| 2026-11-28 | 3,535 | 2,000 |
| 2026-11-29 | 8,126 | 2,000 |
| 2026-11-30 | 7,107 | 2,000 |
| 2026-12-01 | 8,076 | 2,000 |
| 2026-12-02 | 4,580 | 2,000 |
| 2026-12-03 | 7,720 | 2,000 |
| 2026-12-04 | 5,757 | 2,000 |
| 2026-12-05 | 5,409 | 2,000 |
| 2026-12-06 | 3,099 | 2,000 |
| 2026-12-07 | 7,799 | 2,000 |
| 2026-12-08 | 4,482 | 2,000 |
| 2026-12-09 | 9,029 | 2,000 |
| 2026-12-10 | 6,033 | 2,000 |
| 2026-12-11 | 4,693 | 2,000 |
| 2026-12-12 | 2,613 | 2,000 |
| 2026-12-13 | 3,044 | 2,000 |

> Hinweis: Der Rueckstau von 3,166,493 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-14 | 22,797 |
| 2026-11-15 | 17,366 |
| 2026-11-16 | 17,836 |
| 2026-11-17 | 15,149 |
| 2026-11-18 | 19,389 |
| 2026-11-19 | 173,163 |
| 2026-11-20 | 25,991 |
| 2026-11-21 | 61,092 |
| 2026-11-22 | 30,243 |
| 2026-11-23 | 25,517 |
| 2026-11-24 | 26,320 |
| 2026-11-25 | 27,350 |
| 2026-11-26 | 28,528 |
| 2026-11-27 | 27,720 |
| 2026-11-28 | 108,997 |
| 2026-11-29 | 28,060 |
| 2026-11-30 | 25,419 |
| 2026-12-01 | 26,439 |
| 2026-12-02 | 26,069 |
| 2026-12-03 | 25,883 |
| 2026-12-04 | 27,812 |
| 2026-12-05 | 25,857 |
| 2026-12-06 | 30,012 |
| 2026-12-07 | 23,651 |
| 2026-12-08 | 39,235 |
| 2026-12-09 | 54,730 |
| 2026-12-10 | 24,997 |
| 2026-12-11 | 27,665 |
| 2026-12-12 | 24,289 |
| 2026-12-13 | 23,752 |
| 2026-12-14 | 23,361 |
| 2026-12-15 | 26,135 |
| 2026-12-16 | 16,558 |
| 2026-12-17 | 24,927 |
| 2026-12-18 | 22,418 |
| 2026-12-19 | 25,487 |
| 2026-12-20 | 14,254 |
| 2026-12-21 | 27,240 |
| 2026-12-22 | 24,006 |
| 2026-12-23 | 21,047 |
| 2026-12-24 | 20,342 |
| 2026-12-25 | 21,558 |
| 2026-12-26 | 17,763 |
| 2026-12-27 | 24,584 |
| 2026-12-28 | 21,685 |
| 2026-12-29 | 22,518 |
| 2026-12-30 | 26,469 |
| 2026-12-31 | 20,114 |
| 2027-01-01 | 18,469 |
| 2027-01-02 | 26,071 |
| 2027-01-03 | 14,789 |
| 2027-01-04 | 28,413 |
| 2027-01-05 | 22,349 |
| 2027-01-06 | 35,536 |
| 2027-01-07 | 23,927 |
| 2027-01-08 | 25,827 |
| 2027-01-09 | 21,585 |
| 2027-01-10 | 24,689 |
| 2027-01-11 | 24,100 |
| 2027-01-12 | 22,975 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
