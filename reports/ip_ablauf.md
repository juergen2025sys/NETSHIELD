# Seen-DB Expiry Forecast

Lauf: 2026-10-21 06:25 CEST (Europe/Berlin)
Gesamt: 11,013,636 IPs in seen_db.json (7,911,832 aktiv/180-Tage-Pfad, 3,101,804 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 199,737 |
| 8-14 Tage | 274,521 |
| 15-30 Tage | 524,250 |
| 31-60 Tage | 925,220 |
| 61-90 Tage | 700,895 |
| 91-180 Tage | 5,287,209 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,713,513 |
| 0-3 Tage | 47,118 |
| 4-7 Tage | 66,767 |
| 8-14 Tage | 100,547 |
| 15-30 Tage | 173,859 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-21 | 9,467 |
| 2026-10-22 | 10,328 |
| 2026-10-23 | 12,329 |
| 2026-10-24 | 14,994 |
| 2026-10-25 | 11,047 |
| 2026-10-26 | 9,402 |
| 2026-10-27 | 35,075 |
| 2026-10-28 | 11,243 |
| 2026-10-29 | 9,799 |
| 2026-10-30 | 20,047 |
| 2026-10-31 | 16,897 |
| 2026-11-01 | 15,308 |
| 2026-11-02 | 11,873 |
| 2026-11-03 | 16,583 |
| 2026-11-04 | 10,040 |
| 2026-11-05 | 7,216 |
| 2026-11-06 | 12,044 |
| 2026-11-07 | 13,334 |
| 2026-11-08 | 6,253 |
| 2026-11-09 | 11,463 |
| 2026-11-10 | 23,811 |
| 2026-11-11 | 9,879 |
| 2026-11-12 | 8,038 |
| 2026-11-13 | 3,331 |
| 2026-11-14 | 11,611 |
| 2026-11-15 | 14,341 |
| 2026-11-16 | 18,940 |
| 2026-11-17 | 9,349 |
| 2026-11-18 | 3,518 |
| 2026-11-19 | 8,887 |
| 2026-11-20 | 11,031 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,713,513** IPs. Brutto faellig in den naechsten 30 Tagen: **387,478**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,038,991**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-21 | 9,467 | 2,000 |
| 2026-10-22 | 10,328 | 2,000 |
| 2026-10-23 | 12,329 | 2,000 |
| 2026-10-24 | 14,994 | 2,000 |
| 2026-10-25 | 11,047 | 2,000 |
| 2026-10-26 | 9,402 | 2,000 |
| 2026-10-27 | 35,075 | 2,000 |
| 2026-10-28 | 11,243 | 2,000 |
| 2026-10-29 | 9,799 | 2,000 |
| 2026-10-30 | 20,047 | 2,000 |
| 2026-10-31 | 16,897 | 2,000 |
| 2026-11-01 | 15,308 | 2,000 |
| 2026-11-02 | 11,873 | 2,000 |
| 2026-11-03 | 16,583 | 2,000 |
| 2026-11-04 | 10,040 | 2,000 |
| 2026-11-05 | 7,216 | 2,000 |
| 2026-11-06 | 12,044 | 2,000 |
| 2026-11-07 | 13,334 | 2,000 |
| 2026-11-08 | 6,253 | 2,000 |
| 2026-11-09 | 11,463 | 2,000 |
| 2026-11-10 | 23,811 | 2,000 |
| 2026-11-11 | 9,879 | 2,000 |
| 2026-11-12 | 8,038 | 2,000 |
| 2026-11-13 | 3,331 | 2,000 |
| 2026-11-14 | 11,611 | 2,000 |
| 2026-11-15 | 14,341 | 2,000 |
| 2026-11-16 | 18,940 | 2,000 |
| 2026-11-17 | 9,349 | 2,000 |
| 2026-11-18 | 3,518 | 2,000 |
| 2026-11-19 | 8,887 | 2,000 |
| 2026-11-20 | 11,031 | 2,000 |

> Hinweis: Der Rueckstau von 3,038,991 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-22 | 30,441 |
| 2026-10-23 | 50,182 |
| 2026-10-24 | 41,552 |
| 2026-10-25 | 21,468 |
| 2026-10-26 | 20,176 |
| 2026-10-27 | 20,397 |
| 2026-10-28 | 15,521 |
| 2026-10-29 | 9,502 |
| 2026-10-30 | 61,562 |
| 2026-10-31 | 88,024 |
| 2026-11-01 | 27,713 |
| 2026-11-02 | 28,661 |
| 2026-11-03 | 29,602 |
| 2026-11-04 | 29,457 |
| 2026-11-05 | 25,146 |
| 2026-11-06 | 36,189 |
| 2026-11-07 | 24,347 |
| 2026-11-08 | 26,004 |
| 2026-11-09 | 25,432 |
| 2026-11-10 | 32,592 |
| 2026-11-11 | 22,260 |
| 2026-11-12 | 20,433 |
| 2026-11-13 | 19,579 |
| 2026-11-14 | 22,876 |
| 2026-11-15 | 17,399 |
| 2026-11-16 | 17,896 |
| 2026-11-17 | 15,182 |
| 2026-11-18 | 19,438 |
| 2026-11-19 | 173,410 |
| 2026-11-20 | 26,067 |
| 2026-11-21 | 61,227 |
| 2026-11-22 | 30,330 |
| 2026-11-23 | 25,585 |
| 2026-11-24 | 26,396 |
| 2026-11-25 | 27,442 |
| 2026-11-26 | 28,592 |
| 2026-11-27 | 27,779 |
| 2026-11-28 | 109,108 |
| 2026-11-29 | 28,118 |
| 2026-11-30 | 25,474 |
| 2026-12-01 | 26,483 |
| 2026-12-02 | 26,135 |
| 2026-12-03 | 25,958 |
| 2026-12-04 | 27,866 |
| 2026-12-05 | 25,909 |
| 2026-12-06 | 30,081 |
| 2026-12-07 | 23,697 |
| 2026-12-08 | 39,326 |
| 2026-12-09 | 55,033 |
| 2026-12-10 | 25,053 |
| 2026-12-11 | 27,733 |
| 2026-12-12 | 24,357 |
| 2026-12-13 | 23,830 |
| 2026-12-14 | 23,441 |
| 2026-12-15 | 26,221 |
| 2026-12-16 | 16,645 |
| 2026-12-17 | 24,996 |
| 2026-12-18 | 22,496 |
| 2026-12-19 | 25,593 |
| 2026-12-20 | 14,316 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
