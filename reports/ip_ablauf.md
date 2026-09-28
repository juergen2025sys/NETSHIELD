# Seen-DB Expiry Forecast

Lauf: 2026-09-28 16:21 CEST (Europe/Berlin)
Gesamt: 11,830,887 IPs in seen_db.json (8,951,533 aktiv/180-Tage-Pfad, 2,879,354 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 81,110 |
| 8-14 Tage | 450,318 |
| 15-30 Tage | 1,993,349 |
| 31-60 Tage | 1,031,080 |
| 61-90 Tage | 860,222 |
| 91-180 Tage | 4,535,454 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 1,245,306 |
| 0-3 Tage | 67,912 |
| 4-7 Tage | 1,318,932 |
| 8-14 Tage | 51,030 |
| 15-30 Tage | 196,174 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-28 | 770 |
| 2026-09-30 | 59,525 |
| 2026-10-01 | 7,617 |
| 2026-10-02 | 1,306,196 |
| 2026-10-03 | 2,961 |
| 2026-10-04 | 6,894 |
| 2026-10-05 | 2,881 |
| 2026-10-06 | 7,985 |
| 2026-10-07 | 7,926 |
| 2026-10-08 | 7,273 |
| 2026-10-09 | 10,154 |
| 2026-10-10 | 7,562 |
| 2026-10-11 | 6,255 |
| 2026-10-12 | 3,875 |
| 2026-10-13 | 8,299 |
| 2026-10-14 | 7,443 |
| 2026-10-15 | 8,325 |
| 2026-10-16 | 15,505 |
| 2026-10-17 | 9,960 |
| 2026-10-18 | 8,691 |
| 2026-10-19 | 5,171 |
| 2026-10-20 | 9,651 |
| 2026-10-21 | 9,588 |
| 2026-10-22 | 10,470 |
| 2026-10-23 | 12,507 |
| 2026-10-24 | 15,181 |
| 2026-10-25 | 11,165 |
| 2026-10-26 | 9,536 |
| 2026-10-27 | 35,458 |
| 2026-10-28 | 11,432 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **1,245,306** IPs. Brutto faellig in den naechsten 30 Tagen: **1,626,256**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,811,562**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-28 | 770 | 2,000 |
| 2026-09-30 | 59,525 | 2,000 |
| 2026-10-01 | 7,617 | 2,000 |
| 2026-10-02 | 1,306,196 | 2,000 |
| 2026-10-03 | 2,961 | 2,000 |
| 2026-10-04 | 6,894 | 2,000 |
| 2026-10-05 | 2,881 | 2,000 |
| 2026-10-06 | 7,985 | 2,000 |
| 2026-10-07 | 7,926 | 2,000 |
| 2026-10-08 | 7,273 | 2,000 |
| 2026-10-09 | 10,154 | 2,000 |
| 2026-10-10 | 7,562 | 2,000 |
| 2026-10-11 | 6,255 | 2,000 |
| 2026-10-12 | 3,875 | 2,000 |
| 2026-10-13 | 8,299 | 2,000 |
| 2026-10-14 | 7,443 | 2,000 |
| 2026-10-15 | 8,325 | 2,000 |
| 2026-10-16 | 15,505 | 2,000 |
| 2026-10-17 | 9,960 | 2,000 |
| 2026-10-18 | 8,691 | 2,000 |
| 2026-10-19 | 5,171 | 2,000 |
| 2026-10-20 | 9,651 | 2,000 |
| 2026-10-21 | 9,588 | 2,000 |
| 2026-10-22 | 10,470 | 2,000 |
| 2026-10-23 | 12,507 | 2,000 |
| 2026-10-24 | 15,181 | 2,000 |
| 2026-10-25 | 11,165 | 2,000 |
| 2026-10-26 | 9,536 | 2,000 |
| 2026-10-27 | 35,458 | 2,000 |
| 2026-10-28 | 11,432 | 2,000 |

> Hinweis: Der Rueckstau von 2,811,562 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-29 | 9,326 |
| 2026-09-30 | 10,138 |
| 2026-10-01 | 16,558 |
| 2026-10-02 | 7,697 |
| 2026-10-03 | 7,309 |
| 2026-10-04 | 12,582 |
| 2026-10-05 | 17,500 |
| 2026-10-06 | 16,074 |
| 2026-10-07 | 15,012 |
| 2026-10-08 | 61,251 |
| 2026-10-09 | 222,060 |
| 2026-10-10 | 53,333 |
| 2026-10-11 | 16,031 |
| 2026-10-12 | 66,557 |
| 2026-10-13 | 1,583,597 |
| 2026-10-14 | 32,915 |
| 2026-10-15 | 41,324 |
| 2026-10-16 | 51,276 |
| 2026-10-17 | 24,257 |
| 2026-10-18 | 14,254 |
| 2026-10-19 | 22,291 |
| 2026-10-20 | 11,131 |
| 2026-10-21 | 11,096 |
| 2026-10-22 | 30,718 |
| 2026-10-23 | 50,402 |
| 2026-10-24 | 41,702 |
| 2026-10-25 | 21,599 |
| 2026-10-26 | 20,322 |
| 2026-10-27 | 20,674 |
| 2026-10-28 | 15,791 |
| 2026-10-29 | 9,672 |
| 2026-10-30 | 61,917 |
| 2026-10-31 | 88,213 |
| 2026-11-01 | 27,865 |
| 2026-11-02 | 28,817 |
| 2026-11-03 | 29,793 |
| 2026-11-04 | 29,636 |
| 2026-11-05 | 25,286 |
| 2026-11-06 | 36,395 |
| 2026-11-07 | 24,481 |
| 2026-11-08 | 26,135 |
| 2026-11-09 | 25,575 |
| 2026-11-10 | 32,755 |
| 2026-11-11 | 22,394 |
| 2026-11-12 | 20,523 |
| 2026-11-13 | 19,673 |
| 2026-11-14 | 22,997 |
| 2026-11-15 | 17,481 |
| 2026-11-16 | 17,989 |
| 2026-11-17 | 15,274 |
| 2026-11-18 | 19,530 |
| 2026-11-19 | 174,006 |
| 2026-11-20 | 26,211 |
| 2026-11-21 | 61,499 |
| 2026-11-22 | 30,496 |
| 2026-11-23 | 25,730 |
| 2026-11-24 | 26,525 |
| 2026-11-25 | 27,610 |
| 2026-11-26 | 28,710 |
| 2026-11-27 | 27,892 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
