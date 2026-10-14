# Seen-DB Expiry Forecast

Lauf: 2026-10-14 03:07 CEST (Europe/Berlin)
Gesamt: 10,769,450 IPs in seen_db.json (7,737,326 aktiv/180-Tage-Pfad, 3,032,124 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 174,791 |
| 8-14 Tage | 200,066 |
| 15-30 Tage | 506,969 |
| 31-60 Tage | 1,064,520 |
| 61-90 Tage | 692,352 |
| 91-180 Tage | 5,098,628 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,656,963 |
| 0-3 Tage | 40,947 |
| 4-7 Tage | 32,718 |
| 8-14 Tage | 104,530 |
| 15-30 Tage | 196,966 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-14 | 7,381 |
| 2026-10-15 | 8,250 |
| 2026-10-16 | 15,406 |
| 2026-10-17 | 9,910 |
| 2026-10-18 | 8,613 |
| 2026-10-19 | 5,113 |
| 2026-10-20 | 9,516 |
| 2026-10-21 | 9,476 |
| 2026-10-22 | 10,340 |
| 2026-10-23 | 12,340 |
| 2026-10-24 | 15,007 |
| 2026-10-25 | 11,061 |
| 2026-10-26 | 9,411 |
| 2026-10-27 | 35,121 |
| 2026-10-28 | 11,250 |
| 2026-10-29 | 9,811 |
| 2026-10-30 | 20,063 |
| 2026-10-31 | 16,925 |
| 2026-11-01 | 15,324 |
| 2026-11-02 | 11,883 |
| 2026-11-03 | 16,595 |
| 2026-11-04 | 10,050 |
| 2026-11-05 | 7,234 |
| 2026-11-06 | 12,060 |
| 2026-11-07 | 13,362 |
| 2026-11-08 | 6,271 |
| 2026-11-09 | 11,501 |
| 2026-11-10 | 23,875 |
| 2026-11-11 | 9,928 |
| 2026-11-12 | 8,093 |
| 2026-11-13 | 3,406 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,656,963** IPs. Brutto faellig in den naechsten 30 Tagen: **374,576**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **2,969,539**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-14 | 7,381 | 2,000 |
| 2026-10-15 | 8,250 | 2,000 |
| 2026-10-16 | 15,406 | 2,000 |
| 2026-10-17 | 9,910 | 2,000 |
| 2026-10-18 | 8,613 | 2,000 |
| 2026-10-19 | 5,113 | 2,000 |
| 2026-10-20 | 9,516 | 2,000 |
| 2026-10-21 | 9,476 | 2,000 |
| 2026-10-22 | 10,340 | 2,000 |
| 2026-10-23 | 12,340 | 2,000 |
| 2026-10-24 | 15,007 | 2,000 |
| 2026-10-25 | 11,061 | 2,000 |
| 2026-10-26 | 9,411 | 2,000 |
| 2026-10-27 | 35,121 | 2,000 |
| 2026-10-28 | 11,250 | 2,000 |
| 2026-10-29 | 9,811 | 2,000 |
| 2026-10-30 | 20,063 | 2,000 |
| 2026-10-31 | 16,925 | 2,000 |
| 2026-11-01 | 15,324 | 2,000 |
| 2026-11-02 | 11,883 | 2,000 |
| 2026-11-03 | 16,595 | 2,000 |
| 2026-11-04 | 10,050 | 2,000 |
| 2026-11-05 | 7,234 | 2,000 |
| 2026-11-06 | 12,060 | 2,000 |
| 2026-11-07 | 13,362 | 2,000 |
| 2026-11-08 | 6,271 | 2,000 |
| 2026-11-09 | 11,501 | 2,000 |
| 2026-11-10 | 23,875 | 2,000 |
| 2026-11-11 | 9,928 | 2,000 |
| 2026-11-12 | 8,093 | 2,000 |
| 2026-11-13 | 3,406 | 2,000 |

> Hinweis: Der Rueckstau von 2,969,539 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-15 | 41,269 |
| 2026-10-16 | 51,132 |
| 2026-10-17 | 24,157 |
| 2026-10-18 | 14,162 |
| 2026-10-19 | 21,989 |
| 2026-10-20 | 11,059 |
| 2026-10-21 | 11,023 |
| 2026-10-22 | 30,481 |
| 2026-10-23 | 50,220 |
| 2026-10-24 | 41,579 |
| 2026-10-25 | 21,487 |
| 2026-10-26 | 20,201 |
| 2026-10-27 | 20,473 |
| 2026-10-28 | 15,625 |
| 2026-10-29 | 9,568 |
| 2026-10-30 | 61,604 |
| 2026-10-31 | 88,052 |
| 2026-11-01 | 27,741 |
| 2026-11-02 | 28,686 |
| 2026-11-03 | 29,630 |
| 2026-11-04 | 29,489 |
| 2026-11-05 | 25,166 |
| 2026-11-06 | 36,223 |
| 2026-11-07 | 24,366 |
| 2026-11-08 | 26,026 |
| 2026-11-09 | 25,459 |
| 2026-11-10 | 32,619 |
| 2026-11-11 | 22,287 |
| 2026-11-12 | 20,451 |
| 2026-11-13 | 19,602 |
| 2026-11-14 | 22,902 |
| 2026-11-15 | 17,416 |
| 2026-11-16 | 17,916 |
| 2026-11-17 | 15,199 |
| 2026-11-18 | 19,452 |
| 2026-11-19 | 173,470 |
| 2026-11-20 | 26,090 |
| 2026-11-21 | 61,257 |
| 2026-11-22 | 30,348 |
| 2026-11-23 | 25,606 |
| 2026-11-24 | 26,416 |
| 2026-11-25 | 27,467 |
| 2026-11-26 | 28,609 |
| 2026-11-27 | 27,793 |
| 2026-11-28 | 109,146 |
| 2026-11-29 | 28,131 |
| 2026-11-30 | 25,492 |
| 2026-12-01 | 26,510 |
| 2026-12-02 | 26,161 |
| 2026-12-03 | 25,974 |
| 2026-12-04 | 27,881 |
| 2026-12-05 | 25,926 |
| 2026-12-06 | 30,108 |
| 2026-12-07 | 23,718 |
| 2026-12-08 | 39,347 |
| 2026-12-09 | 55,125 |
| 2026-12-10 | 25,079 |
| 2026-12-11 | 27,750 |
| 2026-12-12 | 24,384 |
| 2026-12-13 | 23,847 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
