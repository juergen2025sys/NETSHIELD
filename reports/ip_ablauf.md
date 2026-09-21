# Seen-DB Expiry Forecast

Lauf: 2026-09-21 21:43 CEST (Europe/Berlin)
Gesamt: 11,475,071 IPs in seen_db.json (8,694,282 aktiv/180-Tage-Pfad, 2,780,789 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 101,165 |
| 8-14 Tage | 81,365 |
| 15-30 Tage | 2,246,287 |
| 31-60 Tage | 1,005,972 |
| 61-90 Tage | 932,335 |
| 91-180 Tage | 4,327,158 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 579,688 |
| 0-3 Tage | 32,624 |
| 4-7 Tage | 636,340 |
| 8-14 Tage | 1,387,473 |
| 15-30 Tage | 144,664 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-21 | 4,996 |
| 2026-09-22 | 11,132 |
| 2026-09-23 | 5,111 |
| 2026-09-24 | 11,385 |
| 2026-09-25 | 5,460 |
| 2026-09-26 | 623,823 |
| 2026-09-27 | 6,283 |
| 2026-09-28 | 774 |
| 2026-09-30 | 59,691 |
| 2026-10-01 | 7,652 |
| 2026-10-02 | 1,307,328 |
| 2026-10-03 | 2,972 |
| 2026-10-04 | 6,925 |
| 2026-10-05 | 2,905 |
| 2026-10-06 | 8,056 |
| 2026-10-07 | 7,969 |
| 2026-10-08 | 7,303 |
| 2026-10-09 | 10,200 |
| 2026-10-10 | 7,597 |
| 2026-10-11 | 6,284 |
| 2026-10-12 | 3,896 |
| 2026-10-13 | 8,347 |
| 2026-10-14 | 7,489 |
| 2026-10-15 | 8,373 |
| 2026-10-16 | 15,562 |
| 2026-10-17 | 9,999 |
| 2026-10-18 | 8,765 |
| 2026-10-19 | 5,206 |
| 2026-10-20 | 9,758 |
| 2026-10-21 | 9,737 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **579,688** IPs. Brutto faellig in den naechsten 30 Tagen: **2,190,978**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,710,666**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-21 | 4,996 | 2,000 |
| 2026-09-22 | 11,132 | 2,000 |
| 2026-09-23 | 5,111 | 2,000 |
| 2026-09-24 | 11,385 | 2,000 |
| 2026-09-25 | 5,460 | 2,000 |
| 2026-09-26 | 623,823 | 2,000 |
| 2026-09-27 | 6,283 | 2,000 |
| 2026-09-28 | 774 | 2,000 |
| 2026-09-30 | 59,691 | 2,000 |
| 2026-10-01 | 7,652 | 2,000 |
| 2026-10-02 | 1,307,328 | 2,000 |
| 2026-10-03 | 2,972 | 2,000 |
| 2026-10-04 | 6,925 | 2,000 |
| 2026-10-05 | 2,905 | 2,000 |
| 2026-10-06 | 8,056 | 2,000 |
| 2026-10-07 | 7,969 | 2,000 |
| 2026-10-08 | 7,303 | 2,000 |
| 2026-10-09 | 10,200 | 2,000 |
| 2026-10-10 | 7,597 | 2,000 |
| 2026-10-11 | 6,284 | 2,000 |
| 2026-10-12 | 3,896 | 2,000 |
| 2026-10-13 | 8,347 | 2,000 |
| 2026-10-14 | 7,489 | 2,000 |
| 2026-10-15 | 8,373 | 2,000 |
| 2026-10-16 | 15,562 | 2,000 |
| 2026-10-17 | 9,999 | 2,000 |
| 2026-10-18 | 8,765 | 2,000 |
| 2026-10-19 | 5,206 | 2,000 |
| 2026-10-20 | 9,758 | 2,000 |
| 2026-10-21 | 9,737 | 2,000 |

> Hinweis: Der Rueckstau von 2,710,666 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,432 |
| 2026-09-23 | 13,054 |
| 2026-09-24 | 16,662 |
| 2026-09-25 | 20,927 |
| 2026-09-26 | 17,447 |
| 2026-09-27 | 15,036 |
| 2026-09-28 | 11,607 |
| 2026-09-29 | 9,359 |
| 2026-09-30 | 10,175 |
| 2026-10-01 | 16,602 |
| 2026-10-02 | 7,721 |
| 2026-10-03 | 7,332 |
| 2026-10-04 | 12,629 |
| 2026-10-05 | 17,547 |
| 2026-10-06 | 16,135 |
| 2026-10-07 | 15,068 |
| 2026-10-08 | 61,430 |
| 2026-10-09 | 223,095 |
| 2026-10-10 | 53,385 |
| 2026-10-11 | 16,061 |
| 2026-10-12 | 66,591 |
| 2026-10-13 | 1,585,651 |
| 2026-10-14 | 32,923 |
| 2026-10-15 | 41,350 |
| 2026-10-16 | 51,323 |
| 2026-10-17 | 24,318 |
| 2026-10-18 | 14,289 |
| 2026-10-19 | 22,385 |
| 2026-10-20 | 11,154 |
| 2026-10-21 | 11,129 |
| 2026-10-22 | 30,780 |
| 2026-10-23 | 50,454 |
| 2026-10-24 | 41,768 |
| 2026-10-25 | 21,646 |
| 2026-10-26 | 20,371 |
| 2026-10-27 | 20,735 |
| 2026-10-28 | 15,831 |
| 2026-10-29 | 9,705 |
| 2026-10-30 | 62,028 |
| 2026-10-31 | 88,274 |
| 2026-11-01 | 27,911 |
| 2026-11-02 | 28,875 |
| 2026-11-03 | 29,892 |
| 2026-11-04 | 29,714 |
| 2026-11-05 | 25,341 |
| 2026-11-06 | 36,757 |
| 2026-11-07 | 24,539 |
| 2026-11-08 | 26,191 |
| 2026-11-09 | 25,623 |
| 2026-11-10 | 32,818 |
| 2026-11-11 | 22,443 |
| 2026-11-12 | 20,554 |
| 2026-11-13 | 19,704 |
| 2026-11-14 | 23,037 |
| 2026-11-15 | 17,513 |
| 2026-11-16 | 18,027 |
| 2026-11-17 | 15,287 |
| 2026-11-18 | 19,559 |
| 2026-11-19 | 174,317 |
| 2026-11-20 | 26,278 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
