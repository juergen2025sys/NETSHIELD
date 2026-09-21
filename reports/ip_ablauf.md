# Seen-DB Expiry Forecast

Lauf: 2026-09-21 16:30 CEST (Europe/Berlin)
Gesamt: 11,467,540 IPs in seen_db.json (8,687,377 aktiv/180-Tage-Pfad, 2,780,163 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 101,169 |
| 8-14 Tage | 81,370 |
| 15-30 Tage | 2,246,358 |
| 31-60 Tage | 1,006,015 |
| 61-90 Tage | 932,369 |
| 91-180 Tage | 4,320,096 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 579,718 |
| 0-3 Tage | 32,626 |
| 4-7 Tage | 636,348 |
| 8-14 Tage | 1,387,490 |
| 15-30 Tage | 143,981 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-21 | 4,997 |
| 2026-09-22 | 11,132 |
| 2026-09-23 | 5,111 |
| 2026-09-24 | 11,386 |
| 2026-09-25 | 5,461 |
| 2026-09-26 | 623,827 |
| 2026-09-27 | 6,286 |
| 2026-09-28 | 774 |
| 2026-09-30 | 59,691 |
| 2026-10-01 | 7,653 |
| 2026-10-02 | 1,307,343 |
| 2026-10-03 | 2,973 |
| 2026-10-04 | 6,925 |
| 2026-10-05 | 2,905 |
| 2026-10-06 | 8,057 |
| 2026-10-07 | 7,971 |
| 2026-10-08 | 7,303 |
| 2026-10-09 | 10,201 |
| 2026-10-10 | 7,597 |
| 2026-10-11 | 6,284 |
| 2026-10-12 | 3,897 |
| 2026-10-13 | 8,348 |
| 2026-10-14 | 7,490 |
| 2026-10-15 | 8,373 |
| 2026-10-16 | 15,566 |
| 2026-10-17 | 10,000 |
| 2026-10-18 | 8,768 |
| 2026-10-19 | 5,207 |
| 2026-10-20 | 9,764 |
| 2026-10-21 | 9,745 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **579,718** IPs. Brutto faellig in den naechsten 30 Tagen: **2,191,035**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,710,753**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-21 | 4,997 | 2,000 |
| 2026-09-22 | 11,132 | 2,000 |
| 2026-09-23 | 5,111 | 2,000 |
| 2026-09-24 | 11,386 | 2,000 |
| 2026-09-25 | 5,461 | 2,000 |
| 2026-09-26 | 623,827 | 2,000 |
| 2026-09-27 | 6,286 | 2,000 |
| 2026-09-28 | 774 | 2,000 |
| 2026-09-30 | 59,691 | 2,000 |
| 2026-10-01 | 7,653 | 2,000 |
| 2026-10-02 | 1,307,343 | 2,000 |
| 2026-10-03 | 2,973 | 2,000 |
| 2026-10-04 | 6,925 | 2,000 |
| 2026-10-05 | 2,905 | 2,000 |
| 2026-10-06 | 8,057 | 2,000 |
| 2026-10-07 | 7,971 | 2,000 |
| 2026-10-08 | 7,303 | 2,000 |
| 2026-10-09 | 10,201 | 2,000 |
| 2026-10-10 | 7,597 | 2,000 |
| 2026-10-11 | 6,284 | 2,000 |
| 2026-10-12 | 3,897 | 2,000 |
| 2026-10-13 | 8,348 | 2,000 |
| 2026-10-14 | 7,490 | 2,000 |
| 2026-10-15 | 8,373 | 2,000 |
| 2026-10-16 | 15,566 | 2,000 |
| 2026-10-17 | 10,000 | 2,000 |
| 2026-10-18 | 8,768 | 2,000 |
| 2026-10-19 | 5,207 | 2,000 |
| 2026-10-20 | 9,764 | 2,000 |
| 2026-10-21 | 9,745 | 2,000 |

> Hinweis: Der Rueckstau von 2,710,753 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,433 |
| 2026-09-23 | 13,055 |
| 2026-09-24 | 16,662 |
| 2026-09-25 | 20,927 |
| 2026-09-26 | 17,448 |
| 2026-09-27 | 15,037 |
| 2026-09-28 | 11,607 |
| 2026-09-29 | 9,359 |
| 2026-09-30 | 10,176 |
| 2026-10-01 | 16,604 |
| 2026-10-02 | 7,722 |
| 2026-10-03 | 7,333 |
| 2026-10-04 | 12,629 |
| 2026-10-05 | 17,547 |
| 2026-10-06 | 16,135 |
| 2026-10-07 | 15,069 |
| 2026-10-08 | 61,434 |
| 2026-10-09 | 223,117 |
| 2026-10-10 | 53,386 |
| 2026-10-11 | 16,061 |
| 2026-10-12 | 66,591 |
| 2026-10-13 | 1,585,686 |
| 2026-10-14 | 32,923 |
| 2026-10-15 | 41,350 |
| 2026-10-16 | 51,325 |
| 2026-10-17 | 24,319 |
| 2026-10-18 | 14,289 |
| 2026-10-19 | 22,386 |
| 2026-10-20 | 11,156 |
| 2026-10-21 | 11,131 |
| 2026-10-22 | 30,780 |
| 2026-10-23 | 50,455 |
| 2026-10-24 | 41,770 |
| 2026-10-25 | 21,648 |
| 2026-10-26 | 20,371 |
| 2026-10-27 | 20,735 |
| 2026-10-28 | 15,832 |
| 2026-10-29 | 9,706 |
| 2026-10-30 | 62,035 |
| 2026-10-31 | 88,274 |
| 2026-11-01 | 27,913 |
| 2026-11-02 | 28,879 |
| 2026-11-03 | 29,895 |
| 2026-11-04 | 29,714 |
| 2026-11-05 | 25,342 |
| 2026-11-06 | 36,757 |
| 2026-11-07 | 24,541 |
| 2026-11-08 | 26,191 |
| 2026-11-09 | 25,625 |
| 2026-11-10 | 32,819 |
| 2026-11-11 | 22,443 |
| 2026-11-12 | 20,555 |
| 2026-11-13 | 19,705 |
| 2026-11-14 | 23,037 |
| 2026-11-15 | 17,514 |
| 2026-11-16 | 18,027 |
| 2026-11-17 | 15,287 |
| 2026-11-18 | 19,560 |
| 2026-11-19 | 174,326 |
| 2026-11-20 | 26,279 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
