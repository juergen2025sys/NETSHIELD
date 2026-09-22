# Seen-DB Expiry Forecast

Lauf: 2026-09-22 03:47 CEST (Europe/Berlin)
Gesamt: 11,477,719 IPs in seen_db.json (8,697,163 aktiv/180-Tage-Pfad, 2,780,556 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 104,087 |
| 8-14 Tage | 88,138 |
| 15-30 Tage | 2,260,849 |
| 31-60 Tage | 1,036,782 |
| 61-90 Tage | 898,311 |
| 91-180 Tage | 4,308,996 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 582,662 |
| 0-3 Tage | 33,084 |
| 4-7 Tage | 630,879 |
| 8-14 Tage | 1,395,515 |
| 15-30 Tage | 138,416 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-22 | 11,130 |
| 2026-09-23 | 5,111 |
| 2026-09-24 | 11,384 |
| 2026-09-25 | 5,459 |
| 2026-09-26 | 623,822 |
| 2026-09-27 | 6,283 |
| 2026-09-28 | 774 |
| 2026-09-30 | 59,689 |
| 2026-10-01 | 7,651 |
| 2026-10-02 | 1,307,319 |
| 2026-10-03 | 2,972 |
| 2026-10-04 | 6,925 |
| 2026-10-05 | 2,904 |
| 2026-10-06 | 8,055 |
| 2026-10-07 | 7,967 |
| 2026-10-08 | 7,303 |
| 2026-10-09 | 10,198 |
| 2026-10-10 | 7,596 |
| 2026-10-11 | 6,283 |
| 2026-10-12 | 3,896 |
| 2026-10-13 | 8,345 |
| 2026-10-14 | 7,488 |
| 2026-10-15 | 8,369 |
| 2026-10-16 | 15,560 |
| 2026-10-17 | 9,997 |
| 2026-10-18 | 8,760 |
| 2026-10-19 | 5,205 |
| 2026-10-20 | 9,753 |
| 2026-10-21 | 9,733 |
| 2026-10-22 | 11,470 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **582,662** IPs. Brutto faellig in den naechsten 30 Tagen: **2,197,401**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,720,063**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-22 | 11,130 | 2,000 |
| 2026-09-23 | 5,111 | 2,000 |
| 2026-09-24 | 11,384 | 2,000 |
| 2026-09-25 | 5,459 | 2,000 |
| 2026-09-26 | 623,822 | 2,000 |
| 2026-09-27 | 6,283 | 2,000 |
| 2026-09-28 | 774 | 2,000 |
| 2026-09-30 | 59,689 | 2,000 |
| 2026-10-01 | 7,651 | 2,000 |
| 2026-10-02 | 1,307,319 | 2,000 |
| 2026-10-03 | 2,972 | 2,000 |
| 2026-10-04 | 6,925 | 2,000 |
| 2026-10-05 | 2,904 | 2,000 |
| 2026-10-06 | 8,055 | 2,000 |
| 2026-10-07 | 7,967 | 2,000 |
| 2026-10-08 | 7,303 | 2,000 |
| 2026-10-09 | 10,198 | 2,000 |
| 2026-10-10 | 7,596 | 2,000 |
| 2026-10-11 | 6,283 | 2,000 |
| 2026-10-12 | 3,896 | 2,000 |
| 2026-10-13 | 8,345 | 2,000 |
| 2026-10-14 | 7,488 | 2,000 |
| 2026-10-15 | 8,369 | 2,000 |
| 2026-10-16 | 15,560 | 2,000 |
| 2026-10-17 | 9,997 | 2,000 |
| 2026-10-18 | 8,760 | 2,000 |
| 2026-10-19 | 5,205 | 2,000 |
| 2026-10-20 | 9,753 | 2,000 |
| 2026-10-21 | 9,733 | 2,000 |
| 2026-10-22 | 11,470 | 2,000 |

> Hinweis: Der Rueckstau von 2,720,063 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-23 | 13,053 |
| 2026-09-24 | 16,661 |
| 2026-09-25 | 20,927 |
| 2026-09-26 | 17,445 |
| 2026-09-27 | 15,035 |
| 2026-09-28 | 11,607 |
| 2026-09-29 | 9,359 |
| 2026-09-30 | 10,175 |
| 2026-10-01 | 16,602 |
| 2026-10-02 | 7,721 |
| 2026-10-03 | 7,332 |
| 2026-10-04 | 12,628 |
| 2026-10-05 | 17,546 |
| 2026-10-06 | 16,134 |
| 2026-10-07 | 15,066 |
| 2026-10-08 | 61,429 |
| 2026-10-09 | 223,072 |
| 2026-10-10 | 53,384 |
| 2026-10-11 | 16,059 |
| 2026-10-12 | 66,590 |
| 2026-10-13 | 1,585,608 |
| 2026-10-14 | 32,923 |
| 2026-10-15 | 41,349 |
| 2026-10-16 | 51,322 |
| 2026-10-17 | 24,316 |
| 2026-10-18 | 14,288 |
| 2026-10-19 | 22,381 |
| 2026-10-20 | 11,154 |
| 2026-10-21 | 11,129 |
| 2026-10-22 | 30,779 |
| 2026-10-23 | 50,452 |
| 2026-10-24 | 41,767 |
| 2026-10-25 | 21,645 |
| 2026-10-26 | 20,370 |
| 2026-10-27 | 20,733 |
| 2026-10-28 | 15,831 |
| 2026-10-29 | 9,703 |
| 2026-10-30 | 62,026 |
| 2026-10-31 | 88,274 |
| 2026-11-01 | 27,910 |
| 2026-11-02 | 28,873 |
| 2026-11-03 | 29,889 |
| 2026-11-04 | 29,714 |
| 2026-11-05 | 25,341 |
| 2026-11-06 | 36,756 |
| 2026-11-07 | 24,538 |
| 2026-11-08 | 26,189 |
| 2026-11-09 | 25,622 |
| 2026-11-10 | 32,818 |
| 2026-11-11 | 22,443 |
| 2026-11-12 | 20,553 |
| 2026-11-13 | 19,702 |
| 2026-11-14 | 23,034 |
| 2026-11-15 | 17,512 |
| 2026-11-16 | 18,027 |
| 2026-11-17 | 15,287 |
| 2026-11-18 | 19,559 |
| 2026-11-19 | 174,314 |
| 2026-11-20 | 26,275 |
| 2026-11-21 | 61,625 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
