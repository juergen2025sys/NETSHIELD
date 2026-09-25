# Seen-DB Expiry Forecast

Lauf: 2026-09-25 12:07 CEST (Europe/Berlin)
Gesamt: 11,669,463 IPs in seen_db.json (8,844,351 aktiv/180-Tage-Pfad, 2,825,112 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 87,797 |
| 8-14 Tage | 352,347 |
| 15-30 Tage | 2,073,547 |
| 31-60 Tage | 1,004,492 |
| 61-90 Tage | 880,589 |
| 91-180 Tage | 4,445,579 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 611,206 |
| 0-3 Tage | 636,154 |
| 4-7 Tage | 1,373,944 |
| 8-14 Tage | 46,194 |
| 15-30 Tage | 157,614 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-25 | 5,440 |
| 2026-09-26 | 623,683 |
| 2026-09-27 | 6,261 |
| 2026-09-28 | 770 |
| 2026-09-30 | 59,632 |
| 2026-10-01 | 7,632 |
| 2026-10-02 | 1,306,680 |
| 2026-10-03 | 2,964 |
| 2026-10-04 | 6,910 |
| 2026-10-05 | 2,898 |
| 2026-10-06 | 8,021 |
| 2026-10-07 | 7,945 |
| 2026-10-08 | 7,284 |
| 2026-10-09 | 10,172 |
| 2026-10-10 | 7,575 |
| 2026-10-11 | 6,267 |
| 2026-10-12 | 3,879 |
| 2026-10-13 | 8,320 |
| 2026-10-14 | 7,461 |
| 2026-10-15 | 8,341 |
| 2026-10-16 | 15,523 |
| 2026-10-17 | 9,972 |
| 2026-10-18 | 8,712 |
| 2026-10-19 | 5,183 |
| 2026-10-20 | 9,685 |
| 2026-10-21 | 9,626 |
| 2026-10-22 | 10,514 |
| 2026-10-23 | 12,574 |
| 2026-10-24 | 15,287 |
| 2026-10-25 | 11,446 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **611,206** IPs. Brutto faellig in den naechsten 30 Tagen: **2,206,657**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,757,863**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-25 | 5,440 | 2,000 |
| 2026-09-26 | 623,683 | 2,000 |
| 2026-09-27 | 6,261 | 2,000 |
| 2026-09-28 | 770 | 2,000 |
| 2026-09-30 | 59,632 | 2,000 |
| 2026-10-01 | 7,632 | 2,000 |
| 2026-10-02 | 1,306,680 | 2,000 |
| 2026-10-03 | 2,964 | 2,000 |
| 2026-10-04 | 6,910 | 2,000 |
| 2026-10-05 | 2,898 | 2,000 |
| 2026-10-06 | 8,021 | 2,000 |
| 2026-10-07 | 7,945 | 2,000 |
| 2026-10-08 | 7,284 | 2,000 |
| 2026-10-09 | 10,172 | 2,000 |
| 2026-10-10 | 7,575 | 2,000 |
| 2026-10-11 | 6,267 | 2,000 |
| 2026-10-12 | 3,879 | 2,000 |
| 2026-10-13 | 8,320 | 2,000 |
| 2026-10-14 | 7,461 | 2,000 |
| 2026-10-15 | 8,341 | 2,000 |
| 2026-10-16 | 15,523 | 2,000 |
| 2026-10-17 | 9,972 | 2,000 |
| 2026-10-18 | 8,712 | 2,000 |
| 2026-10-19 | 5,183 | 2,000 |
| 2026-10-20 | 9,685 | 2,000 |
| 2026-10-21 | 9,626 | 2,000 |
| 2026-10-22 | 10,514 | 2,000 |
| 2026-10-23 | 12,574 | 2,000 |
| 2026-10-24 | 15,287 | 2,000 |
| 2026-10-25 | 11,446 | 2,000 |

> Hinweis: Der Rueckstau von 2,757,863 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-26 | 17,416 |
| 2026-09-27 | 15,007 |
| 2026-09-28 | 11,592 |
| 2026-09-29 | 9,340 |
| 2026-09-30 | 10,155 |
| 2026-10-01 | 16,575 |
| 2026-10-02 | 7,712 |
| 2026-10-03 | 7,320 |
| 2026-10-04 | 12,598 |
| 2026-10-05 | 17,517 |
| 2026-10-06 | 16,100 |
| 2026-10-07 | 15,028 |
| 2026-10-08 | 61,334 |
| 2026-10-09 | 222,450 |
| 2026-10-10 | 53,355 |
| 2026-10-11 | 16,042 |
| 2026-10-12 | 66,571 |
| 2026-10-13 | 1,584,395 |
| 2026-10-14 | 32,919 |
| 2026-10-15 | 41,336 |
| 2026-10-16 | 51,292 |
| 2026-10-17 | 24,281 |
| 2026-10-18 | 14,268 |
| 2026-10-19 | 22,332 |
| 2026-10-20 | 11,139 |
| 2026-10-21 | 11,113 |
| 2026-10-22 | 30,740 |
| 2026-10-23 | 50,419 |
| 2026-10-24 | 41,723 |
| 2026-10-25 | 21,622 |
| 2026-10-26 | 20,345 |
| 2026-10-27 | 20,701 |
| 2026-10-28 | 15,806 |
| 2026-10-29 | 9,687 |
| 2026-10-30 | 61,962 |
| 2026-10-31 | 88,245 |
| 2026-11-01 | 27,879 |
| 2026-11-02 | 28,844 |
| 2026-11-03 | 29,841 |
| 2026-11-04 | 29,661 |
| 2026-11-05 | 25,308 |
| 2026-11-06 | 36,441 |
| 2026-11-07 | 24,500 |
| 2026-11-08 | 26,161 |
| 2026-11-09 | 25,593 |
| 2026-11-10 | 32,786 |
| 2026-11-11 | 22,421 |
| 2026-11-12 | 20,538 |
| 2026-11-13 | 19,691 |
| 2026-11-14 | 23,010 |
| 2026-11-15 | 17,491 |
| 2026-11-16 | 18,004 |
| 2026-11-17 | 15,275 |
| 2026-11-18 | 19,540 |
| 2026-11-19 | 174,130 |
| 2026-11-20 | 26,237 |
| 2026-11-21 | 61,561 |
| 2026-11-22 | 30,525 |
| 2026-11-23 | 25,761 |
| 2026-11-24 | 26,548 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
