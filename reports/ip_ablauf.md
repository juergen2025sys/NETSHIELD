# Seen-DB Expiry Forecast

Lauf: 2026-09-26 18:41 CEST (Europe/Berlin)
Gesamt: 11,752,320 IPs in seen_db.json (8,896,213 aktiv/180-Tage-Pfad, 2,856,107 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 77,657 |
| 8-14 Tage | 398,170 |
| 15-30 Tage | 2,040,111 |
| 31-60 Tage | 1,011,420 |
| 61-90 Tage | 874,430 |
| 91-180 Tage | 4,494,425 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 616,355 |
| 0-3 Tage | 630,650 |
| 4-7 Tage | 1,376,660 |
| 8-14 Tage | 50,746 |
| 15-30 Tage | 181,696 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-26 | 623,624 |
| 2026-09-27 | 6,256 |
| 2026-09-28 | 770 |
| 2026-09-30 | 59,615 |
| 2026-10-01 | 7,627 |
| 2026-10-02 | 1,306,456 |
| 2026-10-03 | 2,962 |
| 2026-10-04 | 6,909 |
| 2026-10-05 | 2,895 |
| 2026-10-06 | 7,994 |
| 2026-10-07 | 7,933 |
| 2026-10-08 | 7,279 |
| 2026-10-09 | 10,165 |
| 2026-10-10 | 7,571 |
| 2026-10-11 | 6,264 |
| 2026-10-12 | 3,878 |
| 2026-10-13 | 8,311 |
| 2026-10-14 | 7,453 |
| 2026-10-15 | 8,333 |
| 2026-10-16 | 15,513 |
| 2026-10-17 | 9,966 |
| 2026-10-18 | 8,701 |
| 2026-10-19 | 5,177 |
| 2026-10-20 | 9,674 |
| 2026-10-21 | 9,617 |
| 2026-10-22 | 10,499 |
| 2026-10-23 | 12,540 |
| 2026-10-24 | 15,228 |
| 2026-10-25 | 11,191 |
| 2026-10-26 | 9,595 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **616,355** IPs. Brutto faellig in den naechsten 30 Tagen: **2,209,996**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,766,351**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-26 | 623,624 | 2,000 |
| 2026-09-27 | 6,256 | 2,000 |
| 2026-09-28 | 770 | 2,000 |
| 2026-09-30 | 59,615 | 2,000 |
| 2026-10-01 | 7,627 | 2,000 |
| 2026-10-02 | 1,306,456 | 2,000 |
| 2026-10-03 | 2,962 | 2,000 |
| 2026-10-04 | 6,909 | 2,000 |
| 2026-10-05 | 2,895 | 2,000 |
| 2026-10-06 | 7,994 | 2,000 |
| 2026-10-07 | 7,933 | 2,000 |
| 2026-10-08 | 7,279 | 2,000 |
| 2026-10-09 | 10,165 | 2,000 |
| 2026-10-10 | 7,571 | 2,000 |
| 2026-10-11 | 6,264 | 2,000 |
| 2026-10-12 | 3,878 | 2,000 |
| 2026-10-13 | 8,311 | 2,000 |
| 2026-10-14 | 7,453 | 2,000 |
| 2026-10-15 | 8,333 | 2,000 |
| 2026-10-16 | 15,513 | 2,000 |
| 2026-10-17 | 9,966 | 2,000 |
| 2026-10-18 | 8,701 | 2,000 |
| 2026-10-19 | 5,177 | 2,000 |
| 2026-10-20 | 9,674 | 2,000 |
| 2026-10-21 | 9,617 | 2,000 |
| 2026-10-22 | 10,499 | 2,000 |
| 2026-10-23 | 12,540 | 2,000 |
| 2026-10-24 | 15,228 | 2,000 |
| 2026-10-25 | 11,191 | 2,000 |
| 2026-10-26 | 9,595 | 2,000 |

> Hinweis: Der Rueckstau von 2,766,351 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-27 | 14,989 |
| 2026-09-28 | 11,590 |
| 2026-09-29 | 9,333 |
| 2026-09-30 | 10,147 |
| 2026-10-01 | 16,573 |
| 2026-10-02 | 7,708 |
| 2026-10-03 | 7,317 |
| 2026-10-04 | 12,591 |
| 2026-10-05 | 17,510 |
| 2026-10-06 | 16,094 |
| 2026-10-07 | 15,023 |
| 2026-10-08 | 61,309 |
| 2026-10-09 | 222,298 |
| 2026-10-10 | 53,345 |
| 2026-10-11 | 16,039 |
| 2026-10-12 | 66,566 |
| 2026-10-13 | 1,584,078 |
| 2026-10-14 | 32,918 |
| 2026-10-15 | 41,331 |
| 2026-10-16 | 51,286 |
| 2026-10-17 | 24,266 |
| 2026-10-18 | 14,261 |
| 2026-10-19 | 22,316 |
| 2026-10-20 | 11,137 |
| 2026-10-21 | 11,106 |
| 2026-10-22 | 30,732 |
| 2026-10-23 | 50,411 |
| 2026-10-24 | 41,714 |
| 2026-10-25 | 21,614 |
| 2026-10-26 | 20,336 |
| 2026-10-27 | 20,690 |
| 2026-10-28 | 15,800 |
| 2026-10-29 | 9,681 |
| 2026-10-30 | 61,943 |
| 2026-10-31 | 88,232 |
| 2026-11-01 | 27,872 |
| 2026-11-02 | 28,836 |
| 2026-11-03 | 29,815 |
| 2026-11-04 | 29,651 |
| 2026-11-05 | 25,301 |
| 2026-11-06 | 36,420 |
| 2026-11-07 | 24,492 |
| 2026-11-08 | 26,149 |
| 2026-11-09 | 25,586 |
| 2026-11-10 | 32,772 |
| 2026-11-11 | 22,412 |
| 2026-11-12 | 20,530 |
| 2026-11-13 | 19,687 |
| 2026-11-14 | 23,002 |
| 2026-11-15 | 17,488 |
| 2026-11-16 | 17,997 |
| 2026-11-17 | 15,275 |
| 2026-11-18 | 19,532 |
| 2026-11-19 | 174,076 |
| 2026-11-20 | 26,226 |
| 2026-11-21 | 61,531 |
| 2026-11-22 | 30,512 |
| 2026-11-23 | 25,752 |
| 2026-11-24 | 26,536 |
| 2026-11-25 | 27,624 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
