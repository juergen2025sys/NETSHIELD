# Seen-DB Expiry Forecast

Lauf: 2026-09-27 00:39 CEST (Europe/Berlin)
Gesamt: 11,771,598 IPs in seen_db.json (8,910,590 aktiv/180-Tage-Pfad, 2,861,008 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 77,652 |
| 8-14 Tage | 398,138 |
| 15-30 Tage | 2,040,034 |
| 31-60 Tage | 1,011,359 |
| 61-90 Tage | 874,378 |
| 91-180 Tage | 4,509,029 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 616,139 |
| 0-3 Tage | 630,643 |
| 4-7 Tage | 1,376,623 |
| 8-14 Tage | 50,735 |
| 15-30 Tage | 186,868 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-26 | 623,617 |
| 2026-09-27 | 6,256 |
| 2026-09-28 | 770 |
| 2026-09-30 | 59,610 |
| 2026-10-01 | 7,624 |
| 2026-10-02 | 1,306,427 |
| 2026-10-03 | 2,962 |
| 2026-10-04 | 6,906 |
| 2026-10-05 | 2,894 |
| 2026-10-06 | 7,992 |
| 2026-10-07 | 7,932 |
| 2026-10-08 | 7,278 |
| 2026-10-09 | 10,163 |
| 2026-10-10 | 7,570 |
| 2026-10-11 | 6,260 |
| 2026-10-12 | 3,876 |
| 2026-10-13 | 8,310 |
| 2026-10-14 | 7,453 |
| 2026-10-15 | 8,333 |
| 2026-10-16 | 15,513 |
| 2026-10-17 | 9,966 |
| 2026-10-18 | 8,700 |
| 2026-10-19 | 5,177 |
| 2026-10-20 | 9,669 |
| 2026-10-21 | 9,609 |
| 2026-10-22 | 10,492 |
| 2026-10-23 | 12,533 |
| 2026-10-24 | 15,225 |
| 2026-10-25 | 11,183 |
| 2026-10-26 | 9,588 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **616,139** IPs. Brutto faellig in den naechsten 30 Tagen: **2,209,888**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,766,027**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-26 | 623,617 | 2,000 |
| 2026-09-27 | 6,256 | 2,000 |
| 2026-09-28 | 770 | 2,000 |
| 2026-09-30 | 59,610 | 2,000 |
| 2026-10-01 | 7,624 | 2,000 |
| 2026-10-02 | 1,306,427 | 2,000 |
| 2026-10-03 | 2,962 | 2,000 |
| 2026-10-04 | 6,906 | 2,000 |
| 2026-10-05 | 2,894 | 2,000 |
| 2026-10-06 | 7,992 | 2,000 |
| 2026-10-07 | 7,932 | 2,000 |
| 2026-10-08 | 7,278 | 2,000 |
| 2026-10-09 | 10,163 | 2,000 |
| 2026-10-10 | 7,570 | 2,000 |
| 2026-10-11 | 6,260 | 2,000 |
| 2026-10-12 | 3,876 | 2,000 |
| 2026-10-13 | 8,310 | 2,000 |
| 2026-10-14 | 7,453 | 2,000 |
| 2026-10-15 | 8,333 | 2,000 |
| 2026-10-16 | 15,513 | 2,000 |
| 2026-10-17 | 9,966 | 2,000 |
| 2026-10-18 | 8,700 | 2,000 |
| 2026-10-19 | 5,177 | 2,000 |
| 2026-10-20 | 9,669 | 2,000 |
| 2026-10-21 | 9,609 | 2,000 |
| 2026-10-22 | 10,492 | 2,000 |
| 2026-10-23 | 12,533 | 2,000 |
| 2026-10-24 | 15,225 | 2,000 |
| 2026-10-25 | 11,183 | 2,000 |
| 2026-10-26 | 9,588 | 2,000 |

> Hinweis: Der Rueckstau von 2,766,027 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-27 | 14,989 |
| 2026-09-28 | 11,589 |
| 2026-09-29 | 9,333 |
| 2026-09-30 | 10,146 |
| 2026-10-01 | 16,573 |
| 2026-10-02 | 7,707 |
| 2026-10-03 | 7,315 |
| 2026-10-04 | 12,591 |
| 2026-10-05 | 17,509 |
| 2026-10-06 | 16,093 |
| 2026-10-07 | 15,020 |
| 2026-10-08 | 61,305 |
| 2026-10-09 | 222,276 |
| 2026-10-10 | 53,344 |
| 2026-10-11 | 16,038 |
| 2026-10-12 | 66,566 |
| 2026-10-13 | 1,584,014 |
| 2026-10-14 | 32,918 |
| 2026-10-15 | 41,331 |
| 2026-10-16 | 51,285 |
| 2026-10-17 | 24,264 |
| 2026-10-18 | 14,261 |
| 2026-10-19 | 22,313 |
| 2026-10-20 | 11,136 |
| 2026-10-21 | 11,106 |
| 2026-10-22 | 30,731 |
| 2026-10-23 | 50,411 |
| 2026-10-24 | 41,713 |
| 2026-10-25 | 21,612 |
| 2026-10-26 | 20,335 |
| 2026-10-27 | 20,688 |
| 2026-10-28 | 15,800 |
| 2026-10-29 | 9,680 |
| 2026-10-30 | 61,938 |
| 2026-10-31 | 88,231 |
| 2026-11-01 | 27,871 |
| 2026-11-02 | 28,836 |
| 2026-11-03 | 29,812 |
| 2026-11-04 | 29,649 |
| 2026-11-05 | 25,299 |
| 2026-11-06 | 36,418 |
| 2026-11-07 | 24,491 |
| 2026-11-08 | 26,148 |
| 2026-11-09 | 25,585 |
| 2026-11-10 | 32,770 |
| 2026-11-11 | 22,409 |
| 2026-11-12 | 20,528 |
| 2026-11-13 | 19,687 |
| 2026-11-14 | 23,001 |
| 2026-11-15 | 17,488 |
| 2026-11-16 | 17,995 |
| 2026-11-17 | 15,275 |
| 2026-11-18 | 19,532 |
| 2026-11-19 | 174,063 |
| 2026-11-20 | 26,222 |
| 2026-11-21 | 61,528 |
| 2026-11-22 | 30,509 |
| 2026-11-23 | 25,747 |
| 2026-11-24 | 26,536 |
| 2026-11-25 | 27,623 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
