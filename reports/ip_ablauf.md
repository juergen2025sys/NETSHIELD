# Seen-DB Expiry Forecast

Lauf: 2026-09-23 01:46 CEST (Europe/Berlin)
Gesamt: 11,533,264 IPs in seen_db.json (8,739,911 aktiv/180-Tage-Pfad, 2,793,353 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 104,010 |
| 8-14 Tage | 88,099 |
| 15-30 Tage | 2,260,227 |
| 31-60 Tage | 1,036,475 |
| 61-90 Tage | 897,979 |
| 91-180 Tage | 4,353,121 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 584,198 |
| 0-3 Tage | 33,065 |
| 4-7 Tage | 630,833 |
| 8-14 Tage | 1,395,280 |
| 15-30 Tage | 149,977 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-22 | 11,123 |
| 2026-09-23 | 5,108 |
| 2026-09-24 | 11,382 |
| 2026-09-25 | 5,452 |
| 2026-09-26 | 623,780 |
| 2026-09-27 | 6,279 |
| 2026-09-28 | 774 |
| 2026-09-30 | 59,673 |
| 2026-10-01 | 7,649 |
| 2026-10-02 | 1,307,111 |
| 2026-10-03 | 2,971 |
| 2026-10-04 | 6,923 |
| 2026-10-05 | 2,904 |
| 2026-10-06 | 8,049 |
| 2026-10-07 | 7,961 |
| 2026-10-08 | 7,298 |
| 2026-10-09 | 10,187 |
| 2026-10-10 | 7,589 |
| 2026-10-11 | 6,279 |
| 2026-10-12 | 3,890 |
| 2026-10-13 | 8,340 |
| 2026-10-14 | 7,485 |
| 2026-10-15 | 8,361 |
| 2026-10-16 | 15,550 |
| 2026-10-17 | 9,990 |
| 2026-10-18 | 8,748 |
| 2026-10-19 | 5,199 |
| 2026-10-20 | 9,724 |
| 2026-10-21 | 9,680 |
| 2026-10-22 | 10,666 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **584,198** IPs. Brutto faellig in den naechsten 30 Tagen: **2,196,125**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,720,323**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-22 | 11,123 | 2,000 |
| 2026-09-23 | 5,108 | 2,000 |
| 2026-09-24 | 11,382 | 2,000 |
| 2026-09-25 | 5,452 | 2,000 |
| 2026-09-26 | 623,780 | 2,000 |
| 2026-09-27 | 6,279 | 2,000 |
| 2026-09-28 | 774 | 2,000 |
| 2026-09-30 | 59,673 | 2,000 |
| 2026-10-01 | 7,649 | 2,000 |
| 2026-10-02 | 1,307,111 | 2,000 |
| 2026-10-03 | 2,971 | 2,000 |
| 2026-10-04 | 6,923 | 2,000 |
| 2026-10-05 | 2,904 | 2,000 |
| 2026-10-06 | 8,049 | 2,000 |
| 2026-10-07 | 7,961 | 2,000 |
| 2026-10-08 | 7,298 | 2,000 |
| 2026-10-09 | 10,187 | 2,000 |
| 2026-10-10 | 7,589 | 2,000 |
| 2026-10-11 | 6,279 | 2,000 |
| 2026-10-12 | 3,890 | 2,000 |
| 2026-10-13 | 8,340 | 2,000 |
| 2026-10-14 | 7,485 | 2,000 |
| 2026-10-15 | 8,361 | 2,000 |
| 2026-10-16 | 15,550 | 2,000 |
| 2026-10-17 | 9,990 | 2,000 |
| 2026-10-18 | 8,748 | 2,000 |
| 2026-10-19 | 5,199 | 2,000 |
| 2026-10-20 | 9,724 | 2,000 |
| 2026-10-21 | 9,680 | 2,000 |
| 2026-10-22 | 10,666 | 2,000 |

> Hinweis: Der Rueckstau von 2,720,323 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-23 | 13,041 |
| 2026-09-24 | 16,641 |
| 2026-09-25 | 20,915 |
| 2026-09-26 | 17,435 |
| 2026-09-27 | 15,024 |
| 2026-09-28 | 11,603 |
| 2026-09-29 | 9,351 |
| 2026-09-30 | 10,169 |
| 2026-10-01 | 16,599 |
| 2026-10-02 | 7,717 |
| 2026-10-03 | 7,326 |
| 2026-10-04 | 12,622 |
| 2026-10-05 | 17,540 |
| 2026-10-06 | 16,126 |
| 2026-10-07 | 15,055 |
| 2026-10-08 | 61,393 |
| 2026-10-09 | 222,873 |
| 2026-10-10 | 53,378 |
| 2026-10-11 | 16,052 |
| 2026-10-12 | 66,583 |
| 2026-10-13 | 1,585,331 |
| 2026-10-14 | 32,921 |
| 2026-10-15 | 41,342 |
| 2026-10-16 | 51,315 |
| 2026-10-17 | 24,306 |
| 2026-10-18 | 14,278 |
| 2026-10-19 | 22,366 |
| 2026-10-20 | 11,146 |
| 2026-10-21 | 11,125 |
| 2026-10-22 | 30,763 |
| 2026-10-23 | 50,443 |
| 2026-10-24 | 41,754 |
| 2026-10-25 | 21,640 |
| 2026-10-26 | 20,363 |
| 2026-10-27 | 20,716 |
| 2026-10-28 | 15,824 |
| 2026-10-29 | 9,696 |
| 2026-10-30 | 62,004 |
| 2026-10-31 | 88,267 |
| 2026-11-01 | 27,900 |
| 2026-11-02 | 28,866 |
| 2026-11-03 | 29,880 |
| 2026-11-04 | 29,693 |
| 2026-11-05 | 25,332 |
| 2026-11-06 | 36,744 |
| 2026-11-07 | 24,524 |
| 2026-11-08 | 26,183 |
| 2026-11-09 | 25,610 |
| 2026-11-10 | 32,805 |
| 2026-11-11 | 22,435 |
| 2026-11-12 | 20,550 |
| 2026-11-13 | 19,697 |
| 2026-11-14 | 23,027 |
| 2026-11-15 | 17,505 |
| 2026-11-16 | 18,024 |
| 2026-11-17 | 15,281 |
| 2026-11-18 | 19,550 |
| 2026-11-19 | 174,280 |
| 2026-11-20 | 26,269 |
| 2026-11-21 | 61,613 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
