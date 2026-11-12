# Seen-DB Expiry Forecast

Lauf: 2026-11-12 04:46 CET (Europe/Berlin)
Gesamt: 11,256,860 IPs in seen_db.json (8,030,564 aktiv/180-Tage-Pfad, 3,226,296 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 285,263 |
| 8-14 Tage | 225,074 |
| 15-30 Tage | 546,949 |
| 31-60 Tage | 690,137 |
| 61-90 Tage | 1,180,451 |
| 91-180 Tage | 5,102,690 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,995,065 |
| 0-3 Tage | 37,037 |
| 4-7 Tage | 40,272 |
| 8-14 Tage | 61,788 |
| 15-30 Tage | 92,134 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-12 | 7,968 |
| 2026-11-13 | 3,301 |
| 2026-11-14 | 11,528 |
| 2026-11-15 | 14,240 |
| 2026-11-16 | 18,787 |
| 2026-11-17 | 9,270 |
| 2026-11-18 | 3,461 |
| 2026-11-19 | 8,754 |
| 2026-11-20 | 10,832 |
| 2026-11-21 | 9,926 |
| 2026-11-22 | 9,975 |
| 2026-11-23 | 10,016 |
| 2026-11-24 | 10,095 |
| 2026-11-25 | 7,606 |
| 2026-11-26 | 3,338 |
| 2026-11-27 | 3,861 |
| 2026-11-28 | 3,540 |
| 2026-11-29 | 8,128 |
| 2026-11-30 | 7,111 |
| 2026-12-01 | 8,081 |
| 2026-12-02 | 4,582 |
| 2026-12-03 | 7,724 |
| 2026-12-04 | 5,764 |
| 2026-12-05 | 5,415 |
| 2026-12-06 | 3,102 |
| 2026-12-07 | 7,807 |
| 2026-12-08 | 4,502 |
| 2026-12-09 | 9,049 |
| 2026-12-10 | 6,054 |
| 2026-12-11 | 4,721 |
| 2026-12-12 | 2,628 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,995,065** IPs. Brutto faellig in den naechsten 30 Tagen: **231,166**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,164,231**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-12 | 7,968 | 2,000 |
| 2026-11-13 | 3,301 | 2,000 |
| 2026-11-14 | 11,528 | 2,000 |
| 2026-11-15 | 14,240 | 2,000 |
| 2026-11-16 | 18,787 | 2,000 |
| 2026-11-17 | 9,270 | 2,000 |
| 2026-11-18 | 3,461 | 2,000 |
| 2026-11-19 | 8,754 | 2,000 |
| 2026-11-20 | 10,832 | 2,000 |
| 2026-11-21 | 9,926 | 2,000 |
| 2026-11-22 | 9,975 | 2,000 |
| 2026-11-23 | 10,016 | 2,000 |
| 2026-11-24 | 10,095 | 2,000 |
| 2026-11-25 | 7,606 | 2,000 |
| 2026-11-26 | 3,338 | 2,000 |
| 2026-11-27 | 3,861 | 2,000 |
| 2026-11-28 | 3,540 | 2,000 |
| 2026-11-29 | 8,128 | 2,000 |
| 2026-11-30 | 7,111 | 2,000 |
| 2026-12-01 | 8,081 | 2,000 |
| 2026-12-02 | 4,582 | 2,000 |
| 2026-12-03 | 7,724 | 2,000 |
| 2026-12-04 | 5,764 | 2,000 |
| 2026-12-05 | 5,415 | 2,000 |
| 2026-12-06 | 3,102 | 2,000 |
| 2026-12-07 | 7,807 | 2,000 |
| 2026-12-08 | 4,502 | 2,000 |
| 2026-12-09 | 9,049 | 2,000 |
| 2026-12-10 | 6,054 | 2,000 |
| 2026-12-11 | 4,721 | 2,000 |
| 2026-12-12 | 2,628 | 2,000 |

> Hinweis: Der Rueckstau von 3,164,231 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-13 | 19,523 |
| 2026-11-14 | 22,804 |
| 2026-11-15 | 17,370 |
| 2026-11-16 | 17,839 |
| 2026-11-17 | 15,152 |
| 2026-11-18 | 19,392 |
| 2026-11-19 | 173,183 |
| 2026-11-20 | 25,993 |
| 2026-11-21 | 61,098 |
| 2026-11-22 | 30,249 |
| 2026-11-23 | 25,520 |
| 2026-11-24 | 26,323 |
| 2026-11-25 | 27,358 |
| 2026-11-26 | 28,533 |
| 2026-11-27 | 27,728 |
| 2026-11-28 | 109,005 |
| 2026-11-29 | 28,065 |
| 2026-11-30 | 25,428 |
| 2026-12-01 | 26,442 |
| 2026-12-02 | 26,082 |
| 2026-12-03 | 25,887 |
| 2026-12-04 | 27,815 |
| 2026-12-05 | 25,858 |
| 2026-12-06 | 30,016 |
| 2026-12-07 | 23,654 |
| 2026-12-08 | 39,245 |
| 2026-12-09 | 54,760 |
| 2026-12-10 | 25,003 |
| 2026-12-11 | 27,670 |
| 2026-12-12 | 24,291 |
| 2026-12-13 | 23,756 |
| 2026-12-14 | 23,366 |
| 2026-12-15 | 26,141 |
| 2026-12-16 | 16,561 |
| 2026-12-17 | 24,931 |
| 2026-12-18 | 22,424 |
| 2026-12-19 | 25,495 |
| 2026-12-20 | 14,259 |
| 2026-12-21 | 27,244 |
| 2026-12-22 | 24,015 |
| 2026-12-23 | 21,060 |
| 2026-12-24 | 20,346 |
| 2026-12-25 | 21,562 |
| 2026-12-26 | 17,767 |
| 2026-12-27 | 24,590 |
| 2026-12-28 | 21,691 |
| 2026-12-29 | 22,526 |
| 2026-12-30 | 26,471 |
| 2026-12-31 | 20,118 |
| 2027-01-01 | 18,472 |
| 2027-01-02 | 26,078 |
| 2027-01-03 | 14,795 |
| 2027-01-04 | 28,417 |
| 2027-01-05 | 22,352 |
| 2027-01-06 | 35,542 |
| 2027-01-07 | 23,934 |
| 2027-01-08 | 25,834 |
| 2027-01-09 | 21,590 |
| 2027-01-10 | 24,693 |
| 2027-01-11 | 24,107 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
