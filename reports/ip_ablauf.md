# Seen-DB Expiry Forecast

Lauf: 2026-11-28 03:56 CET (Europe/Berlin)
Gesamt: 11,298,412 IPs in seen_db.json (7,801,966 aktiv/180-Tage-Pfad, 3,496,446 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 185,303 |
| 8-14 Tage | 224,201 |
| 15-30 Tage | 354,428 |
| 31-60 Tage | 819,535 |
| 61-90 Tage | 1,493,894 |
| 91-180 Tage | 4,724,605 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 3,117,145 |
| 0-3 Tage | 26,770 |
| 4-7 Tage | 23,370 |
| 8-14 Tage | 37,481 |
| 15-30 Tage | 291,680 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-28 | 3,521 |
| 2026-11-29 | 8,108 |
| 2026-11-30 | 7,086 |
| 2026-12-01 | 8,055 |
| 2026-12-02 | 4,553 |
| 2026-12-03 | 7,699 |
| 2026-12-04 | 5,740 |
| 2026-12-05 | 5,378 |
| 2026-12-06 | 3,079 |
| 2026-12-07 | 7,769 |
| 2026-12-08 | 4,438 |
| 2026-12-09 | 8,995 |
| 2026-12-10 | 5,993 |
| 2026-12-11 | 4,634 |
| 2026-12-12 | 2,573 |
| 2026-12-13 | 2,988 |
| 2026-12-14 | 7,583 |
| 2026-12-15 | 8,074 |
| 2026-12-16 | 7,479 |
| 2026-12-17 | 7,617 |
| 2026-12-18 | 9,337 |
| 2026-12-19 | 1,625 |
| 2026-12-20 | 10,060 |
| 2026-12-21 | 8,992 |
| 2026-12-22 | 31,682 |
| 2026-12-23 | 14,712 |
| 2026-12-24 | 19,438 |
| 2026-12-25 | 15,207 |
| 2026-12-26 | 18,555 |
| 2026-12-27 | 28,717 |
| 2026-12-28 | 81,403 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **3,117,145** IPs. Brutto faellig in den naechsten 30 Tagen: **361,090**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,416,235**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-28 | 3,521 | 2,000 |
| 2026-11-29 | 8,108 | 2,000 |
| 2026-11-30 | 7,086 | 2,000 |
| 2026-12-01 | 8,055 | 2,000 |
| 2026-12-02 | 4,553 | 2,000 |
| 2026-12-03 | 7,699 | 2,000 |
| 2026-12-04 | 5,740 | 2,000 |
| 2026-12-05 | 5,378 | 2,000 |
| 2026-12-06 | 3,079 | 2,000 |
| 2026-12-07 | 7,769 | 2,000 |
| 2026-12-08 | 4,438 | 2,000 |
| 2026-12-09 | 8,995 | 2,000 |
| 2026-12-10 | 5,993 | 2,000 |
| 2026-12-11 | 4,634 | 2,000 |
| 2026-12-12 | 2,573 | 2,000 |
| 2026-12-13 | 2,988 | 2,000 |
| 2026-12-14 | 7,583 | 2,000 |
| 2026-12-15 | 8,074 | 2,000 |
| 2026-12-16 | 7,479 | 2,000 |
| 2026-12-17 | 7,617 | 2,000 |
| 2026-12-18 | 9,337 | 2,000 |
| 2026-12-19 | 1,625 | 2,000 |
| 2026-12-20 | 10,060 | 2,000 |
| 2026-12-21 | 8,992 | 2,000 |
| 2026-12-22 | 31,682 | 2,000 |
| 2026-12-23 | 14,712 | 2,000 |
| 2026-12-24 | 19,438 | 2,000 |
| 2026-12-25 | 15,207 | 2,000 |
| 2026-12-26 | 18,555 | 2,000 |
| 2026-12-27 | 28,717 | 2,000 |
| 2026-12-28 | 81,403 | 2,000 |

> Hinweis: Der Rueckstau von 3,416,235 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-29 | 28,029 |
| 2026-11-30 | 25,386 |
| 2026-12-01 | 26,411 |
| 2026-12-02 | 26,028 |
| 2026-12-03 | 25,844 |
| 2026-12-04 | 27,782 |
| 2026-12-05 | 25,823 |
| 2026-12-06 | 29,970 |
| 2026-12-07 | 23,625 |
| 2026-12-08 | 39,209 |
| 2026-12-09 | 54,570 |
| 2026-12-10 | 24,956 |
| 2026-12-11 | 27,618 |
| 2026-12-12 | 24,253 |
| 2026-12-13 | 23,696 |
| 2026-12-14 | 23,323 |
| 2026-12-15 | 26,097 |
| 2026-12-16 | 16,510 |
| 2026-12-17 | 24,867 |
| 2026-12-18 | 22,389 |
| 2026-12-19 | 25,442 |
| 2026-12-20 | 14,220 |
| 2026-12-21 | 27,198 |
| 2026-12-22 | 23,962 |
| 2026-12-23 | 21,003 |
| 2026-12-24 | 20,309 |
| 2026-12-25 | 21,525 |
| 2026-12-26 | 17,711 |
| 2026-12-27 | 24,534 |
| 2026-12-28 | 21,642 |
| 2026-12-29 | 22,482 |
| 2026-12-30 | 26,421 |
| 2026-12-31 | 20,081 |
| 2027-01-01 | 18,432 |
| 2027-01-02 | 26,025 |
| 2027-01-03 | 14,747 |
| 2027-01-04 | 28,375 |
| 2027-01-05 | 22,295 |
| 2027-01-06 | 35,475 |
| 2027-01-07 | 23,880 |
| 2027-01-08 | 25,774 |
| 2027-01-09 | 21,530 |
| 2027-01-10 | 24,653 |
| 2027-01-11 | 24,060 |
| 2027-01-12 | 22,937 |
| 2027-01-13 | 23,225 |
| 2027-01-14 | 21,834 |
| 2027-01-15 | 22,670 |
| 2027-01-16 | 26,722 |
| 2027-01-17 | 20,498 |
| 2027-01-18 | 24,819 |
| 2027-01-19 | 22,467 |
| 2027-01-20 | 23,147 |
| 2027-01-21 | 45,448 |
| 2027-01-22 | 28,517 |
| 2027-01-23 | 25,810 |
| 2027-01-24 | 25,111 |
| 2027-01-25 | 41,847 |
| 2027-01-26 | 63,386 |
| 2027-01-27 | 46,867 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
