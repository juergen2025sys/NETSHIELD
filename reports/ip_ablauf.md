# Seen-DB Expiry Forecast

Lauf: 2026-11-25 16:59 CET (Europe/Berlin)
Gesamt: 11,288,835 IPs in seen_db.json (7,919,218 aktiv/180-Tage-Pfad, 3,369,617 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 271,017 |
| 8-14 Tage | 226,882 |
| 15-30 Tage | 367,464 |
| 31-60 Tage | 731,570 |
| 61-90 Tage | 1,591,538 |
| 91-180 Tage | 4,730,747 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 3,106,646 |
| 0-3 Tage | 18,283 |
| 4-7 Tage | 27,814 |
| 8-14 Tage | 43,116 |
| 15-30 Tage | 173,758 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-25 | 7,589 |
| 2026-11-26 | 3,325 |
| 2026-11-27 | 3,846 |
| 2026-11-28 | 3,523 |
| 2026-11-29 | 8,110 |
| 2026-11-30 | 7,089 |
| 2026-12-01 | 8,057 |
| 2026-12-02 | 4,558 |
| 2026-12-03 | 7,704 |
| 2026-12-04 | 5,742 |
| 2026-12-05 | 5,381 |
| 2026-12-06 | 3,079 |
| 2026-12-07 | 7,771 |
| 2026-12-08 | 4,441 |
| 2026-12-09 | 8,998 |
| 2026-12-10 | 5,996 |
| 2026-12-11 | 4,637 |
| 2026-12-12 | 2,578 |
| 2026-12-13 | 2,992 |
| 2026-12-14 | 7,595 |
| 2026-12-15 | 8,080 |
| 2026-12-16 | 7,485 |
| 2026-12-17 | 7,626 |
| 2026-12-18 | 9,345 |
| 2026-12-19 | 1,631 |
| 2026-12-20 | 10,064 |
| 2026-12-21 | 9,005 |
| 2026-12-22 | 31,724 |
| 2026-12-23 | 14,734 |
| 2026-12-24 | 19,466 |
| 2026-12-25 | 15,256 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **3,106,646** IPs. Brutto faellig in den naechsten 30 Tagen: **247,427**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,292,073**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-25 | 7,589 | 2,000 |
| 2026-11-26 | 3,325 | 2,000 |
| 2026-11-27 | 3,846 | 2,000 |
| 2026-11-28 | 3,523 | 2,000 |
| 2026-11-29 | 8,110 | 2,000 |
| 2026-11-30 | 7,089 | 2,000 |
| 2026-12-01 | 8,057 | 2,000 |
| 2026-12-02 | 4,558 | 2,000 |
| 2026-12-03 | 7,704 | 2,000 |
| 2026-12-04 | 5,742 | 2,000 |
| 2026-12-05 | 5,381 | 2,000 |
| 2026-12-06 | 3,079 | 2,000 |
| 2026-12-07 | 7,771 | 2,000 |
| 2026-12-08 | 4,441 | 2,000 |
| 2026-12-09 | 8,998 | 2,000 |
| 2026-12-10 | 5,996 | 2,000 |
| 2026-12-11 | 4,637 | 2,000 |
| 2026-12-12 | 2,578 | 2,000 |
| 2026-12-13 | 2,992 | 2,000 |
| 2026-12-14 | 7,595 | 2,000 |
| 2026-12-15 | 8,080 | 2,000 |
| 2026-12-16 | 7,485 | 2,000 |
| 2026-12-17 | 7,626 | 2,000 |
| 2026-12-18 | 9,345 | 2,000 |
| 2026-12-19 | 1,631 | 2,000 |
| 2026-12-20 | 10,064 | 2,000 |
| 2026-12-21 | 9,005 | 2,000 |
| 2026-12-22 | 31,724 | 2,000 |
| 2026-12-23 | 14,734 | 2,000 |
| 2026-12-24 | 19,466 | 2,000 |
| 2026-12-25 | 15,256 | 2,000 |

> Hinweis: Der Rueckstau von 3,292,073 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-26 | 28,510 |
| 2026-11-27 | 27,696 |
| 2026-11-28 | 108,942 |
| 2026-11-29 | 28,032 |
| 2026-11-30 | 25,388 |
| 2026-12-01 | 26,413 |
| 2026-12-02 | 26,036 |
| 2026-12-03 | 25,855 |
| 2026-12-04 | 27,789 |
| 2026-12-05 | 25,827 |
| 2026-12-06 | 29,973 |
| 2026-12-07 | 23,628 |
| 2026-12-08 | 39,211 |
| 2026-12-09 | 54,599 |
| 2026-12-10 | 24,962 |
| 2026-12-11 | 27,621 |
| 2026-12-12 | 24,258 |
| 2026-12-13 | 23,703 |
| 2026-12-14 | 23,327 |
| 2026-12-15 | 26,104 |
| 2026-12-16 | 16,511 |
| 2026-12-17 | 24,875 |
| 2026-12-18 | 22,394 |
| 2026-12-19 | 25,456 |
| 2026-12-20 | 14,225 |
| 2026-12-21 | 27,203 |
| 2026-12-22 | 23,975 |
| 2026-12-23 | 21,007 |
| 2026-12-24 | 20,312 |
| 2026-12-25 | 21,531 |
| 2026-12-26 | 17,720 |
| 2026-12-27 | 24,545 |
| 2026-12-28 | 21,650 |
| 2026-12-29 | 22,489 |
| 2026-12-30 | 26,426 |
| 2026-12-31 | 20,085 |
| 2027-01-01 | 18,442 |
| 2027-01-02 | 26,032 |
| 2027-01-03 | 14,753 |
| 2027-01-04 | 28,381 |
| 2027-01-05 | 22,305 |
| 2027-01-06 | 35,481 |
| 2027-01-07 | 23,888 |
| 2027-01-08 | 25,786 |
| 2027-01-09 | 21,549 |
| 2027-01-10 | 24,661 |
| 2027-01-11 | 24,066 |
| 2027-01-12 | 22,941 |
| 2027-01-13 | 23,231 |
| 2027-01-14 | 21,841 |
| 2027-01-15 | 22,673 |
| 2027-01-16 | 26,730 |
| 2027-01-17 | 20,506 |
| 2027-01-18 | 24,822 |
| 2027-01-19 | 22,469 |
| 2027-01-20 | 23,152 |
| 2027-01-21 | 45,464 |
| 2027-01-22 | 28,532 |
| 2027-01-23 | 25,822 |
| 2027-01-24 | 25,128 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
