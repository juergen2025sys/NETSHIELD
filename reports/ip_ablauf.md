# Seen-DB Expiry Forecast

Lauf: 2026-11-14 22:21 CET (Europe/Berlin)
Gesamt: 11,347,269 IPs in seen_db.json (8,104,841 aktiv/180-Tage-Pfad, 3,242,428 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 329,963 |
| 8-14 Tage | 274,655 |
| 15-30 Tage | 457,175 |
| 31-60 Tage | 689,015 |
| 61-90 Tage | 1,362,667 |
| 91-180 Tage | 4,991,366 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 3,004,394 |
| 0-3 Tage | 53,789 |
| 4-7 Tage | 32,958 |
| 8-14 Tage | 48,399 |
| 15-30 Tage | 102,888 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-14 | 11,523 |
| 2026-11-15 | 14,229 |
| 2026-11-16 | 18,778 |
| 2026-11-17 | 9,259 |
| 2026-11-18 | 3,461 |
| 2026-11-19 | 8,749 |
| 2026-11-20 | 10,826 |
| 2026-11-21 | 9,922 |
| 2026-11-22 | 9,971 |
| 2026-11-23 | 10,007 |
| 2026-11-24 | 10,090 |
| 2026-11-25 | 7,605 |
| 2026-11-26 | 3,337 |
| 2026-11-27 | 3,855 |
| 2026-11-28 | 3,534 |
| 2026-11-29 | 8,122 |
| 2026-11-30 | 7,105 |
| 2026-12-01 | 8,074 |
| 2026-12-02 | 4,575 |
| 2026-12-03 | 7,719 |
| 2026-12-04 | 5,756 |
| 2026-12-05 | 5,405 |
| 2026-12-06 | 3,097 |
| 2026-12-07 | 7,794 |
| 2026-12-08 | 4,475 |
| 2026-12-09 | 9,023 |
| 2026-12-10 | 6,026 |
| 2026-12-11 | 4,682 |
| 2026-12-12 | 2,606 |
| 2026-12-13 | 3,039 |
| 2026-12-14 | 7,708 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **3,004,394** IPs. Brutto faellig in den naechsten 30 Tagen: **230,352**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,172,746**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-14 | 11,523 | 2,000 |
| 2026-11-15 | 14,229 | 2,000 |
| 2026-11-16 | 18,778 | 2,000 |
| 2026-11-17 | 9,259 | 2,000 |
| 2026-11-18 | 3,461 | 2,000 |
| 2026-11-19 | 8,749 | 2,000 |
| 2026-11-20 | 10,826 | 2,000 |
| 2026-11-21 | 9,922 | 2,000 |
| 2026-11-22 | 9,971 | 2,000 |
| 2026-11-23 | 10,007 | 2,000 |
| 2026-11-24 | 10,090 | 2,000 |
| 2026-11-25 | 7,605 | 2,000 |
| 2026-11-26 | 3,337 | 2,000 |
| 2026-11-27 | 3,855 | 2,000 |
| 2026-11-28 | 3,534 | 2,000 |
| 2026-11-29 | 8,122 | 2,000 |
| 2026-11-30 | 7,105 | 2,000 |
| 2026-12-01 | 8,074 | 2,000 |
| 2026-12-02 | 4,575 | 2,000 |
| 2026-12-03 | 7,719 | 2,000 |
| 2026-12-04 | 5,756 | 2,000 |
| 2026-12-05 | 5,405 | 2,000 |
| 2026-12-06 | 3,097 | 2,000 |
| 2026-12-07 | 7,794 | 2,000 |
| 2026-12-08 | 4,475 | 2,000 |
| 2026-12-09 | 9,023 | 2,000 |
| 2026-12-10 | 6,026 | 2,000 |
| 2026-12-11 | 4,682 | 2,000 |
| 2026-12-12 | 2,606 | 2,000 |
| 2026-12-13 | 3,039 | 2,000 |
| 2026-12-14 | 7,708 | 2,000 |

> Hinweis: Der Rueckstau von 3,172,746 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-15 | 17,365 |
| 2026-11-16 | 17,836 |
| 2026-11-17 | 15,146 |
| 2026-11-18 | 19,388 |
| 2026-11-19 | 173,154 |
| 2026-11-20 | 25,988 |
| 2026-11-21 | 61,086 |
| 2026-11-22 | 30,241 |
| 2026-11-23 | 25,516 |
| 2026-11-24 | 26,317 |
| 2026-11-25 | 27,350 |
| 2026-11-26 | 28,527 |
| 2026-11-27 | 27,714 |
| 2026-11-28 | 108,990 |
| 2026-11-29 | 28,059 |
| 2026-11-30 | 25,415 |
| 2026-12-01 | 26,439 |
| 2026-12-02 | 26,066 |
| 2026-12-03 | 25,879 |
| 2026-12-04 | 27,806 |
| 2026-12-05 | 25,853 |
| 2026-12-06 | 30,009 |
| 2026-12-07 | 23,649 |
| 2026-12-08 | 39,233 |
| 2026-12-09 | 54,719 |
| 2026-12-10 | 24,993 |
| 2026-12-11 | 27,662 |
| 2026-12-12 | 24,288 |
| 2026-12-13 | 23,744 |
| 2026-12-14 | 23,361 |
| 2026-12-15 | 26,135 |
| 2026-12-16 | 16,554 |
| 2026-12-17 | 24,920 |
| 2026-12-18 | 22,415 |
| 2026-12-19 | 25,486 |
| 2026-12-20 | 14,254 |
| 2026-12-21 | 27,235 |
| 2026-12-22 | 24,004 |
| 2026-12-23 | 21,042 |
| 2026-12-24 | 20,341 |
| 2026-12-25 | 21,556 |
| 2026-12-26 | 17,759 |
| 2026-12-27 | 24,579 |
| 2026-12-28 | 21,682 |
| 2026-12-29 | 22,516 |
| 2026-12-30 | 26,466 |
| 2026-12-31 | 20,113 |
| 2027-01-01 | 18,467 |
| 2027-01-02 | 26,066 |
| 2027-01-03 | 14,787 |
| 2027-01-04 | 28,413 |
| 2027-01-05 | 22,346 |
| 2027-01-06 | 35,532 |
| 2027-01-07 | 23,924 |
| 2027-01-08 | 25,823 |
| 2027-01-09 | 21,581 |
| 2027-01-10 | 24,688 |
| 2027-01-11 | 24,097 |
| 2027-01-12 | 22,974 |
| 2027-01-13 | 23,260 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
