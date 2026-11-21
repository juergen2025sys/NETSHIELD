# Seen-DB Expiry Forecast

Lauf: 2026-11-21 07:55 CET (Europe/Berlin)
Gesamt: 11,228,674 IPs in seen_db.json (7,936,714 aktiv/180-Tage-Pfad, 3,291,960 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 274,544 |
| 8-14 Tage | 185,400 |
| 15-30 Tage | 428,271 |
| 31-60 Tage | 693,827 |
| 61-90 Tage | 1,459,190 |
| 91-180 Tage | 4,895,482 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 3,071,736 |
| 0-3 Tage | 39,931 |
| 4-7 Tage | 18,299 |
| 8-14 Tage | 46,687 |
| 15-30 Tage | 115,307 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-21 | 9,900 |
| 2026-11-22 | 9,961 |
| 2026-11-23 | 9,990 |
| 2026-11-24 | 10,080 |
| 2026-11-25 | 7,595 |
| 2026-11-26 | 3,329 |
| 2026-11-27 | 3,848 |
| 2026-11-28 | 3,527 |
| 2026-11-29 | 8,118 |
| 2026-11-30 | 7,097 |
| 2026-12-01 | 8,062 |
| 2026-12-02 | 4,562 |
| 2026-12-03 | 7,708 |
| 2026-12-04 | 5,748 |
| 2026-12-05 | 5,392 |
| 2026-12-06 | 3,085 |
| 2026-12-07 | 7,782 |
| 2026-12-08 | 4,448 |
| 2026-12-09 | 9,011 |
| 2026-12-10 | 5,999 |
| 2026-12-11 | 4,654 |
| 2026-12-12 | 2,585 |
| 2026-12-13 | 2,999 |
| 2026-12-14 | 7,613 |
| 2026-12-15 | 8,106 |
| 2026-12-16 | 7,511 |
| 2026-12-17 | 7,649 |
| 2026-12-18 | 9,390 |
| 2026-12-19 | 1,646 |
| 2026-12-20 | 10,112 |
| 2026-12-21 | 9,061 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **3,071,736** IPs. Brutto faellig in den naechsten 30 Tagen: **206,568**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,216,304**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-21 | 9,900 | 2,000 |
| 2026-11-22 | 9,961 | 2,000 |
| 2026-11-23 | 9,990 | 2,000 |
| 2026-11-24 | 10,080 | 2,000 |
| 2026-11-25 | 7,595 | 2,000 |
| 2026-11-26 | 3,329 | 2,000 |
| 2026-11-27 | 3,848 | 2,000 |
| 2026-11-28 | 3,527 | 2,000 |
| 2026-11-29 | 8,118 | 2,000 |
| 2026-11-30 | 7,097 | 2,000 |
| 2026-12-01 | 8,062 | 2,000 |
| 2026-12-02 | 4,562 | 2,000 |
| 2026-12-03 | 7,708 | 2,000 |
| 2026-12-04 | 5,748 | 2,000 |
| 2026-12-05 | 5,392 | 2,000 |
| 2026-12-06 | 3,085 | 2,000 |
| 2026-12-07 | 7,782 | 2,000 |
| 2026-12-08 | 4,448 | 2,000 |
| 2026-12-09 | 9,011 | 2,000 |
| 2026-12-10 | 5,999 | 2,000 |
| 2026-12-11 | 4,654 | 2,000 |
| 2026-12-12 | 2,585 | 2,000 |
| 2026-12-13 | 2,999 | 2,000 |
| 2026-12-14 | 7,613 | 2,000 |
| 2026-12-15 | 8,106 | 2,000 |
| 2026-12-16 | 7,511 | 2,000 |
| 2026-12-17 | 7,649 | 2,000 |
| 2026-12-18 | 9,390 | 2,000 |
| 2026-12-19 | 1,646 | 2,000 |
| 2026-12-20 | 10,112 | 2,000 |
| 2026-12-21 | 9,061 | 2,000 |

> Hinweis: Der Rueckstau von 3,216,304 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-22 | 30,224 |
| 2026-11-23 | 25,502 |
| 2026-11-24 | 26,309 |
| 2026-11-25 | 27,329 |
| 2026-11-26 | 28,515 |
| 2026-11-27 | 27,706 |
| 2026-11-28 | 108,959 |
| 2026-11-29 | 28,043 |
| 2026-11-30 | 25,397 |
| 2026-12-01 | 26,421 |
| 2026-12-02 | 26,049 |
| 2026-12-03 | 25,863 |
| 2026-12-04 | 27,795 |
| 2026-12-05 | 25,832 |
| 2026-12-06 | 29,988 |
| 2026-12-07 | 23,633 |
| 2026-12-08 | 39,220 |
| 2026-12-09 | 54,636 |
| 2026-12-10 | 24,975 |
| 2026-12-11 | 27,628 |
| 2026-12-12 | 24,265 |
| 2026-12-13 | 23,724 |
| 2026-12-14 | 23,334 |
| 2026-12-15 | 26,118 |
| 2026-12-16 | 16,525 |
| 2026-12-17 | 24,902 |
| 2026-12-18 | 22,401 |
| 2026-12-19 | 25,468 |
| 2026-12-20 | 14,238 |
| 2026-12-21 | 27,216 |
| 2026-12-22 | 23,983 |
| 2026-12-23 | 21,024 |
| 2026-12-24 | 20,323 |
| 2026-12-25 | 21,542 |
| 2026-12-26 | 17,735 |
| 2026-12-27 | 24,556 |
| 2026-12-28 | 21,664 |
| 2026-12-29 | 22,498 |
| 2026-12-30 | 26,439 |
| 2026-12-31 | 20,099 |
| 2027-01-01 | 18,452 |
| 2027-01-02 | 26,048 |
| 2027-01-03 | 14,768 |
| 2027-01-04 | 28,391 |
| 2027-01-05 | 22,320 |
| 2027-01-06 | 35,499 |
| 2027-01-07 | 23,904 |
| 2027-01-08 | 25,802 |
| 2027-01-09 | 21,563 |
| 2027-01-10 | 24,669 |
| 2027-01-11 | 24,078 |
| 2027-01-12 | 22,955 |
| 2027-01-13 | 23,243 |
| 2027-01-14 | 21,854 |
| 2027-01-15 | 22,685 |
| 2027-01-16 | 26,742 |
| 2027-01-17 | 20,518 |
| 2027-01-18 | 24,831 |
| 2027-01-19 | 22,478 |
| 2027-01-20 | 23,164 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
