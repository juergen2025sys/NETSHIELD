# Seen-DB Expiry Forecast

Lauf: 2026-11-17 20:45 CET (Europe/Berlin)
Gesamt: 11,385,629 IPs in seen_db.json (8,122,469 aktiv/180-Tage-Pfad, 3,263,160 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 361,621 |
| 8-14 Tage | 272,440 |
| 15-30 Tage | 444,688 |
| 31-60 Tage | 692,504 |
| 61-90 Tage | 1,405,793 |
| 91-180 Tage | 4,945,423 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 3,044,869 |
| 0-3 Tage | 32,277 |
| 4-7 Tage | 39,962 |
| 8-14 Tage | 41,610 |
| 15-30 Tage | 104,442 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-17 | 9,255 |
| 2026-11-18 | 3,455 |
| 2026-11-19 | 8,746 |
| 2026-11-20 | 10,821 |
| 2026-11-21 | 9,913 |
| 2026-11-22 | 9,967 |
| 2026-11-23 | 9,996 |
| 2026-11-24 | 10,086 |
| 2026-11-25 | 7,602 |
| 2026-11-26 | 3,333 |
| 2026-11-27 | 3,852 |
| 2026-11-28 | 3,531 |
| 2026-11-29 | 8,121 |
| 2026-11-30 | 7,102 |
| 2026-12-01 | 8,069 |
| 2026-12-02 | 4,572 |
| 2026-12-03 | 7,714 |
| 2026-12-04 | 5,754 |
| 2026-12-05 | 5,397 |
| 2026-12-06 | 3,088 |
| 2026-12-07 | 7,787 |
| 2026-12-08 | 4,463 |
| 2026-12-09 | 9,015 |
| 2026-12-10 | 6,005 |
| 2026-12-11 | 4,662 |
| 2026-12-12 | 2,595 |
| 2026-12-13 | 3,010 |
| 2026-12-14 | 7,653 |
| 2026-12-15 | 8,144 |
| 2026-12-16 | 7,873 |
| 2026-12-17 | 7,959 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **3,044,869** IPs. Brutto faellig in den naechsten 30 Tagen: **209,540**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,192,409**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-17 | 9,255 | 2,000 |
| 2026-11-18 | 3,455 | 2,000 |
| 2026-11-19 | 8,746 | 2,000 |
| 2026-11-20 | 10,821 | 2,000 |
| 2026-11-21 | 9,913 | 2,000 |
| 2026-11-22 | 9,967 | 2,000 |
| 2026-11-23 | 9,996 | 2,000 |
| 2026-11-24 | 10,086 | 2,000 |
| 2026-11-25 | 7,602 | 2,000 |
| 2026-11-26 | 3,333 | 2,000 |
| 2026-11-27 | 3,852 | 2,000 |
| 2026-11-28 | 3,531 | 2,000 |
| 2026-11-29 | 8,121 | 2,000 |
| 2026-11-30 | 7,102 | 2,000 |
| 2026-12-01 | 8,069 | 2,000 |
| 2026-12-02 | 4,572 | 2,000 |
| 2026-12-03 | 7,714 | 2,000 |
| 2026-12-04 | 5,754 | 2,000 |
| 2026-12-05 | 5,397 | 2,000 |
| 2026-12-06 | 3,088 | 2,000 |
| 2026-12-07 | 7,787 | 2,000 |
| 2026-12-08 | 4,463 | 2,000 |
| 2026-12-09 | 9,015 | 2,000 |
| 2026-12-10 | 6,005 | 2,000 |
| 2026-12-11 | 4,662 | 2,000 |
| 2026-12-12 | 2,595 | 2,000 |
| 2026-12-13 | 3,010 | 2,000 |
| 2026-12-14 | 7,653 | 2,000 |
| 2026-12-15 | 8,144 | 2,000 |
| 2026-12-16 | 7,873 | 2,000 |
| 2026-12-17 | 7,959 | 2,000 |

> Hinweis: Der Rueckstau von 3,192,409 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-18 | 19,382 |
| 2026-11-19 | 173,121 |
| 2026-11-20 | 25,984 |
| 2026-11-21 | 61,077 |
| 2026-11-22 | 30,233 |
| 2026-11-23 | 25,511 |
| 2026-11-24 | 26,313 |
| 2026-11-25 | 27,344 |
| 2026-11-26 | 28,520 |
| 2026-11-27 | 27,712 |
| 2026-11-28 | 108,978 |
| 2026-11-29 | 28,054 |
| 2026-11-30 | 25,402 |
| 2026-12-01 | 26,430 |
| 2026-12-02 | 26,061 |
| 2026-12-03 | 25,872 |
| 2026-12-04 | 27,797 |
| 2026-12-05 | 25,843 |
| 2026-12-06 | 29,997 |
| 2026-12-07 | 23,641 |
| 2026-12-08 | 39,227 |
| 2026-12-09 | 54,683 |
| 2026-12-10 | 24,984 |
| 2026-12-11 | 27,641 |
| 2026-12-12 | 24,277 |
| 2026-12-13 | 23,736 |
| 2026-12-14 | 23,355 |
| 2026-12-15 | 26,126 |
| 2026-12-16 | 16,540 |
| 2026-12-17 | 24,908 |
| 2026-12-18 | 22,410 |
| 2026-12-19 | 25,477 |
| 2026-12-20 | 14,250 |
| 2026-12-21 | 27,226 |
| 2026-12-22 | 24,000 |
| 2026-12-23 | 21,036 |
| 2026-12-24 | 20,331 |
| 2026-12-25 | 21,550 |
| 2026-12-26 | 17,747 |
| 2026-12-27 | 24,566 |
| 2026-12-28 | 21,676 |
| 2026-12-29 | 22,507 |
| 2026-12-30 | 26,454 |
| 2026-12-31 | 20,108 |
| 2027-01-01 | 18,458 |
| 2027-01-02 | 26,062 |
| 2027-01-03 | 14,780 |
| 2027-01-04 | 28,406 |
| 2027-01-05 | 22,337 |
| 2027-01-06 | 35,520 |
| 2027-01-07 | 23,913 |
| 2027-01-08 | 25,814 |
| 2027-01-09 | 21,573 |
| 2027-01-10 | 24,682 |
| 2027-01-11 | 24,087 |
| 2027-01-12 | 22,963 |
| 2027-01-13 | 23,255 |
| 2027-01-14 | 21,860 |
| 2027-01-15 | 22,694 |
| 2027-01-16 | 26,762 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
