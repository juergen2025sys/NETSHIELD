# Seen-DB Expiry Forecast

Lauf: 2026-11-17 11:37 CET (Europe/Berlin)
Gesamt: 11,370,048 IPs in seen_db.json (8,109,016 aktiv/180-Tage-Pfad, 3,261,032 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 361,638 |
| 8-14 Tage | 272,447 |
| 15-30 Tage | 444,737 |
| 31-60 Tage | 692,561 |
| 61-90 Tage | 1,405,902 |
| 91-180 Tage | 4,931,731 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 3,045,000 |
| 0-3 Tage | 32,284 |
| 4-7 Tage | 39,971 |
| 8-14 Tage | 41,614 |
| 15-30 Tage | 102,163 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-17 | 9,257 |
| 2026-11-18 | 3,457 |
| 2026-11-19 | 8,748 |
| 2026-11-20 | 10,822 |
| 2026-11-21 | 9,915 |
| 2026-11-22 | 9,968 |
| 2026-11-23 | 10,000 |
| 2026-11-24 | 10,088 |
| 2026-11-25 | 7,602 |
| 2026-11-26 | 3,333 |
| 2026-11-27 | 3,854 |
| 2026-11-28 | 3,533 |
| 2026-11-29 | 8,121 |
| 2026-11-30 | 7,102 |
| 2026-12-01 | 8,069 |
| 2026-12-02 | 4,573 |
| 2026-12-03 | 7,714 |
| 2026-12-04 | 5,754 |
| 2026-12-05 | 5,398 |
| 2026-12-06 | 3,089 |
| 2026-12-07 | 7,788 |
| 2026-12-08 | 4,464 |
| 2026-12-09 | 9,017 |
| 2026-12-10 | 6,007 |
| 2026-12-11 | 4,667 |
| 2026-12-12 | 2,597 |
| 2026-12-13 | 3,014 |
| 2026-12-14 | 7,665 |
| 2026-12-15 | 8,149 |
| 2026-12-16 | 8,103 |
| 2026-12-17 | 8,059 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **3,045,000** IPs. Brutto faellig in den naechsten 30 Tagen: **209,927**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,192,927**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-17 | 9,257 | 2,000 |
| 2026-11-18 | 3,457 | 2,000 |
| 2026-11-19 | 8,748 | 2,000 |
| 2026-11-20 | 10,822 | 2,000 |
| 2026-11-21 | 9,915 | 2,000 |
| 2026-11-22 | 9,968 | 2,000 |
| 2026-11-23 | 10,000 | 2,000 |
| 2026-11-24 | 10,088 | 2,000 |
| 2026-11-25 | 7,602 | 2,000 |
| 2026-11-26 | 3,333 | 2,000 |
| 2026-11-27 | 3,854 | 2,000 |
| 2026-11-28 | 3,533 | 2,000 |
| 2026-11-29 | 8,121 | 2,000 |
| 2026-11-30 | 7,102 | 2,000 |
| 2026-12-01 | 8,069 | 2,000 |
| 2026-12-02 | 4,573 | 2,000 |
| 2026-12-03 | 7,714 | 2,000 |
| 2026-12-04 | 5,754 | 2,000 |
| 2026-12-05 | 5,398 | 2,000 |
| 2026-12-06 | 3,089 | 2,000 |
| 2026-12-07 | 7,788 | 2,000 |
| 2026-12-08 | 4,464 | 2,000 |
| 2026-12-09 | 9,017 | 2,000 |
| 2026-12-10 | 6,007 | 2,000 |
| 2026-12-11 | 4,667 | 2,000 |
| 2026-12-12 | 2,597 | 2,000 |
| 2026-12-13 | 3,014 | 2,000 |
| 2026-12-14 | 7,665 | 2,000 |
| 2026-12-15 | 8,149 | 2,000 |
| 2026-12-16 | 8,103 | 2,000 |
| 2026-12-17 | 8,059 | 2,000 |

> Hinweis: Der Rueckstau von 3,192,927 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-18 | 19,385 |
| 2026-11-19 | 173,128 |
| 2026-11-20 | 25,985 |
| 2026-11-21 | 61,079 |
| 2026-11-22 | 30,233 |
| 2026-11-23 | 25,513 |
| 2026-11-24 | 26,315 |
| 2026-11-25 | 27,344 |
| 2026-11-26 | 28,520 |
| 2026-11-27 | 27,713 |
| 2026-11-28 | 108,980 |
| 2026-11-29 | 28,055 |
| 2026-11-30 | 25,404 |
| 2026-12-01 | 26,431 |
| 2026-12-02 | 26,063 |
| 2026-12-03 | 25,873 |
| 2026-12-04 | 27,799 |
| 2026-12-05 | 25,844 |
| 2026-12-06 | 30,001 |
| 2026-12-07 | 23,643 |
| 2026-12-08 | 39,230 |
| 2026-12-09 | 54,694 |
| 2026-12-10 | 24,987 |
| 2026-12-11 | 27,647 |
| 2026-12-12 | 24,280 |
| 2026-12-13 | 23,737 |
| 2026-12-14 | 23,358 |
| 2026-12-15 | 26,129 |
| 2026-12-16 | 16,543 |
| 2026-12-17 | 24,909 |
| 2026-12-18 | 22,411 |
| 2026-12-19 | 25,478 |
| 2026-12-20 | 14,253 |
| 2026-12-21 | 27,228 |
| 2026-12-22 | 24,000 |
| 2026-12-23 | 21,038 |
| 2026-12-24 | 20,332 |
| 2026-12-25 | 21,550 |
| 2026-12-26 | 17,751 |
| 2026-12-27 | 24,568 |
| 2026-12-28 | 21,676 |
| 2026-12-29 | 22,510 |
| 2026-12-30 | 26,458 |
| 2026-12-31 | 20,109 |
| 2027-01-01 | 18,462 |
| 2027-01-02 | 26,063 |
| 2027-01-03 | 14,785 |
| 2027-01-04 | 28,409 |
| 2027-01-05 | 22,339 |
| 2027-01-06 | 35,521 |
| 2027-01-07 | 23,916 |
| 2027-01-08 | 25,814 |
| 2027-01-09 | 21,574 |
| 2027-01-10 | 24,683 |
| 2027-01-11 | 24,089 |
| 2027-01-12 | 22,966 |
| 2027-01-13 | 23,255 |
| 2027-01-14 | 21,860 |
| 2027-01-15 | 22,696 |
| 2027-01-16 | 26,767 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
