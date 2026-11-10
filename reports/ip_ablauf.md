# Seen-DB Expiry Forecast

Lauf: 2026-11-10 13:55 CET (Europe/Berlin)
Gesamt: 11,228,664 IPs in seen_db.json (8,002,876 aktiv/180-Tage-Pfad, 3,225,788 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 135,275 |
| 8-14 Tage | 361,810 |
| 15-30 Tage | 550,951 |
| 31-60 Tage | 693,462 |
| 61-90 Tage | 1,161,975 |
| 91-180 Tage | 5,099,403 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,965,115 |
| 0-3 Tage | 44,660 |
| 4-7 Tage | 53,843 |
| 8-14 Tage | 63,089 |
| 15-30 Tage | 99,081 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-10 | 23,566 |
| 2026-11-11 | 9,824 |
| 2026-11-12 | 7,969 |
| 2026-11-13 | 3,301 |
| 2026-11-14 | 11,532 |
| 2026-11-15 | 14,245 |
| 2026-11-16 | 18,792 |
| 2026-11-17 | 9,274 |
| 2026-11-18 | 3,462 |
| 2026-11-19 | 8,762 |
| 2026-11-20 | 10,837 |
| 2026-11-21 | 9,931 |
| 2026-11-22 | 9,976 |
| 2026-11-23 | 10,020 |
| 2026-11-24 | 10,101 |
| 2026-11-25 | 7,609 |
| 2026-11-26 | 3,338 |
| 2026-11-27 | 3,862 |
| 2026-11-28 | 3,545 |
| 2026-11-29 | 8,137 |
| 2026-11-30 | 7,119 |
| 2026-12-01 | 8,083 |
| 2026-12-02 | 4,587 |
| 2026-12-03 | 7,730 |
| 2026-12-04 | 5,770 |
| 2026-12-05 | 5,423 |
| 2026-12-06 | 3,110 |
| 2026-12-07 | 7,820 |
| 2026-12-08 | 4,528 |
| 2026-12-09 | 9,072 |
| 2026-12-10 | 6,080 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,965,115** IPs. Brutto faellig in den naechsten 30 Tagen: **257,405**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,160,520**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-10 | 23,566 | 2,000 |
| 2026-11-11 | 9,824 | 2,000 |
| 2026-11-12 | 7,969 | 2,000 |
| 2026-11-13 | 3,301 | 2,000 |
| 2026-11-14 | 11,532 | 2,000 |
| 2026-11-15 | 14,245 | 2,000 |
| 2026-11-16 | 18,792 | 2,000 |
| 2026-11-17 | 9,274 | 2,000 |
| 2026-11-18 | 3,462 | 2,000 |
| 2026-11-19 | 8,762 | 2,000 |
| 2026-11-20 | 10,837 | 2,000 |
| 2026-11-21 | 9,931 | 2,000 |
| 2026-11-22 | 9,976 | 2,000 |
| 2026-11-23 | 10,020 | 2,000 |
| 2026-11-24 | 10,101 | 2,000 |
| 2026-11-25 | 7,609 | 2,000 |
| 2026-11-26 | 3,338 | 2,000 |
| 2026-11-27 | 3,862 | 2,000 |
| 2026-11-28 | 3,545 | 2,000 |
| 2026-11-29 | 8,137 | 2,000 |
| 2026-11-30 | 7,119 | 2,000 |
| 2026-12-01 | 8,083 | 2,000 |
| 2026-12-02 | 4,587 | 2,000 |
| 2026-12-03 | 7,730 | 2,000 |
| 2026-12-04 | 5,770 | 2,000 |
| 2026-12-05 | 5,423 | 2,000 |
| 2026-12-06 | 3,110 | 2,000 |
| 2026-12-07 | 7,820 | 2,000 |
| 2026-12-08 | 4,528 | 2,000 |
| 2026-12-09 | 9,072 | 2,000 |
| 2026-12-10 | 6,080 | 2,000 |

> Hinweis: Der Rueckstau von 3,160,520 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-11 | 22,189 |
| 2026-11-12 | 20,382 |
| 2026-11-13 | 19,528 |
| 2026-11-14 | 22,807 |
| 2026-11-15 | 17,371 |
| 2026-11-16 | 17,845 |
| 2026-11-17 | 15,153 |
| 2026-11-18 | 19,397 |
| 2026-11-19 | 173,204 |
| 2026-11-20 | 25,998 |
| 2026-11-21 | 61,108 |
| 2026-11-22 | 30,251 |
| 2026-11-23 | 25,521 |
| 2026-11-24 | 26,331 |
| 2026-11-25 | 27,369 |
| 2026-11-26 | 28,538 |
| 2026-11-27 | 27,732 |
| 2026-11-28 | 109,012 |
| 2026-11-29 | 28,073 |
| 2026-11-30 | 25,430 |
| 2026-12-01 | 26,444 |
| 2026-12-02 | 26,084 |
| 2026-12-03 | 25,889 |
| 2026-12-04 | 27,818 |
| 2026-12-05 | 25,860 |
| 2026-12-06 | 30,018 |
| 2026-12-07 | 23,654 |
| 2026-12-08 | 39,248 |
| 2026-12-09 | 54,776 |
| 2026-12-10 | 25,006 |
| 2026-12-11 | 27,672 |
| 2026-12-12 | 24,296 |
| 2026-12-13 | 23,762 |
| 2026-12-14 | 23,370 |
| 2026-12-15 | 26,149 |
| 2026-12-16 | 16,567 |
| 2026-12-17 | 24,938 |
| 2026-12-18 | 22,429 |
| 2026-12-19 | 25,506 |
| 2026-12-20 | 14,262 |
| 2026-12-21 | 27,249 |
| 2026-12-22 | 24,022 |
| 2026-12-23 | 21,062 |
| 2026-12-24 | 20,351 |
| 2026-12-25 | 21,567 |
| 2026-12-26 | 17,774 |
| 2026-12-27 | 24,593 |
| 2026-12-28 | 21,694 |
| 2026-12-29 | 22,532 |
| 2026-12-30 | 26,479 |
| 2026-12-31 | 20,128 |
| 2027-01-01 | 18,480 |
| 2027-01-02 | 26,081 |
| 2027-01-03 | 14,796 |
| 2027-01-04 | 28,422 |
| 2027-01-05 | 22,360 |
| 2027-01-06 | 35,547 |
| 2027-01-07 | 23,941 |
| 2027-01-08 | 25,840 |
| 2027-01-09 | 21,593 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
