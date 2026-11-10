# Seen-DB Expiry Forecast

Lauf: 2026-11-10 21:25 CET (Europe/Berlin)
Gesamt: 11,239,675 IPs in seen_db.json (8,013,354 aktiv/180-Tage-Pfad, 3,226,321 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 135,273 |
| 8-14 Tage | 361,791 |
| 15-30 Tage | 550,930 |
| 31-60 Tage | 693,420 |
| 61-90 Tage | 1,161,905 |
| 91-180 Tage | 5,110,035 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,965,040 |
| 0-3 Tage | 44,659 |
| 4-7 Tage | 53,836 |
| 8-14 Tage | 63,077 |
| 15-30 Tage | 99,709 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-10 | 23,566 |
| 2026-11-11 | 9,824 |
| 2026-11-12 | 7,968 |
| 2026-11-13 | 3,301 |
| 2026-11-14 | 11,530 |
| 2026-11-15 | 14,242 |
| 2026-11-16 | 18,790 |
| 2026-11-17 | 9,274 |
| 2026-11-18 | 3,462 |
| 2026-11-19 | 8,757 |
| 2026-11-20 | 10,833 |
| 2026-11-21 | 9,930 |
| 2026-11-22 | 9,976 |
| 2026-11-23 | 10,020 |
| 2026-11-24 | 10,099 |
| 2026-11-25 | 7,608 |
| 2026-11-26 | 3,338 |
| 2026-11-27 | 3,861 |
| 2026-11-28 | 3,543 |
| 2026-11-29 | 8,134 |
| 2026-11-30 | 7,116 |
| 2026-12-01 | 8,083 |
| 2026-12-02 | 4,584 |
| 2026-12-03 | 7,730 |
| 2026-12-04 | 5,770 |
| 2026-12-05 | 5,421 |
| 2026-12-06 | 3,109 |
| 2026-12-07 | 7,815 |
| 2026-12-08 | 4,523 |
| 2026-12-09 | 9,068 |
| 2026-12-10 | 6,070 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,965,040** IPs. Brutto faellig in den naechsten 30 Tagen: **257,345**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,160,385**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-10 | 23,566 | 2,000 |
| 2026-11-11 | 9,824 | 2,000 |
| 2026-11-12 | 7,968 | 2,000 |
| 2026-11-13 | 3,301 | 2,000 |
| 2026-11-14 | 11,530 | 2,000 |
| 2026-11-15 | 14,242 | 2,000 |
| 2026-11-16 | 18,790 | 2,000 |
| 2026-11-17 | 9,274 | 2,000 |
| 2026-11-18 | 3,462 | 2,000 |
| 2026-11-19 | 8,757 | 2,000 |
| 2026-11-20 | 10,833 | 2,000 |
| 2026-11-21 | 9,930 | 2,000 |
| 2026-11-22 | 9,976 | 2,000 |
| 2026-11-23 | 10,020 | 2,000 |
| 2026-11-24 | 10,099 | 2,000 |
| 2026-11-25 | 7,608 | 2,000 |
| 2026-11-26 | 3,338 | 2,000 |
| 2026-11-27 | 3,861 | 2,000 |
| 2026-11-28 | 3,543 | 2,000 |
| 2026-11-29 | 8,134 | 2,000 |
| 2026-11-30 | 7,116 | 2,000 |
| 2026-12-01 | 8,083 | 2,000 |
| 2026-12-02 | 4,584 | 2,000 |
| 2026-12-03 | 7,730 | 2,000 |
| 2026-12-04 | 5,770 | 2,000 |
| 2026-12-05 | 5,421 | 2,000 |
| 2026-12-06 | 3,109 | 2,000 |
| 2026-12-07 | 7,815 | 2,000 |
| 2026-12-08 | 4,523 | 2,000 |
| 2026-12-09 | 9,068 | 2,000 |
| 2026-12-10 | 6,070 | 2,000 |

> Hinweis: Der Rueckstau von 3,160,385 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-11 | 22,188 |
| 2026-11-12 | 20,382 |
| 2026-11-13 | 19,528 |
| 2026-11-14 | 22,806 |
| 2026-11-15 | 17,371 |
| 2026-11-16 | 17,845 |
| 2026-11-17 | 15,153 |
| 2026-11-18 | 19,396 |
| 2026-11-19 | 173,199 |
| 2026-11-20 | 25,997 |
| 2026-11-21 | 61,101 |
| 2026-11-22 | 30,250 |
| 2026-11-23 | 25,520 |
| 2026-11-24 | 26,328 |
| 2026-11-25 | 27,368 |
| 2026-11-26 | 28,537 |
| 2026-11-27 | 27,730 |
| 2026-11-28 | 109,009 |
| 2026-11-29 | 28,071 |
| 2026-11-30 | 25,428 |
| 2026-12-01 | 26,444 |
| 2026-12-02 | 26,084 |
| 2026-12-03 | 25,888 |
| 2026-12-04 | 27,816 |
| 2026-12-05 | 25,860 |
| 2026-12-06 | 30,017 |
| 2026-12-07 | 23,654 |
| 2026-12-08 | 39,248 |
| 2026-12-09 | 54,771 |
| 2026-12-10 | 25,005 |
| 2026-12-11 | 27,671 |
| 2026-12-12 | 24,294 |
| 2026-12-13 | 23,760 |
| 2026-12-14 | 23,369 |
| 2026-12-15 | 26,147 |
| 2026-12-16 | 16,566 |
| 2026-12-17 | 24,936 |
| 2026-12-18 | 22,426 |
| 2026-12-19 | 25,504 |
| 2026-12-20 | 14,261 |
| 2026-12-21 | 27,249 |
| 2026-12-22 | 24,021 |
| 2026-12-23 | 21,062 |
| 2026-12-24 | 20,349 |
| 2026-12-25 | 21,567 |
| 2026-12-26 | 17,773 |
| 2026-12-27 | 24,593 |
| 2026-12-28 | 21,693 |
| 2026-12-29 | 22,529 |
| 2026-12-30 | 26,475 |
| 2026-12-31 | 20,127 |
| 2027-01-01 | 18,479 |
| 2027-01-02 | 26,079 |
| 2027-01-03 | 14,796 |
| 2027-01-04 | 28,420 |
| 2027-01-05 | 22,357 |
| 2027-01-06 | 35,547 |
| 2027-01-07 | 23,938 |
| 2027-01-08 | 25,839 |
| 2027-01-09 | 21,593 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
