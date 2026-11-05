# Seen-DB Expiry Forecast

Lauf: 2026-11-05 23:39 CET (Europe/Berlin)
Gesamt: 11,193,835 IPs in seen_db.json (7,991,962 aktiv/180-Tage-Pfad, 3,201,873 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 186,906 |
| 8-14 Tage | 285,428 |
| 15-30 Tage | 547,666 |
| 31-60 Tage | 737,307 |
| 61-90 Tage | 885,300 |
| 91-180 Tage | 5,349,355 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,921,605 |
| 0-3 Tage | 38,718 |
| 4-7 Tage | 52,815 |
| 8-14 Tage | 69,447 |
| 15-30 Tage | 119,288 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-05 | 7,193 |
| 2026-11-06 | 12,011 |
| 2026-11-07 | 13,298 |
| 2026-11-08 | 6,216 |
| 2026-11-09 | 11,411 |
| 2026-11-10 | 23,586 |
| 2026-11-11 | 9,838 |
| 2026-11-12 | 7,980 |
| 2026-11-13 | 3,302 |
| 2026-11-14 | 11,546 |
| 2026-11-15 | 14,261 |
| 2026-11-16 | 18,806 |
| 2026-11-17 | 9,287 |
| 2026-11-18 | 3,469 |
| 2026-11-19 | 8,776 |
| 2026-11-20 | 10,852 |
| 2026-11-21 | 9,944 |
| 2026-11-22 | 9,992 |
| 2026-11-23 | 10,034 |
| 2026-11-24 | 10,111 |
| 2026-11-25 | 7,621 |
| 2026-11-26 | 3,345 |
| 2026-11-27 | 3,870 |
| 2026-11-28 | 3,550 |
| 2026-11-29 | 8,145 |
| 2026-11-30 | 7,144 |
| 2026-12-01 | 8,093 |
| 2026-12-02 | 4,627 |
| 2026-12-03 | 7,748 |
| 2026-12-04 | 5,787 |
| 2026-12-05 | 5,453 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,921,605** IPs. Brutto faellig in den naechsten 30 Tagen: **277,296**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,136,901**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-05 | 7,193 | 2,000 |
| 2026-11-06 | 12,011 | 2,000 |
| 2026-11-07 | 13,298 | 2,000 |
| 2026-11-08 | 6,216 | 2,000 |
| 2026-11-09 | 11,411 | 2,000 |
| 2026-11-10 | 23,586 | 2,000 |
| 2026-11-11 | 9,838 | 2,000 |
| 2026-11-12 | 7,980 | 2,000 |
| 2026-11-13 | 3,302 | 2,000 |
| 2026-11-14 | 11,546 | 2,000 |
| 2026-11-15 | 14,261 | 2,000 |
| 2026-11-16 | 18,806 | 2,000 |
| 2026-11-17 | 9,287 | 2,000 |
| 2026-11-18 | 3,469 | 2,000 |
| 2026-11-19 | 8,776 | 2,000 |
| 2026-11-20 | 10,852 | 2,000 |
| 2026-11-21 | 9,944 | 2,000 |
| 2026-11-22 | 9,992 | 2,000 |
| 2026-11-23 | 10,034 | 2,000 |
| 2026-11-24 | 10,111 | 2,000 |
| 2026-11-25 | 7,621 | 2,000 |
| 2026-11-26 | 3,345 | 2,000 |
| 2026-11-27 | 3,870 | 2,000 |
| 2026-11-28 | 3,550 | 2,000 |
| 2026-11-29 | 8,145 | 2,000 |
| 2026-11-30 | 7,144 | 2,000 |
| 2026-12-01 | 8,093 | 2,000 |
| 2026-12-02 | 4,627 | 2,000 |
| 2026-12-03 | 7,748 | 2,000 |
| 2026-12-04 | 5,787 | 2,000 |
| 2026-12-05 | 5,453 | 2,000 |

> Hinweis: Der Rueckstau von 3,136,901 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-06 | 36,119 |
| 2026-11-07 | 24,297 |
| 2026-11-08 | 25,974 |
| 2026-11-09 | 25,378 |
| 2026-11-10 | 32,530 |
| 2026-11-11 | 22,212 |
| 2026-11-12 | 20,396 |
| 2026-11-13 | 19,535 |
| 2026-11-14 | 22,829 |
| 2026-11-15 | 17,376 |
| 2026-11-16 | 17,852 |
| 2026-11-17 | 15,156 |
| 2026-11-18 | 19,402 |
| 2026-11-19 | 173,278 |
| 2026-11-20 | 26,005 |
| 2026-11-21 | 61,134 |
| 2026-11-22 | 30,267 |
| 2026-11-23 | 25,525 |
| 2026-11-24 | 26,355 |
| 2026-11-25 | 27,391 |
| 2026-11-26 | 28,553 |
| 2026-11-27 | 27,740 |
| 2026-11-28 | 109,031 |
| 2026-11-29 | 28,081 |
| 2026-11-30 | 25,436 |
| 2026-12-01 | 26,455 |
| 2026-12-02 | 26,094 |
| 2026-12-03 | 25,902 |
| 2026-12-04 | 27,829 |
| 2026-12-05 | 25,868 |
| 2026-12-06 | 30,032 |
| 2026-12-07 | 23,666 |
| 2026-12-08 | 39,268 |
| 2026-12-09 | 54,823 |
| 2026-12-10 | 25,018 |
| 2026-12-11 | 27,687 |
| 2026-12-12 | 24,307 |
| 2026-12-13 | 23,773 |
| 2026-12-14 | 23,390 |
| 2026-12-15 | 26,160 |
| 2026-12-16 | 16,576 |
| 2026-12-17 | 24,947 |
| 2026-12-18 | 22,440 |
| 2026-12-19 | 25,530 |
| 2026-12-20 | 14,272 |
| 2026-12-21 | 27,266 |
| 2026-12-22 | 24,041 |
| 2026-12-23 | 21,072 |
| 2026-12-24 | 20,368 |
| 2026-12-25 | 21,579 |
| 2026-12-26 | 17,783 |
| 2026-12-27 | 24,609 |
| 2026-12-28 | 21,712 |
| 2026-12-29 | 22,541 |
| 2026-12-30 | 26,487 |
| 2026-12-31 | 20,133 |
| 2027-01-01 | 18,493 |
| 2027-01-02 | 26,089 |
| 2027-01-03 | 14,810 |
| 2027-01-04 | 28,435 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
