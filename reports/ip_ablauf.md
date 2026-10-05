# Seen-DB Expiry Forecast

Lauf: 2026-10-05 17:50 CEST (Europe/Berlin)
Gesamt: 12,271,629 IPs in seen_db.json (9,305,273 aktiv/180-Tage-Pfad, 2,966,356 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 448,949 |
| 8-14 Tage | 1,767,106 |
| 15-30 Tage | 498,309 |
| 31-60 Tage | 1,023,483 |
| 61-90 Tage | 739,557 |
| 91-180 Tage | 4,827,869 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,617,760 |
| 0-3 Tage | 25,926 |
| 4-7 Tage | 27,739 |
| 8-14 Tage | 63,119 |
| 15-30 Tage | 231,812 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-05 | 2,858 |
| 2026-10-06 | 7,929 |
| 2026-10-07 | 7,891 |
| 2026-10-08 | 7,248 |
| 2026-10-09 | 10,122 |
| 2026-10-10 | 7,525 |
| 2026-10-11 | 6,233 |
| 2026-10-12 | 3,859 |
| 2026-10-13 | 8,246 |
| 2026-10-14 | 7,411 |
| 2026-10-15 | 8,284 |
| 2026-10-16 | 15,454 |
| 2026-10-17 | 9,930 |
| 2026-10-18 | 8,652 |
| 2026-10-19 | 5,142 |
| 2026-10-20 | 9,573 |
| 2026-10-21 | 9,525 |
| 2026-10-22 | 10,383 |
| 2026-10-23 | 12,404 |
| 2026-10-24 | 15,077 |
| 2026-10-25 | 11,100 |
| 2026-10-26 | 9,464 |
| 2026-10-27 | 35,298 |
| 2026-10-28 | 11,294 |
| 2026-10-29 | 9,862 |
| 2026-10-30 | 20,169 |
| 2026-10-31 | 17,117 |
| 2026-11-01 | 15,407 |
| 2026-11-02 | 11,995 |
| 2026-11-03 | 16,739 |
| 2026-11-04 | 10,204 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,617,760** IPs. Brutto faellig in den naechsten 30 Tagen: **342,395**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **2,898,155**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-05 | 2,858 | 2,000 |
| 2026-10-06 | 7,929 | 2,000 |
| 2026-10-07 | 7,891 | 2,000 |
| 2026-10-08 | 7,248 | 2,000 |
| 2026-10-09 | 10,122 | 2,000 |
| 2026-10-10 | 7,525 | 2,000 |
| 2026-10-11 | 6,233 | 2,000 |
| 2026-10-12 | 3,859 | 2,000 |
| 2026-10-13 | 8,246 | 2,000 |
| 2026-10-14 | 7,411 | 2,000 |
| 2026-10-15 | 8,284 | 2,000 |
| 2026-10-16 | 15,454 | 2,000 |
| 2026-10-17 | 9,930 | 2,000 |
| 2026-10-18 | 8,652 | 2,000 |
| 2026-10-19 | 5,142 | 2,000 |
| 2026-10-20 | 9,573 | 2,000 |
| 2026-10-21 | 9,525 | 2,000 |
| 2026-10-22 | 10,383 | 2,000 |
| 2026-10-23 | 12,404 | 2,000 |
| 2026-10-24 | 15,077 | 2,000 |
| 2026-10-25 | 11,100 | 2,000 |
| 2026-10-26 | 9,464 | 2,000 |
| 2026-10-27 | 35,298 | 2,000 |
| 2026-10-28 | 11,294 | 2,000 |
| 2026-10-29 | 9,862 | 2,000 |
| 2026-10-30 | 20,169 | 2,000 |
| 2026-10-31 | 17,117 | 2,000 |
| 2026-11-01 | 15,407 | 2,000 |
| 2026-11-02 | 11,995 | 2,000 |
| 2026-11-03 | 16,739 | 2,000 |
| 2026-11-04 | 10,204 | 2,000 |

> Hinweis: Der Rueckstau von 2,898,155 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-06 | 16,020 |
| 2026-10-07 | 14,954 |
| 2026-10-08 | 61,038 |
| 2026-10-09 | 221,132 |
| 2026-10-10 | 53,280 |
| 2026-10-11 | 16,006 |
| 2026-10-12 | 66,519 |
| 2026-10-13 | 1,581,131 |
| 2026-10-14 | 32,909 |
| 2026-10-15 | 41,297 |
| 2026-10-16 | 51,202 |
| 2026-10-17 | 24,206 |
| 2026-10-18 | 14,217 |
| 2026-10-19 | 22,144 |
| 2026-10-20 | 11,096 |
| 2026-10-21 | 11,056 |
| 2026-10-22 | 30,650 |
| 2026-10-23 | 50,312 |
| 2026-10-24 | 41,641 |
| 2026-10-25 | 21,549 |
| 2026-10-26 | 20,263 |
| 2026-10-27 | 20,602 |
| 2026-10-28 | 15,739 |
| 2026-10-29 | 9,630 |
| 2026-10-30 | 61,778 |
| 2026-10-31 | 88,141 |
| 2026-11-01 | 27,796 |
| 2026-11-02 | 28,756 |
| 2026-11-03 | 29,730 |
| 2026-11-04 | 29,570 |
| 2026-11-05 | 25,230 |
| 2026-11-06 | 36,307 |
| 2026-11-07 | 24,432 |
| 2026-11-08 | 26,092 |
| 2026-11-09 | 25,529 |
| 2026-11-10 | 32,698 |
| 2026-11-11 | 22,344 |
| 2026-11-12 | 20,485 |
| 2026-11-13 | 19,643 |
| 2026-11-14 | 22,955 |
| 2026-11-15 | 17,448 |
| 2026-11-16 | 17,949 |
| 2026-11-17 | 15,249 |
| 2026-11-18 | 19,497 |
| 2026-11-19 | 173,726 |
| 2026-11-20 | 26,153 |
| 2026-11-21 | 61,372 |
| 2026-11-22 | 30,424 |
| 2026-11-23 | 25,673 |
| 2026-11-24 | 26,475 |
| 2026-11-25 | 27,553 |
| 2026-11-26 | 28,667 |
| 2026-11-27 | 27,842 |
| 2026-11-28 | 109,214 |
| 2026-11-29 | 28,190 |
| 2026-11-30 | 25,558 |
| 2026-12-01 | 26,572 |
| 2026-12-02 | 26,211 |
| 2026-12-03 | 26,056 |
| 2026-12-04 | 27,939 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
