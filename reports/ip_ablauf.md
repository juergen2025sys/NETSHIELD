# Seen-DB Expiry Forecast

Lauf: 2026-09-22 09:38 CEST (Europe/Berlin)
Gesamt: 11,495,942 IPs in seen_db.json (8,712,691 aktiv/180-Tage-Pfad, 2,783,251 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 104,056 |
| 8-14 Tage | 88,125 |
| 15-30 Tage | 2,260,639 |
| 31-60 Tage | 1,036,633 |
| 61-90 Tage | 898,158 |
| 91-180 Tage | 4,325,080 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 584,315 |
| 0-3 Tage | 33,075 |
| 4-7 Tage | 630,863 |
| 8-14 Tage | 1,395,388 |
| 15-30 Tage | 139,610 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-22 | 11,127 |
| 2026-09-23 | 5,109 |
| 2026-09-24 | 11,384 |
| 2026-09-25 | 5,455 |
| 2026-09-26 | 623,807 |
| 2026-09-27 | 6,282 |
| 2026-09-28 | 774 |
| 2026-09-30 | 59,676 |
| 2026-10-01 | 7,650 |
| 2026-10-02 | 1,307,210 |
| 2026-10-03 | 2,972 |
| 2026-10-04 | 6,924 |
| 2026-10-05 | 2,904 |
| 2026-10-06 | 8,052 |
| 2026-10-07 | 7,965 |
| 2026-10-08 | 7,300 |
| 2026-10-09 | 10,192 |
| 2026-10-10 | 7,593 |
| 2026-10-11 | 6,282 |
| 2026-10-12 | 3,893 |
| 2026-10-13 | 8,344 |
| 2026-10-14 | 7,487 |
| 2026-10-15 | 8,365 |
| 2026-10-16 | 15,556 |
| 2026-10-17 | 9,997 |
| 2026-10-18 | 8,755 |
| 2026-10-19 | 5,202 |
| 2026-10-20 | 9,737 |
| 2026-10-21 | 9,691 |
| 2026-10-22 | 11,114 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **584,315** IPs. Brutto faellig in den naechsten 30 Tagen: **2,196,799**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,721,114**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-22 | 11,127 | 2,000 |
| 2026-09-23 | 5,109 | 2,000 |
| 2026-09-24 | 11,384 | 2,000 |
| 2026-09-25 | 5,455 | 2,000 |
| 2026-09-26 | 623,807 | 2,000 |
| 2026-09-27 | 6,282 | 2,000 |
| 2026-09-28 | 774 | 2,000 |
| 2026-09-30 | 59,676 | 2,000 |
| 2026-10-01 | 7,650 | 2,000 |
| 2026-10-02 | 1,307,210 | 2,000 |
| 2026-10-03 | 2,972 | 2,000 |
| 2026-10-04 | 6,924 | 2,000 |
| 2026-10-05 | 2,904 | 2,000 |
| 2026-10-06 | 8,052 | 2,000 |
| 2026-10-07 | 7,965 | 2,000 |
| 2026-10-08 | 7,300 | 2,000 |
| 2026-10-09 | 10,192 | 2,000 |
| 2026-10-10 | 7,593 | 2,000 |
| 2026-10-11 | 6,282 | 2,000 |
| 2026-10-12 | 3,893 | 2,000 |
| 2026-10-13 | 8,344 | 2,000 |
| 2026-10-14 | 7,487 | 2,000 |
| 2026-10-15 | 8,365 | 2,000 |
| 2026-10-16 | 15,556 | 2,000 |
| 2026-10-17 | 9,997 | 2,000 |
| 2026-10-18 | 8,755 | 2,000 |
| 2026-10-19 | 5,202 | 2,000 |
| 2026-10-20 | 9,737 | 2,000 |
| 2026-10-21 | 9,691 | 2,000 |
| 2026-10-22 | 11,114 | 2,000 |

> Hinweis: Der Rueckstau von 2,721,114 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-23 | 13,047 |
| 2026-09-24 | 16,655 |
| 2026-09-25 | 20,924 |
| 2026-09-26 | 17,440 |
| 2026-09-27 | 15,030 |
| 2026-09-28 | 11,607 |
| 2026-09-29 | 9,353 |
| 2026-09-30 | 10,173 |
| 2026-10-01 | 16,602 |
| 2026-10-02 | 7,719 |
| 2026-10-03 | 7,330 |
| 2026-10-04 | 12,626 |
| 2026-10-05 | 17,543 |
| 2026-10-06 | 16,132 |
| 2026-10-07 | 15,059 |
| 2026-10-08 | 61,414 |
| 2026-10-09 | 223,013 |
| 2026-10-10 | 53,382 |
| 2026-10-11 | 16,056 |
| 2026-10-12 | 66,588 |
| 2026-10-13 | 1,585,525 |
| 2026-10-14 | 32,922 |
| 2026-10-15 | 41,346 |
| 2026-10-16 | 51,319 |
| 2026-10-17 | 24,309 |
| 2026-10-18 | 14,281 |
| 2026-10-19 | 22,376 |
| 2026-10-20 | 11,150 |
| 2026-10-21 | 11,129 |
| 2026-10-22 | 30,770 |
| 2026-10-23 | 50,446 |
| 2026-10-24 | 41,764 |
| 2026-10-25 | 21,645 |
| 2026-10-26 | 20,366 |
| 2026-10-27 | 20,723 |
| 2026-10-28 | 15,828 |
| 2026-10-29 | 9,701 |
| 2026-10-30 | 62,013 |
| 2026-10-31 | 88,269 |
| 2026-11-01 | 27,906 |
| 2026-11-02 | 28,869 |
| 2026-11-03 | 29,884 |
| 2026-11-04 | 29,706 |
| 2026-11-05 | 25,334 |
| 2026-11-06 | 36,751 |
| 2026-11-07 | 24,534 |
| 2026-11-08 | 26,185 |
| 2026-11-09 | 25,616 |
| 2026-11-10 | 32,807 |
| 2026-11-11 | 22,440 |
| 2026-11-12 | 20,551 |
| 2026-11-13 | 19,698 |
| 2026-11-14 | 23,032 |
| 2026-11-15 | 17,507 |
| 2026-11-16 | 18,026 |
| 2026-11-17 | 15,283 |
| 2026-11-18 | 19,552 |
| 2026-11-19 | 174,303 |
| 2026-11-20 | 26,274 |
| 2026-11-21 | 61,620 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
