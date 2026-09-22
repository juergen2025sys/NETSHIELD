# Seen-DB Expiry Forecast

Lauf: 2026-09-22 15:21 CEST (Europe/Berlin)
Gesamt: 11,516,051 IPs in seen_db.json (8,727,444 aktiv/180-Tage-Pfad, 2,788,607 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 104,032 |
| 8-14 Tage | 88,111 |
| 15-30 Tage | 2,260,450 |
| 31-60 Tage | 1,036,556 |
| 61-90 Tage | 898,057 |
| 91-180 Tage | 4,340,238 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 584,241 |
| 0-3 Tage | 33,067 |
| 4-7 Tage | 630,848 |
| 8-14 Tage | 1,395,316 |
| 15-30 Tage | 145,135 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-22 | 11,124 |
| 2026-09-23 | 5,108 |
| 2026-09-24 | 11,382 |
| 2026-09-25 | 5,453 |
| 2026-09-26 | 623,794 |
| 2026-09-27 | 6,280 |
| 2026-09-28 | 774 |
| 2026-09-30 | 59,674 |
| 2026-10-01 | 7,649 |
| 2026-10-02 | 1,307,145 |
| 2026-10-03 | 2,971 |
| 2026-10-04 | 6,923 |
| 2026-10-05 | 2,904 |
| 2026-10-06 | 8,050 |
| 2026-10-07 | 7,962 |
| 2026-10-08 | 7,299 |
| 2026-10-09 | 10,188 |
| 2026-10-10 | 7,590 |
| 2026-10-11 | 6,280 |
| 2026-10-12 | 3,892 |
| 2026-10-13 | 8,342 |
| 2026-10-14 | 7,487 |
| 2026-10-15 | 8,362 |
| 2026-10-16 | 15,552 |
| 2026-10-17 | 9,996 |
| 2026-10-18 | 8,750 |
| 2026-10-19 | 5,201 |
| 2026-10-20 | 9,733 |
| 2026-10-21 | 9,684 |
| 2026-10-22 | 10,684 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **584,241** IPs. Brutto faellig in den naechsten 30 Tagen: **2,196,233**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,720,474**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-22 | 11,124 | 2,000 |
| 2026-09-23 | 5,108 | 2,000 |
| 2026-09-24 | 11,382 | 2,000 |
| 2026-09-25 | 5,453 | 2,000 |
| 2026-09-26 | 623,794 | 2,000 |
| 2026-09-27 | 6,280 | 2,000 |
| 2026-09-28 | 774 | 2,000 |
| 2026-09-30 | 59,674 | 2,000 |
| 2026-10-01 | 7,649 | 2,000 |
| 2026-10-02 | 1,307,145 | 2,000 |
| 2026-10-03 | 2,971 | 2,000 |
| 2026-10-04 | 6,923 | 2,000 |
| 2026-10-05 | 2,904 | 2,000 |
| 2026-10-06 | 8,050 | 2,000 |
| 2026-10-07 | 7,962 | 2,000 |
| 2026-10-08 | 7,299 | 2,000 |
| 2026-10-09 | 10,188 | 2,000 |
| 2026-10-10 | 7,590 | 2,000 |
| 2026-10-11 | 6,280 | 2,000 |
| 2026-10-12 | 3,892 | 2,000 |
| 2026-10-13 | 8,342 | 2,000 |
| 2026-10-14 | 7,487 | 2,000 |
| 2026-10-15 | 8,362 | 2,000 |
| 2026-10-16 | 15,552 | 2,000 |
| 2026-10-17 | 9,996 | 2,000 |
| 2026-10-18 | 8,750 | 2,000 |
| 2026-10-19 | 5,201 | 2,000 |
| 2026-10-20 | 9,733 | 2,000 |
| 2026-10-21 | 9,684 | 2,000 |
| 2026-10-22 | 10,684 | 2,000 |

> Hinweis: Der Rueckstau von 2,720,474 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-23 | 13,046 |
| 2026-09-24 | 16,645 |
| 2026-09-25 | 20,918 |
| 2026-09-26 | 17,439 |
| 2026-09-27 | 15,027 |
| 2026-09-28 | 11,605 |
| 2026-09-29 | 9,352 |
| 2026-09-30 | 10,172 |
| 2026-10-01 | 16,601 |
| 2026-10-02 | 7,717 |
| 2026-10-03 | 7,326 |
| 2026-10-04 | 12,623 |
| 2026-10-05 | 17,542 |
| 2026-10-06 | 16,130 |
| 2026-10-07 | 15,058 |
| 2026-10-08 | 61,403 |
| 2026-10-09 | 222,946 |
| 2026-10-10 | 53,381 |
| 2026-10-11 | 16,056 |
| 2026-10-12 | 66,588 |
| 2026-10-13 | 1,585,439 |
| 2026-10-14 | 32,922 |
| 2026-10-15 | 41,346 |
| 2026-10-16 | 51,316 |
| 2026-10-17 | 24,307 |
| 2026-10-18 | 14,278 |
| 2026-10-19 | 22,369 |
| 2026-10-20 | 11,146 |
| 2026-10-21 | 11,128 |
| 2026-10-22 | 30,767 |
| 2026-10-23 | 50,445 |
| 2026-10-24 | 41,756 |
| 2026-10-25 | 21,640 |
| 2026-10-26 | 20,364 |
| 2026-10-27 | 20,720 |
| 2026-10-28 | 15,828 |
| 2026-10-29 | 9,699 |
| 2026-10-30 | 62,006 |
| 2026-10-31 | 88,269 |
| 2026-11-01 | 27,905 |
| 2026-11-02 | 28,869 |
| 2026-11-03 | 29,884 |
| 2026-11-04 | 29,700 |
| 2026-11-05 | 25,333 |
| 2026-11-06 | 36,747 |
| 2026-11-07 | 24,531 |
| 2026-11-08 | 26,185 |
| 2026-11-09 | 25,613 |
| 2026-11-10 | 32,805 |
| 2026-11-11 | 22,437 |
| 2026-11-12 | 20,551 |
| 2026-11-13 | 19,697 |
| 2026-11-14 | 23,030 |
| 2026-11-15 | 17,507 |
| 2026-11-16 | 18,024 |
| 2026-11-17 | 15,282 |
| 2026-11-18 | 19,551 |
| 2026-11-19 | 174,292 |
| 2026-11-20 | 26,271 |
| 2026-11-21 | 61,615 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
