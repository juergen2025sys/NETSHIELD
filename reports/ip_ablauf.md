# Seen-DB Expiry Forecast

Lauf: 2026-10-26 00:09 CET (Europe/Berlin)
Gesamt: 11,166,217 IPs in seen_db.json (8,017,031 aktiv/180-Tage-Pfad, 3,149,186 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 242,673 |
| 8-14 Tage | 199,280 |
| 15-30 Tage | 555,802 |
| 31-60 Tage | 874,112 |
| 61-90 Tage | 731,030 |
| 91-180 Tage | 5,414,134 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,761,562 |
| 0-3 Tage | 66,702 |
| 4-7 Tage | 62,002 |
| 8-14 Tage | 77,263 |
| 15-30 Tage | 181,657 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-25 | 11,041 |
| 2026-10-26 | 9,394 |
| 2026-10-27 | 35,030 |
| 2026-10-28 | 11,237 |
| 2026-10-29 | 9,790 |
| 2026-10-30 | 20,022 |
| 2026-10-31 | 16,887 |
| 2026-11-01 | 15,303 |
| 2026-11-02 | 11,862 |
| 2026-11-03 | 16,568 |
| 2026-11-04 | 10,028 |
| 2026-11-05 | 7,208 |
| 2026-11-06 | 12,034 |
| 2026-11-07 | 13,320 |
| 2026-11-08 | 6,243 |
| 2026-11-09 | 11,440 |
| 2026-11-10 | 23,626 |
| 2026-11-11 | 9,865 |
| 2026-11-12 | 8,017 |
| 2026-11-13 | 3,318 |
| 2026-11-14 | 11,581 |
| 2026-11-15 | 14,305 |
| 2026-11-16 | 18,883 |
| 2026-11-17 | 9,319 |
| 2026-11-18 | 3,489 |
| 2026-11-19 | 8,823 |
| 2026-11-20 | 10,910 |
| 2026-11-21 | 10,023 |
| 2026-11-22 | 10,057 |
| 2026-11-23 | 10,101 |
| 2026-11-24 | 10,194 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,761,562** IPs. Brutto faellig in den naechsten 30 Tagen: **379,918**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,079,480**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-25 | 11,041 | 2,000 |
| 2026-10-26 | 9,394 | 2,000 |
| 2026-10-27 | 35,030 | 2,000 |
| 2026-10-28 | 11,237 | 2,000 |
| 2026-10-29 | 9,790 | 2,000 |
| 2026-10-30 | 20,022 | 2,000 |
| 2026-10-31 | 16,887 | 2,000 |
| 2026-11-01 | 15,303 | 2,000 |
| 2026-11-02 | 11,862 | 2,000 |
| 2026-11-03 | 16,568 | 2,000 |
| 2026-11-04 | 10,028 | 2,000 |
| 2026-11-05 | 7,208 | 2,000 |
| 2026-11-06 | 12,034 | 2,000 |
| 2026-11-07 | 13,320 | 2,000 |
| 2026-11-08 | 6,243 | 2,000 |
| 2026-11-09 | 11,440 | 2,000 |
| 2026-11-10 | 23,626 | 2,000 |
| 2026-11-11 | 9,865 | 2,000 |
| 2026-11-12 | 8,017 | 2,000 |
| 2026-11-13 | 3,318 | 2,000 |
| 2026-11-14 | 11,581 | 2,000 |
| 2026-11-15 | 14,305 | 2,000 |
| 2026-11-16 | 18,883 | 2,000 |
| 2026-11-17 | 9,319 | 2,000 |
| 2026-11-18 | 3,489 | 2,000 |
| 2026-11-19 | 8,823 | 2,000 |
| 2026-11-20 | 10,910 | 2,000 |
| 2026-11-21 | 10,023 | 2,000 |
| 2026-11-22 | 10,057 | 2,000 |
| 2026-11-23 | 10,101 | 2,000 |
| 2026-11-24 | 10,194 | 2,000 |

> Hinweis: Der Rueckstau von 3,079,480 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-26 | 20,152 |
| 2026-10-27 | 20,367 |
| 2026-10-28 | 15,469 |
| 2026-10-29 | 9,476 |
| 2026-10-30 | 61,512 |
| 2026-10-31 | 88,002 |
| 2026-11-01 | 27,695 |
| 2026-11-02 | 28,638 |
| 2026-11-03 | 29,583 |
| 2026-11-04 | 29,438 |
| 2026-11-05 | 25,129 |
| 2026-11-06 | 36,173 |
| 2026-11-07 | 24,325 |
| 2026-11-08 | 25,994 |
| 2026-11-09 | 25,414 |
| 2026-11-10 | 32,571 |
| 2026-11-11 | 22,243 |
| 2026-11-12 | 20,424 |
| 2026-11-13 | 19,566 |
| 2026-11-14 | 22,860 |
| 2026-11-15 | 17,391 |
| 2026-11-16 | 17,875 |
| 2026-11-17 | 15,175 |
| 2026-11-18 | 19,423 |
| 2026-11-19 | 173,365 |
| 2026-11-20 | 26,045 |
| 2026-11-21 | 61,200 |
| 2026-11-22 | 30,307 |
| 2026-11-23 | 25,569 |
| 2026-11-24 | 26,374 |
| 2026-11-25 | 27,430 |
| 2026-11-26 | 28,580 |
| 2026-11-27 | 27,766 |
| 2026-11-28 | 109,086 |
| 2026-11-29 | 28,101 |
| 2026-11-30 | 25,460 |
| 2026-12-01 | 26,475 |
| 2026-12-02 | 26,117 |
| 2026-12-03 | 25,935 |
| 2026-12-04 | 27,856 |
| 2026-12-05 | 25,900 |
| 2026-12-06 | 30,065 |
| 2026-12-07 | 23,688 |
| 2026-12-08 | 39,306 |
| 2026-12-09 | 54,964 |
| 2026-12-10 | 25,044 |
| 2026-12-11 | 27,717 |
| 2026-12-12 | 24,338 |
| 2026-12-13 | 23,813 |
| 2026-12-14 | 23,431 |
| 2026-12-15 | 26,205 |
| 2026-12-16 | 16,608 |
| 2026-12-17 | 24,974 |
| 2026-12-18 | 22,482 |
| 2026-12-19 | 25,568 |
| 2026-12-20 | 14,298 |
| 2026-12-21 | 27,314 |
| 2026-12-22 | 24,091 |
| 2026-12-23 | 21,108 |
| 2026-12-24 | 20,392 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
