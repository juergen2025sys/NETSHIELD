# Seen-DB Expiry Forecast

Lauf: 2026-10-06 04:29 CEST (Europe/Berlin)
Gesamt: 12,278,090 IPs in seen_db.json (9,312,435 aktiv/180-Tage-Pfad, 2,965,655 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 2,013,910 |
| 8-14 Tage | 197,057 |
| 15-30 Tage | 512,405 |
| 31-60 Tage | 1,024,162 |
| 61-90 Tage | 742,096 |
| 91-180 Tage | 4,822,805 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,618,524 |
| 0-3 Tage | 33,181 |
| 4-7 Tage | 25,858 |
| 8-14 Tage | 64,430 |
| 15-30 Tage | 223,662 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-06 | 7,925 |
| 2026-10-07 | 7,888 |
| 2026-10-08 | 7,246 |
| 2026-10-09 | 10,122 |
| 2026-10-10 | 7,525 |
| 2026-10-11 | 6,231 |
| 2026-10-12 | 3,859 |
| 2026-10-13 | 8,243 |
| 2026-10-14 | 7,409 |
| 2026-10-15 | 8,280 |
| 2026-10-16 | 15,451 |
| 2026-10-17 | 9,929 |
| 2026-10-18 | 8,649 |
| 2026-10-19 | 5,141 |
| 2026-10-20 | 9,571 |
| 2026-10-21 | 9,521 |
| 2026-10-22 | 10,382 |
| 2026-10-23 | 12,401 |
| 2026-10-24 | 15,070 |
| 2026-10-25 | 11,098 |
| 2026-10-26 | 9,459 |
| 2026-10-27 | 35,285 |
| 2026-10-28 | 11,294 |
| 2026-10-29 | 9,860 |
| 2026-10-30 | 20,168 |
| 2026-10-31 | 17,109 |
| 2026-11-01 | 15,399 |
| 2026-11-02 | 11,988 |
| 2026-11-03 | 16,724 |
| 2026-11-04 | 10,174 |
| 2026-11-05 | 7,451 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,618,524** IPs. Brutto faellig in den naechsten 30 Tagen: **346,852**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **2,903,376**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-06 | 7,925 | 2,000 |
| 2026-10-07 | 7,888 | 2,000 |
| 2026-10-08 | 7,246 | 2,000 |
| 2026-10-09 | 10,122 | 2,000 |
| 2026-10-10 | 7,525 | 2,000 |
| 2026-10-11 | 6,231 | 2,000 |
| 2026-10-12 | 3,859 | 2,000 |
| 2026-10-13 | 8,243 | 2,000 |
| 2026-10-14 | 7,409 | 2,000 |
| 2026-10-15 | 8,280 | 2,000 |
| 2026-10-16 | 15,451 | 2,000 |
| 2026-10-17 | 9,929 | 2,000 |
| 2026-10-18 | 8,649 | 2,000 |
| 2026-10-19 | 5,141 | 2,000 |
| 2026-10-20 | 9,571 | 2,000 |
| 2026-10-21 | 9,521 | 2,000 |
| 2026-10-22 | 10,382 | 2,000 |
| 2026-10-23 | 12,401 | 2,000 |
| 2026-10-24 | 15,070 | 2,000 |
| 2026-10-25 | 11,098 | 2,000 |
| 2026-10-26 | 9,459 | 2,000 |
| 2026-10-27 | 35,285 | 2,000 |
| 2026-10-28 | 11,294 | 2,000 |
| 2026-10-29 | 9,860 | 2,000 |
| 2026-10-30 | 20,168 | 2,000 |
| 2026-10-31 | 17,109 | 2,000 |
| 2026-11-01 | 15,399 | 2,000 |
| 2026-11-02 | 11,988 | 2,000 |
| 2026-11-03 | 16,724 | 2,000 |
| 2026-11-04 | 10,174 | 2,000 |
| 2026-11-05 | 7,451 | 2,000 |

> Hinweis: Der Rueckstau von 2,903,376 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-07 | 14,949 |
| 2026-10-08 | 61,032 |
| 2026-10-09 | 221,093 |
| 2026-10-10 | 53,278 |
| 2026-10-11 | 16,005 |
| 2026-10-12 | 66,518 |
| 2026-10-13 | 1,581,035 |
| 2026-10-14 | 32,909 |
| 2026-10-15 | 41,297 |
| 2026-10-16 | 51,200 |
| 2026-10-17 | 24,205 |
| 2026-10-18 | 14,215 |
| 2026-10-19 | 22,136 |
| 2026-10-20 | 11,095 |
| 2026-10-21 | 11,055 |
| 2026-10-22 | 30,647 |
| 2026-10-23 | 50,308 |
| 2026-10-24 | 41,640 |
| 2026-10-25 | 21,548 |
| 2026-10-26 | 20,263 |
| 2026-10-27 | 20,601 |
| 2026-10-28 | 15,737 |
| 2026-10-29 | 9,630 |
| 2026-10-30 | 61,767 |
| 2026-10-31 | 88,135 |
| 2026-11-01 | 27,796 |
| 2026-11-02 | 28,754 |
| 2026-11-03 | 29,727 |
| 2026-11-04 | 29,568 |
| 2026-11-05 | 25,229 |
| 2026-11-06 | 36,305 |
| 2026-11-07 | 24,432 |
| 2026-11-08 | 26,092 |
| 2026-11-09 | 25,528 |
| 2026-11-10 | 32,698 |
| 2026-11-11 | 22,343 |
| 2026-11-12 | 20,484 |
| 2026-11-13 | 19,643 |
| 2026-11-14 | 22,954 |
| 2026-11-15 | 17,448 |
| 2026-11-16 | 17,949 |
| 2026-11-17 | 15,248 |
| 2026-11-18 | 19,496 |
| 2026-11-19 | 173,714 |
| 2026-11-20 | 26,147 |
| 2026-11-21 | 61,370 |
| 2026-11-22 | 30,421 |
| 2026-11-23 | 25,671 |
| 2026-11-24 | 26,473 |
| 2026-11-25 | 27,549 |
| 2026-11-26 | 28,667 |
| 2026-11-27 | 27,841 |
| 2026-11-28 | 109,208 |
| 2026-11-29 | 28,188 |
| 2026-11-30 | 25,555 |
| 2026-12-01 | 26,566 |
| 2026-12-02 | 26,211 |
| 2026-12-03 | 26,050 |
| 2026-12-04 | 27,936 |
| 2026-12-05 | 25,975 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
