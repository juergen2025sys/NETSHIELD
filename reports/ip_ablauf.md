# Seen-DB Expiry Forecast

Lauf: 2026-10-03 13:32 CEST (Europe/Berlin)
Gesamt: 12,147,651 IPs in seen_db.json (9,195,781 aktiv/180-Tage-Pfad, 2,951,870 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 396,820 |
| 8-14 Tage | 1,814,397 |
| 15-30 Tage | 475,660 |
| 31-60 Tage | 1,029,298 |
| 61-90 Tage | 753,015 |
| 91-180 Tage | 4,726,591 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,612,771 |
| 0-3 Tage | 20,564 |
| 4-7 Tage | 32,814 |
| 8-14 Tage | 59,495 |
| 15-30 Tage | 226,226 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-03 | 2,944 |
| 2026-10-04 | 6,825 |
| 2026-10-05 | 2,860 |
| 2026-10-06 | 7,935 |
| 2026-10-07 | 7,896 |
| 2026-10-08 | 7,255 |
| 2026-10-09 | 10,131 |
| 2026-10-10 | 7,532 |
| 2026-10-11 | 6,241 |
| 2026-10-12 | 3,864 |
| 2026-10-13 | 8,260 |
| 2026-10-14 | 7,419 |
| 2026-10-15 | 8,301 |
| 2026-10-16 | 15,470 |
| 2026-10-17 | 9,940 |
| 2026-10-18 | 8,656 |
| 2026-10-19 | 5,151 |
| 2026-10-20 | 9,593 |
| 2026-10-21 | 9,544 |
| 2026-10-22 | 10,397 |
| 2026-10-23 | 12,422 |
| 2026-10-24 | 15,093 |
| 2026-10-25 | 11,116 |
| 2026-10-26 | 9,482 |
| 2026-10-27 | 35,322 |
| 2026-10-28 | 11,308 |
| 2026-10-29 | 9,880 |
| 2026-10-30 | 20,202 |
| 2026-10-31 | 17,179 |
| 2026-11-01 | 15,441 |
| 2026-11-02 | 12,120 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,612,771** IPs. Brutto faellig in den naechsten 30 Tagen: **325,779**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **2,876,550**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-03 | 2,944 | 2,000 |
| 2026-10-04 | 6,825 | 2,000 |
| 2026-10-05 | 2,860 | 2,000 |
| 2026-10-06 | 7,935 | 2,000 |
| 2026-10-07 | 7,896 | 2,000 |
| 2026-10-08 | 7,255 | 2,000 |
| 2026-10-09 | 10,131 | 2,000 |
| 2026-10-10 | 7,532 | 2,000 |
| 2026-10-11 | 6,241 | 2,000 |
| 2026-10-12 | 3,864 | 2,000 |
| 2026-10-13 | 8,260 | 2,000 |
| 2026-10-14 | 7,419 | 2,000 |
| 2026-10-15 | 8,301 | 2,000 |
| 2026-10-16 | 15,470 | 2,000 |
| 2026-10-17 | 9,940 | 2,000 |
| 2026-10-18 | 8,656 | 2,000 |
| 2026-10-19 | 5,151 | 2,000 |
| 2026-10-20 | 9,593 | 2,000 |
| 2026-10-21 | 9,544 | 2,000 |
| 2026-10-22 | 10,397 | 2,000 |
| 2026-10-23 | 12,422 | 2,000 |
| 2026-10-24 | 15,093 | 2,000 |
| 2026-10-25 | 11,116 | 2,000 |
| 2026-10-26 | 9,482 | 2,000 |
| 2026-10-27 | 35,322 | 2,000 |
| 2026-10-28 | 11,308 | 2,000 |
| 2026-10-29 | 9,880 | 2,000 |
| 2026-10-30 | 20,202 | 2,000 |
| 2026-10-31 | 17,179 | 2,000 |
| 2026-11-01 | 15,441 | 2,000 |
| 2026-11-02 | 12,120 | 2,000 |

> Hinweis: Der Rueckstau von 2,876,550 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-04 | 12,539 |
| 2026-10-05 | 17,459 |
| 2026-10-06 | 16,037 |
| 2026-10-07 | 14,973 |
| 2026-10-08 | 61,087 |
| 2026-10-09 | 221,432 |
| 2026-10-10 | 53,293 |
| 2026-10-11 | 16,013 |
| 2026-10-12 | 66,525 |
| 2026-10-13 | 1,582,210 |
| 2026-10-14 | 32,912 |
| 2026-10-15 | 41,299 |
| 2026-10-16 | 51,222 |
| 2026-10-17 | 24,216 |
| 2026-10-18 | 14,227 |
| 2026-10-19 | 22,180 |
| 2026-10-20 | 11,114 |
| 2026-10-21 | 11,074 |
| 2026-10-22 | 30,671 |
| 2026-10-23 | 50,339 |
| 2026-10-24 | 41,656 |
| 2026-10-25 | 21,561 |
| 2026-10-26 | 20,284 |
| 2026-10-27 | 20,614 |
| 2026-10-28 | 15,749 |
| 2026-10-29 | 9,640 |
| 2026-10-30 | 61,810 |
| 2026-10-31 | 88,155 |
| 2026-11-01 | 27,814 |
| 2026-11-02 | 28,772 |
| 2026-11-03 | 29,743 |
| 2026-11-04 | 29,586 |
| 2026-11-05 | 25,241 |
| 2026-11-06 | 36,340 |
| 2026-11-07 | 24,444 |
| 2026-11-08 | 26,097 |
| 2026-11-09 | 25,541 |
| 2026-11-10 | 32,711 |
| 2026-11-11 | 22,355 |
| 2026-11-12 | 20,496 |
| 2026-11-13 | 19,651 |
| 2026-11-14 | 22,967 |
| 2026-11-15 | 17,452 |
| 2026-11-16 | 17,967 |
| 2026-11-17 | 15,255 |
| 2026-11-18 | 19,504 |
| 2026-11-19 | 173,813 |
| 2026-11-20 | 26,169 |
| 2026-11-21 | 61,410 |
| 2026-11-22 | 30,440 |
| 2026-11-23 | 25,691 |
| 2026-11-24 | 26,488 |
| 2026-11-25 | 27,569 |
| 2026-11-26 | 28,681 |
| 2026-11-27 | 27,858 |
| 2026-11-28 | 109,239 |
| 2026-11-29 | 28,207 |
| 2026-11-30 | 25,573 |
| 2026-12-01 | 26,586 |
| 2026-12-02 | 26,224 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
