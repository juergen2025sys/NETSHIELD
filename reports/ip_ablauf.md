# Seen-DB Expiry Forecast

Lauf: 2026-10-03 17:18 CEST (Europe/Berlin)
Gesamt: 12,159,299 IPs in seen_db.json (9,207,268 aktiv/180-Tage-Pfad, 2,952,031 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 396,765 |
| 8-14 Tage | 1,814,321 |
| 15-30 Tage | 475,634 |
| 31-60 Tage | 1,029,250 |
| 61-90 Tage | 752,946 |
| 91-180 Tage | 4,738,352 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,612,647 |
| 0-3 Tage | 20,562 |
| 4-7 Tage | 32,809 |
| 8-14 Tage | 59,483 |
| 15-30 Tage | 226,530 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-03 | 2,944 |
| 2026-10-04 | 6,824 |
| 2026-10-05 | 2,859 |
| 2026-10-06 | 7,935 |
| 2026-10-07 | 7,895 |
| 2026-10-08 | 7,255 |
| 2026-10-09 | 10,127 |
| 2026-10-10 | 7,532 |
| 2026-10-11 | 6,240 |
| 2026-10-12 | 3,863 |
| 2026-10-13 | 8,257 |
| 2026-10-14 | 7,417 |
| 2026-10-15 | 8,297 |
| 2026-10-16 | 15,470 |
| 2026-10-17 | 9,939 |
| 2026-10-18 | 8,656 |
| 2026-10-19 | 5,150 |
| 2026-10-20 | 9,591 |
| 2026-10-21 | 9,544 |
| 2026-10-22 | 10,396 |
| 2026-10-23 | 12,421 |
| 2026-10-24 | 15,093 |
| 2026-10-25 | 11,116 |
| 2026-10-26 | 9,479 |
| 2026-10-27 | 35,318 |
| 2026-10-28 | 11,306 |
| 2026-10-29 | 9,878 |
| 2026-10-30 | 20,202 |
| 2026-10-31 | 17,173 |
| 2026-11-01 | 15,438 |
| 2026-11-02 | 12,052 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,612,647** IPs. Brutto faellig in den naechsten 30 Tagen: **325,667**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **2,876,314**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-03 | 2,944 | 2,000 |
| 2026-10-04 | 6,824 | 2,000 |
| 2026-10-05 | 2,859 | 2,000 |
| 2026-10-06 | 7,935 | 2,000 |
| 2026-10-07 | 7,895 | 2,000 |
| 2026-10-08 | 7,255 | 2,000 |
| 2026-10-09 | 10,127 | 2,000 |
| 2026-10-10 | 7,532 | 2,000 |
| 2026-10-11 | 6,240 | 2,000 |
| 2026-10-12 | 3,863 | 2,000 |
| 2026-10-13 | 8,257 | 2,000 |
| 2026-10-14 | 7,417 | 2,000 |
| 2026-10-15 | 8,297 | 2,000 |
| 2026-10-16 | 15,470 | 2,000 |
| 2026-10-17 | 9,939 | 2,000 |
| 2026-10-18 | 8,656 | 2,000 |
| 2026-10-19 | 5,150 | 2,000 |
| 2026-10-20 | 9,591 | 2,000 |
| 2026-10-21 | 9,544 | 2,000 |
| 2026-10-22 | 10,396 | 2,000 |
| 2026-10-23 | 12,421 | 2,000 |
| 2026-10-24 | 15,093 | 2,000 |
| 2026-10-25 | 11,116 | 2,000 |
| 2026-10-26 | 9,479 | 2,000 |
| 2026-10-27 | 35,318 | 2,000 |
| 2026-10-28 | 11,306 | 2,000 |
| 2026-10-29 | 9,878 | 2,000 |
| 2026-10-30 | 20,202 | 2,000 |
| 2026-10-31 | 17,173 | 2,000 |
| 2026-11-01 | 15,438 | 2,000 |
| 2026-11-02 | 12,052 | 2,000 |

> Hinweis: Der Rueckstau von 2,876,314 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-04 | 12,537 |
| 2026-10-05 | 17,455 |
| 2026-10-06 | 16,036 |
| 2026-10-07 | 14,972 |
| 2026-10-08 | 61,080 |
| 2026-10-09 | 221,393 |
| 2026-10-10 | 53,292 |
| 2026-10-11 | 16,012 |
| 2026-10-12 | 66,524 |
| 2026-10-13 | 1,582,137 |
| 2026-10-14 | 32,912 |
| 2026-10-15 | 41,299 |
| 2026-10-16 | 51,221 |
| 2026-10-17 | 24,216 |
| 2026-10-18 | 14,225 |
| 2026-10-19 | 22,178 |
| 2026-10-20 | 11,112 |
| 2026-10-21 | 11,073 |
| 2026-10-22 | 30,671 |
| 2026-10-23 | 50,334 |
| 2026-10-24 | 41,654 |
| 2026-10-25 | 21,558 |
| 2026-10-26 | 20,284 |
| 2026-10-27 | 20,611 |
| 2026-10-28 | 15,749 |
| 2026-10-29 | 9,639 |
| 2026-10-30 | 61,807 |
| 2026-10-31 | 88,154 |
| 2026-11-01 | 27,814 |
| 2026-11-02 | 28,771 |
| 2026-11-03 | 29,741 |
| 2026-11-04 | 29,585 |
| 2026-11-05 | 25,241 |
| 2026-11-06 | 36,340 |
| 2026-11-07 | 24,442 |
| 2026-11-08 | 26,095 |
| 2026-11-09 | 25,541 |
| 2026-11-10 | 32,711 |
| 2026-11-11 | 22,355 |
| 2026-11-12 | 20,495 |
| 2026-11-13 | 19,649 |
| 2026-11-14 | 22,967 |
| 2026-11-15 | 17,452 |
| 2026-11-16 | 17,964 |
| 2026-11-17 | 15,254 |
| 2026-11-18 | 19,504 |
| 2026-11-19 | 173,803 |
| 2026-11-20 | 26,168 |
| 2026-11-21 | 61,406 |
| 2026-11-22 | 30,439 |
| 2026-11-23 | 25,689 |
| 2026-11-24 | 26,487 |
| 2026-11-25 | 27,568 |
| 2026-11-26 | 28,681 |
| 2026-11-27 | 27,856 |
| 2026-11-28 | 109,235 |
| 2026-11-29 | 28,205 |
| 2026-11-30 | 25,571 |
| 2026-12-01 | 26,584 |
| 2026-12-02 | 26,222 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
