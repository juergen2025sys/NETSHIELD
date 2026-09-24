# Seen-DB Expiry Forecast

Lauf: 2026-09-24 14:08 CEST (Europe/Berlin)
Gesamt: 11,624,524 IPs in seen_db.json (8,807,134 aktiv/180-Tage-Pfad, 2,817,390 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 101,029 |
| 8-14 Tage | 137,661 |
| 15-30 Tage | 2,274,897 |
| 31-60 Tage | 999,825 |
| 61-90 Tage | 886,874 |
| 91-180 Tage | 4,406,848 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 600,017 |
| 0-3 Tage | 646,789 |
| 4-7 Tage | 68,047 |
| 8-14 Tage | 1,342,926 |
| 15-30 Tage | 159,611 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-24 | 11,370 |
| 2026-09-25 | 5,445 |
| 2026-09-26 | 623,711 |
| 2026-09-27 | 6,263 |
| 2026-09-28 | 772 |
| 2026-09-30 | 59,641 |
| 2026-10-01 | 7,634 |
| 2026-10-02 | 1,306,868 |
| 2026-10-03 | 2,965 |
| 2026-10-04 | 6,913 |
| 2026-10-05 | 2,901 |
| 2026-10-06 | 8,042 |
| 2026-10-07 | 7,950 |
| 2026-10-08 | 7,287 |
| 2026-10-09 | 10,177 |
| 2026-10-10 | 7,578 |
| 2026-10-11 | 6,274 |
| 2026-10-12 | 3,881 |
| 2026-10-13 | 8,324 |
| 2026-10-14 | 7,470 |
| 2026-10-15 | 8,348 |
| 2026-10-16 | 15,531 |
| 2026-10-17 | 9,975 |
| 2026-10-18 | 8,724 |
| 2026-10-19 | 5,188 |
| 2026-10-20 | 9,699 |
| 2026-10-21 | 9,635 |
| 2026-10-22 | 10,536 |
| 2026-10-23 | 12,613 |
| 2026-10-24 | 15,880 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **600,017** IPs. Brutto faellig in den naechsten 30 Tagen: **2,207,595**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,747,612**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-24 | 11,370 | 2,000 |
| 2026-09-25 | 5,445 | 2,000 |
| 2026-09-26 | 623,711 | 2,000 |
| 2026-09-27 | 6,263 | 2,000 |
| 2026-09-28 | 772 | 2,000 |
| 2026-09-30 | 59,641 | 2,000 |
| 2026-10-01 | 7,634 | 2,000 |
| 2026-10-02 | 1,306,868 | 2,000 |
| 2026-10-03 | 2,965 | 2,000 |
| 2026-10-04 | 6,913 | 2,000 |
| 2026-10-05 | 2,901 | 2,000 |
| 2026-10-06 | 8,042 | 2,000 |
| 2026-10-07 | 7,950 | 2,000 |
| 2026-10-08 | 7,287 | 2,000 |
| 2026-10-09 | 10,177 | 2,000 |
| 2026-10-10 | 7,578 | 2,000 |
| 2026-10-11 | 6,274 | 2,000 |
| 2026-10-12 | 3,881 | 2,000 |
| 2026-10-13 | 8,324 | 2,000 |
| 2026-10-14 | 7,470 | 2,000 |
| 2026-10-15 | 8,348 | 2,000 |
| 2026-10-16 | 15,531 | 2,000 |
| 2026-10-17 | 9,975 | 2,000 |
| 2026-10-18 | 8,724 | 2,000 |
| 2026-10-19 | 5,188 | 2,000 |
| 2026-10-20 | 9,699 | 2,000 |
| 2026-10-21 | 9,635 | 2,000 |
| 2026-10-22 | 10,536 | 2,000 |
| 2026-10-23 | 12,613 | 2,000 |
| 2026-10-24 | 15,880 | 2,000 |

> Hinweis: Der Rueckstau von 2,747,612 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-25 | 20,905 |
| 2026-09-26 | 17,423 |
| 2026-09-27 | 15,013 |
| 2026-09-28 | 11,597 |
| 2026-09-29 | 9,343 |
| 2026-09-30 | 10,163 |
| 2026-10-01 | 16,585 |
| 2026-10-02 | 7,712 |
| 2026-10-03 | 7,322 |
| 2026-10-04 | 12,602 |
| 2026-10-05 | 17,524 |
| 2026-10-06 | 16,107 |
| 2026-10-07 | 15,037 |
| 2026-10-08 | 61,357 |
| 2026-10-09 | 222,595 |
| 2026-10-10 | 53,363 |
| 2026-10-11 | 16,046 |
| 2026-10-12 | 66,575 |
| 2026-10-13 | 1,584,686 |
| 2026-10-14 | 32,919 |
| 2026-10-15 | 41,337 |
| 2026-10-16 | 51,301 |
| 2026-10-17 | 24,285 |
| 2026-10-18 | 14,274 |
| 2026-10-19 | 22,351 |
| 2026-10-20 | 11,141 |
| 2026-10-21 | 11,118 |
| 2026-10-22 | 30,749 |
| 2026-10-23 | 50,425 |
| 2026-10-24 | 41,732 |
| 2026-10-25 | 21,629 |
| 2026-10-26 | 20,351 |
| 2026-10-27 | 20,708 |
| 2026-10-28 | 15,812 |
| 2026-10-29 | 9,691 |
| 2026-10-30 | 61,974 |
| 2026-10-31 | 88,256 |
| 2026-11-01 | 27,888 |
| 2026-11-02 | 28,848 |
| 2026-11-03 | 29,856 |
| 2026-11-04 | 29,674 |
| 2026-11-05 | 25,310 |
| 2026-11-06 | 36,454 |
| 2026-11-07 | 24,502 |
| 2026-11-08 | 26,168 |
| 2026-11-09 | 25,602 |
| 2026-11-10 | 32,793 |
| 2026-11-11 | 22,425 |
| 2026-11-12 | 20,543 |
| 2026-11-13 | 19,692 |
| 2026-11-14 | 23,016 |
| 2026-11-15 | 17,494 |
| 2026-11-16 | 18,013 |
| 2026-11-17 | 15,278 |
| 2026-11-18 | 19,544 |
| 2026-11-19 | 174,178 |
| 2026-11-20 | 26,249 |
| 2026-11-21 | 61,581 |
| 2026-11-22 | 30,530 |
| 2026-11-23 | 25,766 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
