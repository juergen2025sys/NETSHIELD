# Seen-DB Expiry Forecast

Lauf: 2026-10-23 13:27 CEST (Europe/Berlin)
Gesamt: 11,103,995 IPs in seen_db.json (7,974,439 aktiv/180-Tage-Pfad, 3,129,556 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 190,040 |
| 8-14 Tage | 264,725 |
| 15-30 Tage | 554,311 |
| 31-60 Tage | 884,860 |
| 61-90 Tage | 718,186 |
| 91-180 Tage | 5,362,317 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,734,803 |
| 0-3 Tage | 47,740 |
| 4-7 Tage | 76,116 |
| 8-14 Tage | 89,919 |
| 15-30 Tage | 180,978 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-23 | 12,317 |
| 2026-10-24 | 14,982 |
| 2026-10-25 | 11,044 |
| 2026-10-26 | 9,397 |
| 2026-10-27 | 35,045 |
| 2026-10-28 | 11,240 |
| 2026-10-29 | 9,796 |
| 2026-10-30 | 20,035 |
| 2026-10-31 | 16,888 |
| 2026-11-01 | 15,307 |
| 2026-11-02 | 11,866 |
| 2026-11-03 | 16,574 |
| 2026-11-04 | 10,034 |
| 2026-11-05 | 7,211 |
| 2026-11-06 | 12,039 |
| 2026-11-07 | 13,326 |
| 2026-11-08 | 6,250 |
| 2026-11-09 | 11,449 |
| 2026-11-10 | 23,788 |
| 2026-11-11 | 9,875 |
| 2026-11-12 | 8,024 |
| 2026-11-13 | 3,324 |
| 2026-11-14 | 11,591 |
| 2026-11-15 | 14,316 |
| 2026-11-16 | 18,901 |
| 2026-11-17 | 9,333 |
| 2026-11-18 | 3,503 |
| 2026-11-19 | 8,852 |
| 2026-11-20 | 10,942 |
| 2026-11-21 | 10,087 |
| 2026-11-22 | 10,102 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,734,803** IPs. Brutto faellig in den naechsten 30 Tagen: **387,438**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,060,241**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-23 | 12,317 | 2,000 |
| 2026-10-24 | 14,982 | 2,000 |
| 2026-10-25 | 11,044 | 2,000 |
| 2026-10-26 | 9,397 | 2,000 |
| 2026-10-27 | 35,045 | 2,000 |
| 2026-10-28 | 11,240 | 2,000 |
| 2026-10-29 | 9,796 | 2,000 |
| 2026-10-30 | 20,035 | 2,000 |
| 2026-10-31 | 16,888 | 2,000 |
| 2026-11-01 | 15,307 | 2,000 |
| 2026-11-02 | 11,866 | 2,000 |
| 2026-11-03 | 16,574 | 2,000 |
| 2026-11-04 | 10,034 | 2,000 |
| 2026-11-05 | 7,211 | 2,000 |
| 2026-11-06 | 12,039 | 2,000 |
| 2026-11-07 | 13,326 | 2,000 |
| 2026-11-08 | 6,250 | 2,000 |
| 2026-11-09 | 11,449 | 2,000 |
| 2026-11-10 | 23,788 | 2,000 |
| 2026-11-11 | 9,875 | 2,000 |
| 2026-11-12 | 8,024 | 2,000 |
| 2026-11-13 | 3,324 | 2,000 |
| 2026-11-14 | 11,591 | 2,000 |
| 2026-11-15 | 14,316 | 2,000 |
| 2026-11-16 | 18,901 | 2,000 |
| 2026-11-17 | 9,333 | 2,000 |
| 2026-11-18 | 3,503 | 2,000 |
| 2026-11-19 | 8,852 | 2,000 |
| 2026-11-20 | 10,942 | 2,000 |
| 2026-11-21 | 10,087 | 2,000 |
| 2026-11-22 | 10,102 | 2,000 |

> Hinweis: Der Rueckstau von 3,060,241 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-24 | 41,539 |
| 2026-10-25 | 21,456 |
| 2026-10-26 | 20,160 |
| 2026-10-27 | 20,379 |
| 2026-10-28 | 15,486 |
| 2026-10-29 | 9,484 |
| 2026-10-30 | 61,536 |
| 2026-10-31 | 88,011 |
| 2026-11-01 | 27,703 |
| 2026-11-02 | 28,649 |
| 2026-11-03 | 29,593 |
| 2026-11-04 | 29,452 |
| 2026-11-05 | 25,135 |
| 2026-11-06 | 36,182 |
| 2026-11-07 | 24,333 |
| 2026-11-08 | 25,999 |
| 2026-11-09 | 25,421 |
| 2026-11-10 | 32,579 |
| 2026-11-11 | 22,251 |
| 2026-11-12 | 20,429 |
| 2026-11-13 | 19,574 |
| 2026-11-14 | 22,865 |
| 2026-11-15 | 17,396 |
| 2026-11-16 | 17,884 |
| 2026-11-17 | 15,178 |
| 2026-11-18 | 19,430 |
| 2026-11-19 | 173,384 |
| 2026-11-20 | 26,055 |
| 2026-11-21 | 61,215 |
| 2026-11-22 | 30,318 |
| 2026-11-23 | 25,576 |
| 2026-11-24 | 26,390 |
| 2026-11-25 | 27,439 |
| 2026-11-26 | 28,586 |
| 2026-11-27 | 27,774 |
| 2026-11-28 | 109,099 |
| 2026-11-29 | 28,107 |
| 2026-11-30 | 25,466 |
| 2026-12-01 | 26,479 |
| 2026-12-02 | 26,124 |
| 2026-12-03 | 25,947 |
| 2026-12-04 | 27,864 |
| 2026-12-05 | 25,905 |
| 2026-12-06 | 30,076 |
| 2026-12-07 | 23,692 |
| 2026-12-08 | 39,317 |
| 2026-12-09 | 54,995 |
| 2026-12-10 | 25,051 |
| 2026-12-11 | 27,728 |
| 2026-12-12 | 24,350 |
| 2026-12-13 | 23,822 |
| 2026-12-14 | 23,439 |
| 2026-12-15 | 26,215 |
| 2026-12-16 | 16,625 |
| 2026-12-17 | 24,985 |
| 2026-12-18 | 22,491 |
| 2026-12-19 | 25,581 |
| 2026-12-20 | 14,307 |
| 2026-12-21 | 27,326 |
| 2026-12-22 | 24,104 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
