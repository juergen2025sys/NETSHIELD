# Seen-DB Expiry Forecast

Lauf: 2026-10-27 11:54 CET (Europe/Berlin)
Gesamt: 11,180,389 IPs in seen_db.json (8,025,162 aktiv/180-Tage-Pfad, 3,155,227 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 260,333 |
| 8-14 Tage | 199,005 |
| 15-30 Tage | 553,710 |
| 31-60 Tage | 857,328 |
| 61-90 Tage | 758,652 |
| 91-180 Tage | 5,396,134 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,781,708 |
| 0-3 Tage | 76,033 |
| 4-7 Tage | 60,608 |
| 8-14 Tage | 83,871 |
| 15-30 Tage | 153,007 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-27 | 34,997 |
| 2026-10-28 | 11,232 |
| 2026-10-29 | 9,788 |
| 2026-10-30 | 20,016 |
| 2026-10-31 | 16,879 |
| 2026-11-01 | 15,302 |
| 2026-11-02 | 11,862 |
| 2026-11-03 | 16,565 |
| 2026-11-04 | 10,025 |
| 2026-11-05 | 7,204 |
| 2026-11-06 | 12,029 |
| 2026-11-07 | 13,318 |
| 2026-11-08 | 6,239 |
| 2026-11-09 | 11,437 |
| 2026-11-10 | 23,619 |
| 2026-11-11 | 9,863 |
| 2026-11-12 | 8,012 |
| 2026-11-13 | 3,316 |
| 2026-11-14 | 11,573 |
| 2026-11-15 | 14,301 |
| 2026-11-16 | 18,872 |
| 2026-11-17 | 9,313 |
| 2026-11-18 | 3,486 |
| 2026-11-19 | 8,818 |
| 2026-11-20 | 10,899 |
| 2026-11-21 | 10,008 |
| 2026-11-22 | 10,036 |
| 2026-11-23 | 10,085 |
| 2026-11-24 | 10,175 |
| 2026-11-25 | 7,665 |
| 2026-11-26 | 3,395 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,781,708** IPs. Brutto faellig in den naechsten 30 Tagen: **370,329**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,090,037**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-27 | 34,997 | 2,000 |
| 2026-10-28 | 11,232 | 2,000 |
| 2026-10-29 | 9,788 | 2,000 |
| 2026-10-30 | 20,016 | 2,000 |
| 2026-10-31 | 16,879 | 2,000 |
| 2026-11-01 | 15,302 | 2,000 |
| 2026-11-02 | 11,862 | 2,000 |
| 2026-11-03 | 16,565 | 2,000 |
| 2026-11-04 | 10,025 | 2,000 |
| 2026-11-05 | 7,204 | 2,000 |
| 2026-11-06 | 12,029 | 2,000 |
| 2026-11-07 | 13,318 | 2,000 |
| 2026-11-08 | 6,239 | 2,000 |
| 2026-11-09 | 11,437 | 2,000 |
| 2026-11-10 | 23,619 | 2,000 |
| 2026-11-11 | 9,863 | 2,000 |
| 2026-11-12 | 8,012 | 2,000 |
| 2026-11-13 | 3,316 | 2,000 |
| 2026-11-14 | 11,573 | 2,000 |
| 2026-11-15 | 14,301 | 2,000 |
| 2026-11-16 | 18,872 | 2,000 |
| 2026-11-17 | 9,313 | 2,000 |
| 2026-11-18 | 3,486 | 2,000 |
| 2026-11-19 | 8,818 | 2,000 |
| 2026-11-20 | 10,899 | 2,000 |
| 2026-11-21 | 10,008 | 2,000 |
| 2026-11-22 | 10,036 | 2,000 |
| 2026-11-23 | 10,085 | 2,000 |
| 2026-11-24 | 10,175 | 2,000 |
| 2026-11-25 | 7,665 | 2,000 |
| 2026-11-26 | 3,395 | 2,000 |

> Hinweis: Der Rueckstau von 3,090,037 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-28 | 15,462 |
| 2026-10-29 | 9,474 |
| 2026-10-30 | 61,498 |
| 2026-10-31 | 87,995 |
| 2026-11-01 | 27,694 |
| 2026-11-02 | 28,634 |
| 2026-11-03 | 29,576 |
| 2026-11-04 | 29,435 |
| 2026-11-05 | 25,124 |
| 2026-11-06 | 36,157 |
| 2026-11-07 | 24,320 |
| 2026-11-08 | 25,991 |
| 2026-11-09 | 25,410 |
| 2026-11-10 | 32,568 |
| 2026-11-11 | 22,236 |
| 2026-11-12 | 20,417 |
| 2026-11-13 | 19,559 |
| 2026-11-14 | 22,857 |
| 2026-11-15 | 17,389 |
| 2026-11-16 | 17,871 |
| 2026-11-17 | 15,173 |
| 2026-11-18 | 19,420 |
| 2026-11-19 | 173,345 |
| 2026-11-20 | 26,039 |
| 2026-11-21 | 61,193 |
| 2026-11-22 | 30,295 |
| 2026-11-23 | 25,556 |
| 2026-11-24 | 26,371 |
| 2026-11-25 | 27,414 |
| 2026-11-26 | 28,575 |
| 2026-11-27 | 27,762 |
| 2026-11-28 | 109,079 |
| 2026-11-29 | 28,099 |
| 2026-11-30 | 25,452 |
| 2026-12-01 | 26,471 |
| 2026-12-02 | 26,112 |
| 2026-12-03 | 25,933 |
| 2026-12-04 | 27,855 |
| 2026-12-05 | 25,892 |
| 2026-12-06 | 30,063 |
| 2026-12-07 | 23,684 |
| 2026-12-08 | 39,301 |
| 2026-12-09 | 54,940 |
| 2026-12-10 | 25,038 |
| 2026-12-11 | 27,711 |
| 2026-12-12 | 24,333 |
| 2026-12-13 | 23,803 |
| 2026-12-14 | 23,425 |
| 2026-12-15 | 26,190 |
| 2026-12-16 | 16,603 |
| 2026-12-17 | 24,966 |
| 2026-12-18 | 22,465 |
| 2026-12-19 | 25,560 |
| 2026-12-20 | 14,294 |
| 2026-12-21 | 27,312 |
| 2026-12-22 | 24,080 |
| 2026-12-23 | 21,105 |
| 2026-12-24 | 20,389 |
| 2026-12-25 | 21,595 |
| 2026-12-26 | 17,816 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
