# Seen-DB Expiry Forecast

Lauf: 2026-09-23 16:25 CEST (Europe/Berlin)
Gesamt: 11,594,263 IPs in seen_db.json (8,791,808 aktiv/180-Tage-Pfad, 2,802,455 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 101,102 |
| 8-14 Tage | 92,931 |
| 15-30 Tage | 2,294,923 |
| 31-60 Tage | 1,016,315 |
| 61-90 Tage | 891,605 |
| 91-180 Tage | 4,394,932 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 595,121 |
| 0-3 Tage | 645,683 |
| 4-7 Tage | 66,705 |
| 8-14 Tage | 1,343,377 |
| 15-30 Tage | 151,569 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-23 | 5,104 |
| 2026-09-24 | 11,377 |
| 2026-09-25 | 5,446 |
| 2026-09-26 | 623,756 |
| 2026-09-27 | 6,275 |
| 2026-09-28 | 773 |
| 2026-09-30 | 59,657 |
| 2026-10-01 | 7,641 |
| 2026-10-02 | 1,306,945 |
| 2026-10-03 | 2,970 |
| 2026-10-04 | 6,917 |
| 2026-10-05 | 2,903 |
| 2026-10-06 | 8,045 |
| 2026-10-07 | 7,956 |
| 2026-10-08 | 7,295 |
| 2026-10-09 | 10,185 |
| 2026-10-10 | 7,583 |
| 2026-10-11 | 6,278 |
| 2026-10-12 | 3,884 |
| 2026-10-13 | 8,330 |
| 2026-10-14 | 7,479 |
| 2026-10-15 | 8,353 |
| 2026-10-16 | 15,540 |
| 2026-10-17 | 9,982 |
| 2026-10-18 | 8,737 |
| 2026-10-19 | 5,191 |
| 2026-10-20 | 9,711 |
| 2026-10-21 | 9,657 |
| 2026-10-22 | 10,614 |
| 2026-10-23 | 12,713 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **595,121** IPs. Brutto faellig in den naechsten 30 Tagen: **2,197,297**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,732,418**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-23 | 5,104 | 2,000 |
| 2026-09-24 | 11,377 | 2,000 |
| 2026-09-25 | 5,446 | 2,000 |
| 2026-09-26 | 623,756 | 2,000 |
| 2026-09-27 | 6,275 | 2,000 |
| 2026-09-28 | 773 | 2,000 |
| 2026-09-30 | 59,657 | 2,000 |
| 2026-10-01 | 7,641 | 2,000 |
| 2026-10-02 | 1,306,945 | 2,000 |
| 2026-10-03 | 2,970 | 2,000 |
| 2026-10-04 | 6,917 | 2,000 |
| 2026-10-05 | 2,903 | 2,000 |
| 2026-10-06 | 8,045 | 2,000 |
| 2026-10-07 | 7,956 | 2,000 |
| 2026-10-08 | 7,295 | 2,000 |
| 2026-10-09 | 10,185 | 2,000 |
| 2026-10-10 | 7,583 | 2,000 |
| 2026-10-11 | 6,278 | 2,000 |
| 2026-10-12 | 3,884 | 2,000 |
| 2026-10-13 | 8,330 | 2,000 |
| 2026-10-14 | 7,479 | 2,000 |
| 2026-10-15 | 8,353 | 2,000 |
| 2026-10-16 | 15,540 | 2,000 |
| 2026-10-17 | 9,982 | 2,000 |
| 2026-10-18 | 8,737 | 2,000 |
| 2026-10-19 | 5,191 | 2,000 |
| 2026-10-20 | 9,711 | 2,000 |
| 2026-10-21 | 9,657 | 2,000 |
| 2026-10-22 | 10,614 | 2,000 |
| 2026-10-23 | 12,713 | 2,000 |

> Hinweis: Der Rueckstau von 2,732,418 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-24 | 16,629 |
| 2026-09-25 | 20,912 |
| 2026-09-26 | 17,428 |
| 2026-09-27 | 15,017 |
| 2026-09-28 | 11,601 |
| 2026-09-29 | 9,348 |
| 2026-09-30 | 10,167 |
| 2026-10-01 | 16,592 |
| 2026-10-02 | 7,714 |
| 2026-10-03 | 7,322 |
| 2026-10-04 | 12,615 |
| 2026-10-05 | 17,532 |
| 2026-10-06 | 16,116 |
| 2026-10-07 | 15,040 |
| 2026-10-08 | 61,371 |
| 2026-10-09 | 222,716 |
| 2026-10-10 | 53,367 |
| 2026-10-11 | 16,051 |
| 2026-10-12 | 66,582 |
| 2026-10-13 | 1,584,878 |
| 2026-10-14 | 32,920 |
| 2026-10-15 | 41,341 |
| 2026-10-16 | 51,310 |
| 2026-10-17 | 24,295 |
| 2026-10-18 | 14,275 |
| 2026-10-19 | 22,360 |
| 2026-10-20 | 11,146 |
| 2026-10-21 | 11,124 |
| 2026-10-22 | 30,755 |
| 2026-10-23 | 50,432 |
| 2026-10-24 | 41,743 |
| 2026-10-25 | 21,633 |
| 2026-10-26 | 20,358 |
| 2026-10-27 | 20,714 |
| 2026-10-28 | 15,817 |
| 2026-10-29 | 9,695 |
| 2026-10-30 | 61,985 |
| 2026-10-31 | 88,260 |
| 2026-11-01 | 27,895 |
| 2026-11-02 | 28,858 |
| 2026-11-03 | 29,867 |
| 2026-11-04 | 29,686 |
| 2026-11-05 | 25,322 |
| 2026-11-06 | 36,736 |
| 2026-11-07 | 24,511 |
| 2026-11-08 | 26,180 |
| 2026-11-09 | 25,604 |
| 2026-11-10 | 32,799 |
| 2026-11-11 | 22,432 |
| 2026-11-12 | 20,548 |
| 2026-11-13 | 19,694 |
| 2026-11-14 | 23,025 |
| 2026-11-15 | 17,502 |
| 2026-11-16 | 18,021 |
| 2026-11-17 | 15,281 |
| 2026-11-18 | 19,547 |
| 2026-11-19 | 174,214 |
| 2026-11-20 | 26,258 |
| 2026-11-21 | 61,592 |
| 2026-11-22 | 30,538 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
