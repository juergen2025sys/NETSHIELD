# Seen-DB Expiry Forecast

Lauf: 2026-10-28 07:12 CET (Europe/Berlin)
Gesamt: 11,187,789 IPs in seen_db.json (8,030,863 aktiv/180-Tage-Pfad, 3,156,926 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 274,281 |
| 8-14 Tage | 191,782 |
| 15-30 Tage | 559,197 |
| 31-60 Tage | 854,095 |
| 61-90 Tage | 797,462 |
| 91-180 Tage | 5,354,046 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,816,439 |
| 0-3 Tage | 57,908 |
| 4-7 Tage | 53,746 |
| 8-14 Tage | 83,693 |
| 15-30 Tage | 145,140 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-28 | 11,231 |
| 2026-10-29 | 9,786 |
| 2026-10-30 | 20,014 |
| 2026-10-31 | 16,877 |
| 2026-11-01 | 15,298 |
| 2026-11-02 | 11,861 |
| 2026-11-03 | 16,562 |
| 2026-11-04 | 10,025 |
| 2026-11-05 | 7,204 |
| 2026-11-06 | 12,027 |
| 2026-11-07 | 13,314 |
| 2026-11-08 | 6,236 |
| 2026-11-09 | 11,436 |
| 2026-11-10 | 23,615 |
| 2026-11-11 | 9,861 |
| 2026-11-12 | 8,008 |
| 2026-11-13 | 3,314 |
| 2026-11-14 | 11,569 |
| 2026-11-15 | 14,297 |
| 2026-11-16 | 18,866 |
| 2026-11-17 | 9,311 |
| 2026-11-18 | 3,484 |
| 2026-11-19 | 8,812 |
| 2026-11-20 | 10,892 |
| 2026-11-21 | 9,998 |
| 2026-11-22 | 10,031 |
| 2026-11-23 | 10,073 |
| 2026-11-24 | 10,167 |
| 2026-11-25 | 7,657 |
| 2026-11-26 | 3,382 |
| 2026-11-27 | 3,956 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,816,439** IPs. Brutto faellig in den naechsten 30 Tagen: **339,164**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,093,603**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-28 | 11,231 | 2,000 |
| 2026-10-29 | 9,786 | 2,000 |
| 2026-10-30 | 20,014 | 2,000 |
| 2026-10-31 | 16,877 | 2,000 |
| 2026-11-01 | 15,298 | 2,000 |
| 2026-11-02 | 11,861 | 2,000 |
| 2026-11-03 | 16,562 | 2,000 |
| 2026-11-04 | 10,025 | 2,000 |
| 2026-11-05 | 7,204 | 2,000 |
| 2026-11-06 | 12,027 | 2,000 |
| 2026-11-07 | 13,314 | 2,000 |
| 2026-11-08 | 6,236 | 2,000 |
| 2026-11-09 | 11,436 | 2,000 |
| 2026-11-10 | 23,615 | 2,000 |
| 2026-11-11 | 9,861 | 2,000 |
| 2026-11-12 | 8,008 | 2,000 |
| 2026-11-13 | 3,314 | 2,000 |
| 2026-11-14 | 11,569 | 2,000 |
| 2026-11-15 | 14,297 | 2,000 |
| 2026-11-16 | 18,866 | 2,000 |
| 2026-11-17 | 9,311 | 2,000 |
| 2026-11-18 | 3,484 | 2,000 |
| 2026-11-19 | 8,812 | 2,000 |
| 2026-11-20 | 10,892 | 2,000 |
| 2026-11-21 | 9,998 | 2,000 |
| 2026-11-22 | 10,031 | 2,000 |
| 2026-11-23 | 10,073 | 2,000 |
| 2026-11-24 | 10,167 | 2,000 |
| 2026-11-25 | 7,657 | 2,000 |
| 2026-11-26 | 3,382 | 2,000 |
| 2026-11-27 | 3,956 | 2,000 |

> Hinweis: Der Rueckstau von 3,093,603 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-29 | 9,472 |
| 2026-10-30 | 61,492 |
| 2026-10-31 | 87,993 |
| 2026-11-01 | 27,690 |
| 2026-11-02 | 28,631 |
| 2026-11-03 | 29,570 |
| 2026-11-04 | 29,433 |
| 2026-11-05 | 25,120 |
| 2026-11-06 | 36,154 |
| 2026-11-07 | 24,316 |
| 2026-11-08 | 25,989 |
| 2026-11-09 | 25,407 |
| 2026-11-10 | 32,563 |
| 2026-11-11 | 22,233 |
| 2026-11-12 | 20,414 |
| 2026-11-13 | 19,559 |
| 2026-11-14 | 22,856 |
| 2026-11-15 | 17,387 |
| 2026-11-16 | 17,870 |
| 2026-11-17 | 15,172 |
| 2026-11-18 | 19,420 |
| 2026-11-19 | 173,339 |
| 2026-11-20 | 26,036 |
| 2026-11-21 | 61,187 |
| 2026-11-22 | 30,293 |
| 2026-11-23 | 25,552 |
| 2026-11-24 | 26,369 |
| 2026-11-25 | 27,410 |
| 2026-11-26 | 28,573 |
| 2026-11-27 | 27,760 |
| 2026-11-28 | 109,074 |
| 2026-11-29 | 28,098 |
| 2026-11-30 | 25,449 |
| 2026-12-01 | 26,470 |
| 2026-12-02 | 26,110 |
| 2026-12-03 | 25,932 |
| 2026-12-04 | 27,852 |
| 2026-12-05 | 25,885 |
| 2026-12-06 | 30,061 |
| 2026-12-07 | 23,683 |
| 2026-12-08 | 39,299 |
| 2026-12-09 | 54,924 |
| 2026-12-10 | 25,032 |
| 2026-12-11 | 27,708 |
| 2026-12-12 | 24,330 |
| 2026-12-13 | 23,799 |
| 2026-12-14 | 23,418 |
| 2026-12-15 | 26,189 |
| 2026-12-16 | 16,596 |
| 2026-12-17 | 24,965 |
| 2026-12-18 | 22,460 |
| 2026-12-19 | 25,555 |
| 2026-12-20 | 14,291 |
| 2026-12-21 | 27,306 |
| 2026-12-22 | 24,072 |
| 2026-12-23 | 21,103 |
| 2026-12-24 | 20,387 |
| 2026-12-25 | 21,594 |
| 2026-12-26 | 17,807 |
| 2026-12-27 | 24,646 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
