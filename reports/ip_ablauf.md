# Seen-DB Expiry Forecast

Lauf: 2026-10-29 00:28 CET (Europe/Berlin)
Gesamt: 11,210,120 IPs in seen_db.json (8,051,173 aktiv/180-Tage-Pfad, 3,158,947 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 274,257 |
| 8-14 Tage | 191,765 |
| 15-30 Tage | 559,157 |
| 31-60 Tage | 854,021 |
| 61-90 Tage | 797,377 |
| 91-180 Tage | 5,374,596 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,816,284 |
| 0-3 Tage | 57,904 |
| 4-7 Tage | 53,740 |
| 8-14 Tage | 83,677 |
| 15-30 Tage | 147,342 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-28 | 11,230 |
| 2026-10-29 | 9,786 |
| 2026-10-30 | 20,013 |
| 2026-10-31 | 16,875 |
| 2026-11-01 | 15,298 |
| 2026-11-02 | 11,860 |
| 2026-11-03 | 16,558 |
| 2026-11-04 | 10,024 |
| 2026-11-05 | 7,202 |
| 2026-11-06 | 12,024 |
| 2026-11-07 | 13,312 |
| 2026-11-08 | 6,235 |
| 2026-11-09 | 11,430 |
| 2026-11-10 | 23,614 |
| 2026-11-11 | 9,860 |
| 2026-11-12 | 8,006 |
| 2026-11-13 | 3,314 |
| 2026-11-14 | 11,567 |
| 2026-11-15 | 14,293 |
| 2026-11-16 | 18,857 |
| 2026-11-17 | 9,308 |
| 2026-11-18 | 3,482 |
| 2026-11-19 | 8,807 |
| 2026-11-20 | 10,887 |
| 2026-11-21 | 9,997 |
| 2026-11-22 | 10,025 |
| 2026-11-23 | 10,068 |
| 2026-11-24 | 10,155 |
| 2026-11-25 | 7,654 |
| 2026-11-26 | 3,376 |
| 2026-11-27 | 3,941 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,816,284** IPs. Brutto faellig in den naechsten 30 Tagen: **339,058**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,093,342**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-28 | 11,230 | 2,000 |
| 2026-10-29 | 9,786 | 2,000 |
| 2026-10-30 | 20,013 | 2,000 |
| 2026-10-31 | 16,875 | 2,000 |
| 2026-11-01 | 15,298 | 2,000 |
| 2026-11-02 | 11,860 | 2,000 |
| 2026-11-03 | 16,558 | 2,000 |
| 2026-11-04 | 10,024 | 2,000 |
| 2026-11-05 | 7,202 | 2,000 |
| 2026-11-06 | 12,024 | 2,000 |
| 2026-11-07 | 13,312 | 2,000 |
| 2026-11-08 | 6,235 | 2,000 |
| 2026-11-09 | 11,430 | 2,000 |
| 2026-11-10 | 23,614 | 2,000 |
| 2026-11-11 | 9,860 | 2,000 |
| 2026-11-12 | 8,006 | 2,000 |
| 2026-11-13 | 3,314 | 2,000 |
| 2026-11-14 | 11,567 | 2,000 |
| 2026-11-15 | 14,293 | 2,000 |
| 2026-11-16 | 18,857 | 2,000 |
| 2026-11-17 | 9,308 | 2,000 |
| 2026-11-18 | 3,482 | 2,000 |
| 2026-11-19 | 8,807 | 2,000 |
| 2026-11-20 | 10,887 | 2,000 |
| 2026-11-21 | 9,997 | 2,000 |
| 2026-11-22 | 10,025 | 2,000 |
| 2026-11-23 | 10,068 | 2,000 |
| 2026-11-24 | 10,155 | 2,000 |
| 2026-11-25 | 7,654 | 2,000 |
| 2026-11-26 | 3,376 | 2,000 |
| 2026-11-27 | 3,941 | 2,000 |

> Hinweis: Der Rueckstau von 3,093,342 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-29 | 9,468 |
| 2026-10-30 | 61,486 |
| 2026-10-31 | 87,990 |
| 2026-11-01 | 27,689 |
| 2026-11-02 | 28,628 |
| 2026-11-03 | 29,570 |
| 2026-11-04 | 29,426 |
| 2026-11-05 | 25,118 |
| 2026-11-06 | 36,148 |
| 2026-11-07 | 24,315 |
| 2026-11-08 | 25,989 |
| 2026-11-09 | 25,405 |
| 2026-11-10 | 32,560 |
| 2026-11-11 | 22,230 |
| 2026-11-12 | 20,412 |
| 2026-11-13 | 19,553 |
| 2026-11-14 | 22,854 |
| 2026-11-15 | 17,386 |
| 2026-11-16 | 17,868 |
| 2026-11-17 | 15,167 |
| 2026-11-18 | 19,420 |
| 2026-11-19 | 173,331 |
| 2026-11-20 | 26,035 |
| 2026-11-21 | 61,184 |
| 2026-11-22 | 30,292 |
| 2026-11-23 | 25,550 |
| 2026-11-24 | 26,368 |
| 2026-11-25 | 27,410 |
| 2026-11-26 | 28,571 |
| 2026-11-27 | 27,756 |
| 2026-11-28 | 109,068 |
| 2026-11-29 | 28,094 |
| 2026-11-30 | 25,449 |
| 2026-12-01 | 26,467 |
| 2026-12-02 | 26,110 |
| 2026-12-03 | 25,931 |
| 2026-12-04 | 27,849 |
| 2026-12-05 | 25,884 |
| 2026-12-06 | 30,060 |
| 2026-12-07 | 23,682 |
| 2026-12-08 | 39,297 |
| 2026-12-09 | 54,914 |
| 2026-12-10 | 25,030 |
| 2026-12-11 | 27,706 |
| 2026-12-12 | 24,326 |
| 2026-12-13 | 23,798 |
| 2026-12-14 | 23,414 |
| 2026-12-15 | 26,185 |
| 2026-12-16 | 16,594 |
| 2026-12-17 | 24,963 |
| 2026-12-18 | 22,459 |
| 2026-12-19 | 25,555 |
| 2026-12-20 | 14,289 |
| 2026-12-21 | 27,302 |
| 2026-12-22 | 24,070 |
| 2026-12-23 | 21,100 |
| 2026-12-24 | 20,382 |
| 2026-12-25 | 21,594 |
| 2026-12-26 | 17,807 |
| 2026-12-27 | 24,642 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
