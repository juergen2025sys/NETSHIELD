# Seen-DB Expiry Forecast

Lauf: 2026-10-29 10:46 CET (Europe/Berlin)
Gesamt: 11,214,240 IPs in seen_db.json (8,050,130 aktiv/180-Tage-Pfad, 3,164,110 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 289,893 |
| 8-14 Tage | 187,050 |
| 15-30 Tage | 647,791 |
| 31-60 Tage | 766,658 |
| 61-90 Tage | 822,586 |
| 91-180 Tage | 5,336,152 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,827,423 |
| 0-3 Tage | 61,966 |
| 4-7 Tage | 45,638 |
| 8-14 Tage | 84,471 |
| 15-30 Tage | 144,612 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-29 | 9,786 |
| 2026-10-30 | 20,010 |
| 2026-10-31 | 16,873 |
| 2026-11-01 | 15,297 |
| 2026-11-02 | 11,856 |
| 2026-11-03 | 16,558 |
| 2026-11-04 | 10,022 |
| 2026-11-05 | 7,202 |
| 2026-11-06 | 12,024 |
| 2026-11-07 | 13,312 |
| 2026-11-08 | 6,234 |
| 2026-11-09 | 11,430 |
| 2026-11-10 | 23,612 |
| 2026-11-11 | 9,857 |
| 2026-11-12 | 8,002 |
| 2026-11-13 | 3,314 |
| 2026-11-14 | 11,565 |
| 2026-11-15 | 14,293 |
| 2026-11-16 | 18,850 |
| 2026-11-17 | 9,308 |
| 2026-11-18 | 3,482 |
| 2026-11-19 | 8,804 |
| 2026-11-20 | 10,886 |
| 2026-11-21 | 9,991 |
| 2026-11-22 | 10,023 |
| 2026-11-23 | 10,065 |
| 2026-11-24 | 10,149 |
| 2026-11-25 | 7,651 |
| 2026-11-26 | 3,373 |
| 2026-11-27 | 3,932 |
| 2026-11-28 | 3,596 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,827,423** IPs. Brutto faellig in den naechsten 30 Tagen: **331,357**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,096,780**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-29 | 9,786 | 2,000 |
| 2026-10-30 | 20,010 | 2,000 |
| 2026-10-31 | 16,873 | 2,000 |
| 2026-11-01 | 15,297 | 2,000 |
| 2026-11-02 | 11,856 | 2,000 |
| 2026-11-03 | 16,558 | 2,000 |
| 2026-11-04 | 10,022 | 2,000 |
| 2026-11-05 | 7,202 | 2,000 |
| 2026-11-06 | 12,024 | 2,000 |
| 2026-11-07 | 13,312 | 2,000 |
| 2026-11-08 | 6,234 | 2,000 |
| 2026-11-09 | 11,430 | 2,000 |
| 2026-11-10 | 23,612 | 2,000 |
| 2026-11-11 | 9,857 | 2,000 |
| 2026-11-12 | 8,002 | 2,000 |
| 2026-11-13 | 3,314 | 2,000 |
| 2026-11-14 | 11,565 | 2,000 |
| 2026-11-15 | 14,293 | 2,000 |
| 2026-11-16 | 18,850 | 2,000 |
| 2026-11-17 | 9,308 | 2,000 |
| 2026-11-18 | 3,482 | 2,000 |
| 2026-11-19 | 8,804 | 2,000 |
| 2026-11-20 | 10,886 | 2,000 |
| 2026-11-21 | 9,991 | 2,000 |
| 2026-11-22 | 10,023 | 2,000 |
| 2026-11-23 | 10,065 | 2,000 |
| 2026-11-24 | 10,149 | 2,000 |
| 2026-11-25 | 7,651 | 2,000 |
| 2026-11-26 | 3,373 | 2,000 |
| 2026-11-27 | 3,932 | 2,000 |
| 2026-11-28 | 3,596 | 2,000 |

> Hinweis: Der Rueckstau von 3,096,780 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-30 | 61,483 |
| 2026-10-31 | 87,987 |
| 2026-11-01 | 27,687 |
| 2026-11-02 | 28,626 |
| 2026-11-03 | 29,567 |
| 2026-11-04 | 29,426 |
| 2026-11-05 | 25,117 |
| 2026-11-06 | 36,146 |
| 2026-11-07 | 24,315 |
| 2026-11-08 | 25,988 |
| 2026-11-09 | 25,402 |
| 2026-11-10 | 32,559 |
| 2026-11-11 | 22,229 |
| 2026-11-12 | 20,411 |
| 2026-11-13 | 19,550 |
| 2026-11-14 | 22,852 |
| 2026-11-15 | 17,386 |
| 2026-11-16 | 17,868 |
| 2026-11-17 | 15,167 |
| 2026-11-18 | 19,418 |
| 2026-11-19 | 173,329 |
| 2026-11-20 | 26,032 |
| 2026-11-21 | 61,182 |
| 2026-11-22 | 30,290 |
| 2026-11-23 | 25,550 |
| 2026-11-24 | 26,368 |
| 2026-11-25 | 27,408 |
| 2026-11-26 | 28,571 |
| 2026-11-27 | 27,754 |
| 2026-11-28 | 109,066 |
| 2026-11-29 | 28,093 |
| 2026-11-30 | 25,449 |
| 2026-12-01 | 26,466 |
| 2026-12-02 | 26,110 |
| 2026-12-03 | 25,929 |
| 2026-12-04 | 27,847 |
| 2026-12-05 | 25,884 |
| 2026-12-06 | 30,060 |
| 2026-12-07 | 23,682 |
| 2026-12-08 | 39,296 |
| 2026-12-09 | 54,910 |
| 2026-12-10 | 25,029 |
| 2026-12-11 | 27,706 |
| 2026-12-12 | 24,326 |
| 2026-12-13 | 23,797 |
| 2026-12-14 | 23,412 |
| 2026-12-15 | 26,185 |
| 2026-12-16 | 16,592 |
| 2026-12-17 | 24,963 |
| 2026-12-18 | 22,459 |
| 2026-12-19 | 25,555 |
| 2026-12-20 | 14,288 |
| 2026-12-21 | 27,302 |
| 2026-12-22 | 24,068 |
| 2026-12-23 | 21,098 |
| 2026-12-24 | 20,381 |
| 2026-12-25 | 21,594 |
| 2026-12-26 | 17,803 |
| 2026-12-27 | 24,641 |
| 2026-12-28 | 21,733 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
