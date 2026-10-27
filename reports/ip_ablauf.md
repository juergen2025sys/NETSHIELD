# Seen-DB Expiry Forecast

Lauf: 2026-10-27 01:21 CET (Europe/Berlin)
Gesamt: 11,184,824 IPs in seen_db.json (8,032,589 aktiv/180-Tage-Pfad, 3,152,235 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 280,706 |
| 8-14 Tage | 199,022 |
| 15-30 Tage | 553,736 |
| 31-60 Tage | 857,388 |
| 61-90 Tage | 758,707 |
| 91-180 Tage | 5,383,030 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,781,796 |
| 0-3 Tage | 76,062 |
| 4-7 Tage | 60,613 |
| 8-14 Tage | 83,879 |
| 15-30 Tage | 149,885 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-27 | 35,019 |
| 2026-10-28 | 11,234 |
| 2026-10-29 | 9,789 |
| 2026-10-30 | 20,020 |
| 2026-10-31 | 16,882 |
| 2026-11-01 | 15,302 |
| 2026-11-02 | 11,862 |
| 2026-11-03 | 16,567 |
| 2026-11-04 | 10,026 |
| 2026-11-05 | 7,206 |
| 2026-11-06 | 12,031 |
| 2026-11-07 | 13,318 |
| 2026-11-08 | 6,240 |
| 2026-11-09 | 11,438 |
| 2026-11-10 | 23,620 |
| 2026-11-11 | 9,863 |
| 2026-11-12 | 8,014 |
| 2026-11-13 | 3,317 |
| 2026-11-14 | 11,575 |
| 2026-11-15 | 14,304 |
| 2026-11-16 | 18,875 |
| 2026-11-17 | 9,317 |
| 2026-11-18 | 3,488 |
| 2026-11-19 | 8,820 |
| 2026-11-20 | 10,905 |
| 2026-11-21 | 10,011 |
| 2026-11-22 | 10,041 |
| 2026-11-23 | 10,091 |
| 2026-11-24 | 10,179 |
| 2026-11-25 | 7,674 |
| 2026-11-26 | 3,411 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,781,796** IPs. Brutto faellig in den naechsten 30 Tagen: **370,439**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,090,235**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-27 | 35,019 | 2,000 |
| 2026-10-28 | 11,234 | 2,000 |
| 2026-10-29 | 9,789 | 2,000 |
| 2026-10-30 | 20,020 | 2,000 |
| 2026-10-31 | 16,882 | 2,000 |
| 2026-11-01 | 15,302 | 2,000 |
| 2026-11-02 | 11,862 | 2,000 |
| 2026-11-03 | 16,567 | 2,000 |
| 2026-11-04 | 10,026 | 2,000 |
| 2026-11-05 | 7,206 | 2,000 |
| 2026-11-06 | 12,031 | 2,000 |
| 2026-11-07 | 13,318 | 2,000 |
| 2026-11-08 | 6,240 | 2,000 |
| 2026-11-09 | 11,438 | 2,000 |
| 2026-11-10 | 23,620 | 2,000 |
| 2026-11-11 | 9,863 | 2,000 |
| 2026-11-12 | 8,014 | 2,000 |
| 2026-11-13 | 3,317 | 2,000 |
| 2026-11-14 | 11,575 | 2,000 |
| 2026-11-15 | 14,304 | 2,000 |
| 2026-11-16 | 18,875 | 2,000 |
| 2026-11-17 | 9,317 | 2,000 |
| 2026-11-18 | 3,488 | 2,000 |
| 2026-11-19 | 8,820 | 2,000 |
| 2026-11-20 | 10,905 | 2,000 |
| 2026-11-21 | 10,011 | 2,000 |
| 2026-11-22 | 10,041 | 2,000 |
| 2026-11-23 | 10,091 | 2,000 |
| 2026-11-24 | 10,179 | 2,000 |
| 2026-11-25 | 7,674 | 2,000 |
| 2026-11-26 | 3,411 | 2,000 |

> Hinweis: Der Rueckstau von 3,090,235 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-27 | 20,360 |
| 2026-10-28 | 15,464 |
| 2026-10-29 | 9,474 |
| 2026-10-30 | 61,499 |
| 2026-10-31 | 87,999 |
| 2026-11-01 | 27,694 |
| 2026-11-02 | 28,636 |
| 2026-11-03 | 29,580 |
| 2026-11-04 | 29,437 |
| 2026-11-05 | 25,126 |
| 2026-11-06 | 36,164 |
| 2026-11-07 | 24,322 |
| 2026-11-08 | 25,992 |
| 2026-11-09 | 25,410 |
| 2026-11-10 | 32,571 |
| 2026-11-11 | 22,240 |
| 2026-11-12 | 20,420 |
| 2026-11-13 | 19,560 |
| 2026-11-14 | 22,857 |
| 2026-11-15 | 17,389 |
| 2026-11-16 | 17,873 |
| 2026-11-17 | 15,174 |
| 2026-11-18 | 19,421 |
| 2026-11-19 | 173,351 |
| 2026-11-20 | 26,040 |
| 2026-11-21 | 61,195 |
| 2026-11-22 | 30,297 |
| 2026-11-23 | 25,558 |
| 2026-11-24 | 26,371 |
| 2026-11-25 | 27,415 |
| 2026-11-26 | 28,575 |
| 2026-11-27 | 27,763 |
| 2026-11-28 | 109,080 |
| 2026-11-29 | 28,099 |
| 2026-11-30 | 25,454 |
| 2026-12-01 | 26,472 |
| 2026-12-02 | 26,114 |
| 2026-12-03 | 25,934 |
| 2026-12-04 | 27,855 |
| 2026-12-05 | 25,896 |
| 2026-12-06 | 30,063 |
| 2026-12-07 | 23,686 |
| 2026-12-08 | 39,301 |
| 2026-12-09 | 54,948 |
| 2026-12-10 | 25,039 |
| 2026-12-11 | 27,713 |
| 2026-12-12 | 24,334 |
| 2026-12-13 | 23,804 |
| 2026-12-14 | 23,426 |
| 2026-12-15 | 26,197 |
| 2026-12-16 | 16,605 |
| 2026-12-17 | 24,969 |
| 2026-12-18 | 22,470 |
| 2026-12-19 | 25,560 |
| 2026-12-20 | 14,295 |
| 2026-12-21 | 27,313 |
| 2026-12-22 | 24,086 |
| 2026-12-23 | 21,107 |
| 2026-12-24 | 20,391 |
| 2026-12-25 | 21,595 |
| 2026-12-26 | 17,819 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
