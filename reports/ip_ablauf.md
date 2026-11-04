# Seen-DB Expiry Forecast

Lauf: 2026-11-04 06:57 CET (Europe/Berlin)
Gesamt: 11,162,247 IPs in seen_db.json (7,966,102 aktiv/180-Tage-Pfad, 3,196,145 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 191,628 |
| 8-14 Tage | 132,572 |
| 15-30 Tage | 695,161 |
| 31-60 Tage | 734,887 |
| 61-90 Tage | 900,286 |
| 91-180 Tage | 5,311,568 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,913,119 |
| 0-3 Tage | 42,525 |
| 4-7 Tage | 51,075 |
| 8-14 Tage | 68,699 |
| 15-30 Tage | 120,727 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-04 | 10,015 |
| 2026-11-05 | 7,194 |
| 2026-11-06 | 12,014 |
| 2026-11-07 | 13,302 |
| 2026-11-08 | 6,223 |
| 2026-11-09 | 11,414 |
| 2026-11-10 | 23,594 |
| 2026-11-11 | 9,844 |
| 2026-11-12 | 7,989 |
| 2026-11-13 | 3,304 |
| 2026-11-14 | 11,549 |
| 2026-11-15 | 14,269 |
| 2026-11-16 | 18,817 |
| 2026-11-17 | 9,297 |
| 2026-11-18 | 3,474 |
| 2026-11-19 | 8,784 |
| 2026-11-20 | 10,860 |
| 2026-11-21 | 9,957 |
| 2026-11-22 | 9,999 |
| 2026-11-23 | 10,043 |
| 2026-11-24 | 10,115 |
| 2026-11-25 | 7,625 |
| 2026-11-26 | 3,350 |
| 2026-11-27 | 3,876 |
| 2026-11-28 | 3,552 |
| 2026-11-29 | 8,151 |
| 2026-11-30 | 7,159 |
| 2026-12-01 | 8,101 |
| 2026-12-02 | 4,659 |
| 2026-12-03 | 7,764 |
| 2026-12-04 | 5,809 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,913,119** IPs. Brutto faellig in den naechsten 30 Tagen: **282,103**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,133,222**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-04 | 10,015 | 2,000 |
| 2026-11-05 | 7,194 | 2,000 |
| 2026-11-06 | 12,014 | 2,000 |
| 2026-11-07 | 13,302 | 2,000 |
| 2026-11-08 | 6,223 | 2,000 |
| 2026-11-09 | 11,414 | 2,000 |
| 2026-11-10 | 23,594 | 2,000 |
| 2026-11-11 | 9,844 | 2,000 |
| 2026-11-12 | 7,989 | 2,000 |
| 2026-11-13 | 3,304 | 2,000 |
| 2026-11-14 | 11,549 | 2,000 |
| 2026-11-15 | 14,269 | 2,000 |
| 2026-11-16 | 18,817 | 2,000 |
| 2026-11-17 | 9,297 | 2,000 |
| 2026-11-18 | 3,474 | 2,000 |
| 2026-11-19 | 8,784 | 2,000 |
| 2026-11-20 | 10,860 | 2,000 |
| 2026-11-21 | 9,957 | 2,000 |
| 2026-11-22 | 9,999 | 2,000 |
| 2026-11-23 | 10,043 | 2,000 |
| 2026-11-24 | 10,115 | 2,000 |
| 2026-11-25 | 7,625 | 2,000 |
| 2026-11-26 | 3,350 | 2,000 |
| 2026-11-27 | 3,876 | 2,000 |
| 2026-11-28 | 3,552 | 2,000 |
| 2026-11-29 | 8,151 | 2,000 |
| 2026-11-30 | 7,159 | 2,000 |
| 2026-12-01 | 8,101 | 2,000 |
| 2026-12-02 | 4,659 | 2,000 |
| 2026-12-03 | 7,764 | 2,000 |
| 2026-12-04 | 5,809 | 2,000 |

> Hinweis: Der Rueckstau von 3,133,222 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-05 | 25,089 |
| 2026-11-06 | 36,126 |
| 2026-11-07 | 24,301 |
| 2026-11-08 | 25,977 |
| 2026-11-09 | 25,384 |
| 2026-11-10 | 32,538 |
| 2026-11-11 | 22,213 |
| 2026-11-12 | 20,401 |
| 2026-11-13 | 19,540 |
| 2026-11-14 | 22,836 |
| 2026-11-15 | 17,378 |
| 2026-11-16 | 17,856 |
| 2026-11-17 | 15,157 |
| 2026-11-18 | 19,404 |
| 2026-11-19 | 173,291 |
| 2026-11-20 | 26,010 |
| 2026-11-21 | 61,142 |
| 2026-11-22 | 30,272 |
| 2026-11-23 | 25,529 |
| 2026-11-24 | 26,359 |
| 2026-11-25 | 27,394 |
| 2026-11-26 | 28,556 |
| 2026-11-27 | 27,744 |
| 2026-11-28 | 109,039 |
| 2026-11-29 | 28,088 |
| 2026-11-30 | 25,439 |
| 2026-12-01 | 26,456 |
| 2026-12-02 | 26,096 |
| 2026-12-03 | 25,911 |
| 2026-12-04 | 27,835 |
| 2026-12-05 | 25,869 |
| 2026-12-06 | 30,035 |
| 2026-12-07 | 23,669 |
| 2026-12-08 | 39,275 |
| 2026-12-09 | 54,843 |
| 2026-12-10 | 25,021 |
| 2026-12-11 | 27,691 |
| 2026-12-12 | 24,311 |
| 2026-12-13 | 23,779 |
| 2026-12-14 | 23,395 |
| 2026-12-15 | 26,168 |
| 2026-12-16 | 16,577 |
| 2026-12-17 | 24,950 |
| 2026-12-18 | 22,444 |
| 2026-12-19 | 25,535 |
| 2026-12-20 | 14,273 |
| 2026-12-21 | 27,272 |
| 2026-12-22 | 24,044 |
| 2026-12-23 | 21,077 |
| 2026-12-24 | 20,370 |
| 2026-12-25 | 21,583 |
| 2026-12-26 | 17,789 |
| 2026-12-27 | 24,617 |
| 2026-12-28 | 21,718 |
| 2026-12-29 | 22,543 |
| 2026-12-30 | 26,494 |
| 2026-12-31 | 20,138 |
| 2027-01-01 | 18,499 |
| 2027-01-02 | 26,094 |
| 2027-01-03 | 14,814 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
