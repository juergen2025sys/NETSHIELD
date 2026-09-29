# Seen-DB Expiry Forecast

Lauf: 2026-09-29 08:05 CEST (Europe/Berlin)
Gesamt: 11,858,404 IPs in seen_db.json (8,971,270 aktiv/180-Tage-Pfad, 2,887,134 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 87,850 |
| 8-14 Tage | 2,017,638 |
| 15-30 Tage | 419,369 |
| 31-60 Tage | 1,130,597 |
| 61-90 Tage | 772,743 |
| 91-180 Tage | 4,543,073 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 1,245,943 |
| 0-3 Tage | 1,373,206 |
| 4-7 Tage | 20,636 |
| 8-14 Tage | 51,326 |
| 15-30 Tage | 196,023 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-30 | 59,441 |
| 2026-10-01 | 7,612 |
| 2026-10-02 | 1,306,153 |
| 2026-10-03 | 2,951 |
| 2026-10-04 | 6,847 |
| 2026-10-05 | 2,868 |
| 2026-10-06 | 7,970 |
| 2026-10-07 | 7,921 |
| 2026-10-08 | 7,273 |
| 2026-10-09 | 10,153 |
| 2026-10-10 | 7,560 |
| 2026-10-11 | 6,254 |
| 2026-10-12 | 3,874 |
| 2026-10-13 | 8,291 |
| 2026-10-14 | 7,441 |
| 2026-10-15 | 8,324 |
| 2026-10-16 | 15,501 |
| 2026-10-17 | 9,959 |
| 2026-10-18 | 8,686 |
| 2026-10-19 | 5,168 |
| 2026-10-20 | 9,648 |
| 2026-10-21 | 9,585 |
| 2026-10-22 | 10,464 |
| 2026-10-23 | 12,501 |
| 2026-10-24 | 15,173 |
| 2026-10-25 | 11,162 |
| 2026-10-26 | 9,526 |
| 2026-10-27 | 35,433 |
| 2026-10-28 | 11,410 |
| 2026-10-29 | 10,111 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **1,245,943** IPs. Brutto faellig in den naechsten 30 Tagen: **1,635,260**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,821,203**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-30 | 59,441 | 2,000 |
| 2026-10-01 | 7,612 | 2,000 |
| 2026-10-02 | 1,306,153 | 2,000 |
| 2026-10-03 | 2,951 | 2,000 |
| 2026-10-04 | 6,847 | 2,000 |
| 2026-10-05 | 2,868 | 2,000 |
| 2026-10-06 | 7,970 | 2,000 |
| 2026-10-07 | 7,921 | 2,000 |
| 2026-10-08 | 7,273 | 2,000 |
| 2026-10-09 | 10,153 | 2,000 |
| 2026-10-10 | 7,560 | 2,000 |
| 2026-10-11 | 6,254 | 2,000 |
| 2026-10-12 | 3,874 | 2,000 |
| 2026-10-13 | 8,291 | 2,000 |
| 2026-10-14 | 7,441 | 2,000 |
| 2026-10-15 | 8,324 | 2,000 |
| 2026-10-16 | 15,501 | 2,000 |
| 2026-10-17 | 9,959 | 2,000 |
| 2026-10-18 | 8,686 | 2,000 |
| 2026-10-19 | 5,168 | 2,000 |
| 2026-10-20 | 9,648 | 2,000 |
| 2026-10-21 | 9,585 | 2,000 |
| 2026-10-22 | 10,464 | 2,000 |
| 2026-10-23 | 12,501 | 2,000 |
| 2026-10-24 | 15,173 | 2,000 |
| 2026-10-25 | 11,162 | 2,000 |
| 2026-10-26 | 9,526 | 2,000 |
| 2026-10-27 | 35,433 | 2,000 |
| 2026-10-28 | 11,410 | 2,000 |
| 2026-10-29 | 10,111 | 2,000 |

> Hinweis: Der Rueckstau von 2,821,203 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-30 | 10,137 |
| 2026-10-01 | 16,558 |
| 2026-10-02 | 7,697 |
| 2026-10-03 | 7,309 |
| 2026-10-04 | 12,578 |
| 2026-10-05 | 17,499 |
| 2026-10-06 | 16,072 |
| 2026-10-07 | 15,010 |
| 2026-10-08 | 61,241 |
| 2026-10-09 | 222,015 |
| 2026-10-10 | 53,325 |
| 2026-10-11 | 16,028 |
| 2026-10-12 | 66,552 |
| 2026-10-13 | 1,583,467 |
| 2026-10-14 | 32,913 |
| 2026-10-15 | 41,322 |
| 2026-10-16 | 51,272 |
| 2026-10-17 | 24,254 |
| 2026-10-18 | 14,253 |
| 2026-10-19 | 22,280 |
| 2026-10-20 | 11,131 |
| 2026-10-21 | 11,096 |
| 2026-10-22 | 30,713 |
| 2026-10-23 | 50,391 |
| 2026-10-24 | 41,699 |
| 2026-10-25 | 21,597 |
| 2026-10-26 | 20,316 |
| 2026-10-27 | 20,671 |
| 2026-10-28 | 15,791 |
| 2026-10-29 | 9,670 |
| 2026-10-30 | 61,909 |
| 2026-10-31 | 88,209 |
| 2026-11-01 | 27,862 |
| 2026-11-02 | 28,814 |
| 2026-11-03 | 29,791 |
| 2026-11-04 | 29,632 |
| 2026-11-05 | 25,280 |
| 2026-11-06 | 36,391 |
| 2026-11-07 | 24,480 |
| 2026-11-08 | 26,129 |
| 2026-11-09 | 25,573 |
| 2026-11-10 | 32,752 |
| 2026-11-11 | 22,388 |
| 2026-11-12 | 20,521 |
| 2026-11-13 | 19,672 |
| 2026-11-14 | 22,996 |
| 2026-11-15 | 17,480 |
| 2026-11-16 | 17,988 |
| 2026-11-17 | 15,272 |
| 2026-11-18 | 19,529 |
| 2026-11-19 | 173,990 |
| 2026-11-20 | 26,209 |
| 2026-11-21 | 61,492 |
| 2026-11-22 | 30,490 |
| 2026-11-23 | 25,729 |
| 2026-11-24 | 26,523 |
| 2026-11-25 | 27,607 |
| 2026-11-26 | 28,707 |
| 2026-11-27 | 27,887 |
| 2026-11-28 | 109,295 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
