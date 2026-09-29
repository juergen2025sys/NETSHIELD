# Seen-DB Expiry Forecast

Lauf: 2026-09-29 15:17 CEST (Europe/Berlin)
Gesamt: 11,881,181 IPs in seen_db.json (8,988,564 aktiv/180-Tage-Pfad, 2,892,617 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 87,833 |
| 8-14 Tage | 2,017,389 |
| 15-30 Tage | 419,313 |
| 31-60 Tage | 1,130,478 |
| 61-90 Tage | 772,583 |
| 91-180 Tage | 4,560,968 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 1,245,794 |
| 0-3 Tage | 1,373,093 |
| 4-7 Tage | 20,627 |
| 8-14 Tage | 51,318 |
| 15-30 Tage | 201,785 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-30 | 59,438 |
| 2026-10-01 | 7,610 |
| 2026-10-02 | 1,306,045 |
| 2026-10-03 | 2,950 |
| 2026-10-04 | 6,844 |
| 2026-10-05 | 2,867 |
| 2026-10-06 | 7,966 |
| 2026-10-07 | 7,920 |
| 2026-10-08 | 7,273 |
| 2026-10-09 | 10,151 |
| 2026-10-10 | 7,558 |
| 2026-10-11 | 6,254 |
| 2026-10-12 | 3,873 |
| 2026-10-13 | 8,289 |
| 2026-10-14 | 7,440 |
| 2026-10-15 | 8,321 |
| 2026-10-16 | 15,498 |
| 2026-10-17 | 9,958 |
| 2026-10-18 | 8,683 |
| 2026-10-19 | 5,167 |
| 2026-10-20 | 9,642 |
| 2026-10-21 | 9,582 |
| 2026-10-22 | 10,455 |
| 2026-10-23 | 12,498 |
| 2026-10-24 | 15,165 |
| 2026-10-25 | 11,158 |
| 2026-10-26 | 9,521 |
| 2026-10-27 | 35,421 |
| 2026-10-28 | 11,384 |
| 2026-10-29 | 9,982 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **1,245,794** IPs. Brutto faellig in den naechsten 30 Tagen: **1,634,913**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,820,707**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-30 | 59,438 | 2,000 |
| 2026-10-01 | 7,610 | 2,000 |
| 2026-10-02 | 1,306,045 | 2,000 |
| 2026-10-03 | 2,950 | 2,000 |
| 2026-10-04 | 6,844 | 2,000 |
| 2026-10-05 | 2,867 | 2,000 |
| 2026-10-06 | 7,966 | 2,000 |
| 2026-10-07 | 7,920 | 2,000 |
| 2026-10-08 | 7,273 | 2,000 |
| 2026-10-09 | 10,151 | 2,000 |
| 2026-10-10 | 7,558 | 2,000 |
| 2026-10-11 | 6,254 | 2,000 |
| 2026-10-12 | 3,873 | 2,000 |
| 2026-10-13 | 8,289 | 2,000 |
| 2026-10-14 | 7,440 | 2,000 |
| 2026-10-15 | 8,321 | 2,000 |
| 2026-10-16 | 15,498 | 2,000 |
| 2026-10-17 | 9,958 | 2,000 |
| 2026-10-18 | 8,683 | 2,000 |
| 2026-10-19 | 5,167 | 2,000 |
| 2026-10-20 | 9,642 | 2,000 |
| 2026-10-21 | 9,582 | 2,000 |
| 2026-10-22 | 10,455 | 2,000 |
| 2026-10-23 | 12,498 | 2,000 |
| 2026-10-24 | 15,165 | 2,000 |
| 2026-10-25 | 11,158 | 2,000 |
| 2026-10-26 | 9,521 | 2,000 |
| 2026-10-27 | 35,421 | 2,000 |
| 2026-10-28 | 11,384 | 2,000 |
| 2026-10-29 | 9,982 | 2,000 |

> Hinweis: Der Rueckstau von 2,820,707 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-30 | 10,132 |
| 2026-10-01 | 16,556 |
| 2026-10-02 | 7,696 |
| 2026-10-03 | 7,308 |
| 2026-10-04 | 12,576 |
| 2026-10-05 | 17,498 |
| 2026-10-06 | 16,067 |
| 2026-10-07 | 15,008 |
| 2026-10-08 | 61,219 |
| 2026-10-09 | 221,932 |
| 2026-10-10 | 53,325 |
| 2026-10-11 | 16,025 |
| 2026-10-12 | 66,551 |
| 2026-10-13 | 1,583,329 |
| 2026-10-14 | 32,912 |
| 2026-10-15 | 41,319 |
| 2026-10-16 | 51,269 |
| 2026-10-17 | 24,251 |
| 2026-10-18 | 14,250 |
| 2026-10-19 | 22,274 |
| 2026-10-20 | 11,128 |
| 2026-10-21 | 11,092 |
| 2026-10-22 | 30,709 |
| 2026-10-23 | 50,383 |
| 2026-10-24 | 41,695 |
| 2026-10-25 | 21,596 |
| 2026-10-26 | 20,312 |
| 2026-10-27 | 20,666 |
| 2026-10-28 | 15,788 |
| 2026-10-29 | 9,669 |
| 2026-10-30 | 61,900 |
| 2026-10-31 | 88,203 |
| 2026-11-01 | 27,857 |
| 2026-11-02 | 28,810 |
| 2026-11-03 | 29,788 |
| 2026-11-04 | 29,628 |
| 2026-11-05 | 25,277 |
| 2026-11-06 | 36,388 |
| 2026-11-07 | 24,478 |
| 2026-11-08 | 26,126 |
| 2026-11-09 | 25,572 |
| 2026-11-10 | 32,747 |
| 2026-11-11 | 22,384 |
| 2026-11-12 | 20,519 |
| 2026-11-13 | 19,672 |
| 2026-11-14 | 22,992 |
| 2026-11-15 | 17,479 |
| 2026-11-16 | 17,988 |
| 2026-11-17 | 15,271 |
| 2026-11-18 | 19,527 |
| 2026-11-19 | 173,970 |
| 2026-11-20 | 26,203 |
| 2026-11-21 | 61,482 |
| 2026-11-22 | 30,485 |
| 2026-11-23 | 25,725 |
| 2026-11-24 | 26,521 |
| 2026-11-25 | 27,606 |
| 2026-11-26 | 28,706 |
| 2026-11-27 | 27,885 |
| 2026-11-28 | 109,289 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
