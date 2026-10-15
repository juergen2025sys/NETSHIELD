# Seen-DB Expiry Forecast

Lauf: 2026-10-16 00:38 CEST (Europe/Berlin)
Gesamt: 10,830,920 IPs in seen_db.json (7,775,691 aktiv/180-Tage-Pfad, 3,055,229 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 163,951 |
| 8-14 Tage | 179,067 |
| 15-30 Tage | 520,192 |
| 31-60 Tage | 1,064,908 |
| 61-90 Tage | 692,043 |
| 91-180 Tage | 5,155,530 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,662,114 |
| 0-3 Tage | 42,174 |
| 4-7 Tage | 34,438 |
| 8-14 Tage | 103,977 |
| 15-30 Tage | 212,526 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-15 | 8,248 |
| 2026-10-16 | 15,406 |
| 2026-10-17 | 9,908 |
| 2026-10-18 | 8,612 |
| 2026-10-19 | 5,112 |
| 2026-10-20 | 9,514 |
| 2026-10-21 | 9,474 |
| 2026-10-22 | 10,338 |
| 2026-10-23 | 12,338 |
| 2026-10-24 | 15,006 |
| 2026-10-25 | 11,056 |
| 2026-10-26 | 9,408 |
| 2026-10-27 | 35,111 |
| 2026-10-28 | 11,250 |
| 2026-10-29 | 9,808 |
| 2026-10-30 | 20,051 |
| 2026-10-31 | 16,910 |
| 2026-11-01 | 15,319 |
| 2026-11-02 | 11,879 |
| 2026-11-03 | 16,589 |
| 2026-11-04 | 10,048 |
| 2026-11-05 | 7,231 |
| 2026-11-06 | 12,056 |
| 2026-11-07 | 13,351 |
| 2026-11-08 | 6,264 |
| 2026-11-09 | 11,483 |
| 2026-11-10 | 23,854 |
| 2026-11-11 | 9,908 |
| 2026-11-12 | 8,072 |
| 2026-11-13 | 3,361 |
| 2026-11-14 | 11,697 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,662,114** IPs. Brutto faellig in den naechsten 30 Tagen: **378,662**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **2,978,776**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-15 | 8,248 | 2,000 |
| 2026-10-16 | 15,406 | 2,000 |
| 2026-10-17 | 9,908 | 2,000 |
| 2026-10-18 | 8,612 | 2,000 |
| 2026-10-19 | 5,112 | 2,000 |
| 2026-10-20 | 9,514 | 2,000 |
| 2026-10-21 | 9,474 | 2,000 |
| 2026-10-22 | 10,338 | 2,000 |
| 2026-10-23 | 12,338 | 2,000 |
| 2026-10-24 | 15,006 | 2,000 |
| 2026-10-25 | 11,056 | 2,000 |
| 2026-10-26 | 9,408 | 2,000 |
| 2026-10-27 | 35,111 | 2,000 |
| 2026-10-28 | 11,250 | 2,000 |
| 2026-10-29 | 9,808 | 2,000 |
| 2026-10-30 | 20,051 | 2,000 |
| 2026-10-31 | 16,910 | 2,000 |
| 2026-11-01 | 15,319 | 2,000 |
| 2026-11-02 | 11,879 | 2,000 |
| 2026-11-03 | 16,589 | 2,000 |
| 2026-11-04 | 10,048 | 2,000 |
| 2026-11-05 | 7,231 | 2,000 |
| 2026-11-06 | 12,056 | 2,000 |
| 2026-11-07 | 13,351 | 2,000 |
| 2026-11-08 | 6,264 | 2,000 |
| 2026-11-09 | 11,483 | 2,000 |
| 2026-11-10 | 23,854 | 2,000 |
| 2026-11-11 | 9,908 | 2,000 |
| 2026-11-12 | 8,072 | 2,000 |
| 2026-11-13 | 3,361 | 2,000 |
| 2026-11-14 | 11,697 | 2,000 |

> Hinweis: Der Rueckstau von 2,978,776 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-16 | 51,126 |
| 2026-10-17 | 24,153 |
| 2026-10-18 | 14,160 |
| 2026-10-19 | 21,968 |
| 2026-10-20 | 11,056 |
| 2026-10-21 | 11,017 |
| 2026-10-22 | 30,471 |
| 2026-10-23 | 50,210 |
| 2026-10-24 | 41,573 |
| 2026-10-25 | 21,480 |
| 2026-10-26 | 20,189 |
| 2026-10-27 | 20,453 |
| 2026-10-28 | 15,606 |
| 2026-10-29 | 9,556 |
| 2026-10-30 | 61,589 |
| 2026-10-31 | 88,041 |
| 2026-11-01 | 27,734 |
| 2026-11-02 | 28,682 |
| 2026-11-03 | 29,625 |
| 2026-11-04 | 29,480 |
| 2026-11-05 | 25,161 |
| 2026-11-06 | 36,216 |
| 2026-11-07 | 24,362 |
| 2026-11-08 | 26,022 |
| 2026-11-09 | 25,453 |
| 2026-11-10 | 32,614 |
| 2026-11-11 | 22,282 |
| 2026-11-12 | 20,446 |
| 2026-11-13 | 19,594 |
| 2026-11-14 | 22,891 |
| 2026-11-15 | 17,411 |
| 2026-11-16 | 17,913 |
| 2026-11-17 | 15,196 |
| 2026-11-18 | 19,450 |
| 2026-11-19 | 173,459 |
| 2026-11-20 | 26,083 |
| 2026-11-21 | 61,250 |
| 2026-11-22 | 30,341 |
| 2026-11-23 | 25,604 |
| 2026-11-24 | 26,412 |
| 2026-11-25 | 27,460 |
| 2026-11-26 | 28,601 |
| 2026-11-27 | 27,790 |
| 2026-11-28 | 109,135 |
| 2026-11-29 | 28,128 |
| 2026-11-30 | 25,488 |
| 2026-12-01 | 26,501 |
| 2026-12-02 | 26,156 |
| 2026-12-03 | 25,971 |
| 2026-12-04 | 27,878 |
| 2026-12-05 | 25,924 |
| 2026-12-06 | 30,101 |
| 2026-12-07 | 23,714 |
| 2026-12-08 | 39,341 |
| 2026-12-09 | 55,098 |
| 2026-12-10 | 25,073 |
| 2026-12-11 | 27,746 |
| 2026-12-12 | 24,376 |
| 2026-12-13 | 23,844 |
| 2026-12-14 | 23,464 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
