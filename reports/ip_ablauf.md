# Seen-DB Expiry Forecast

Lauf: 2026-10-15 17:19 CEST (Europe/Berlin)
Gesamt: 10,819,616 IPs in seen_db.json (7,768,846 aktiv/180-Tage-Pfad, 3,050,770 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 163,964 |
| 8-14 Tage | 179,085 |
| 15-30 Tage | 520,222 |
| 31-60 Tage | 1,064,960 |
| 61-90 Tage | 692,093 |
| 91-180 Tage | 5,148,522 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,662,173 |
| 0-3 Tage | 42,174 |
| 4-7 Tage | 34,439 |
| 8-14 Tage | 103,981 |
| 15-30 Tage | 208,003 |

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
| 2026-10-21 | 9,475 |
| 2026-10-22 | 10,338 |
| 2026-10-23 | 12,338 |
| 2026-10-24 | 15,007 |
| 2026-10-25 | 11,058 |
| 2026-10-26 | 9,409 |
| 2026-10-27 | 35,111 |
| 2026-10-28 | 11,250 |
| 2026-10-29 | 9,808 |
| 2026-10-30 | 20,052 |
| 2026-10-31 | 16,911 |
| 2026-11-01 | 15,319 |
| 2026-11-02 | 11,880 |
| 2026-11-03 | 16,591 |
| 2026-11-04 | 10,049 |
| 2026-11-05 | 7,231 |
| 2026-11-06 | 12,056 |
| 2026-11-07 | 13,355 |
| 2026-11-08 | 6,266 |
| 2026-11-09 | 11,487 |
| 2026-11-10 | 23,856 |
| 2026-11-11 | 9,913 |
| 2026-11-12 | 8,074 |
| 2026-11-13 | 3,364 |
| 2026-11-14 | 11,707 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,662,173** IPs. Brutto faellig in den naechsten 30 Tagen: **378,705**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **2,978,878**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-15 | 8,248 | 2,000 |
| 2026-10-16 | 15,406 | 2,000 |
| 2026-10-17 | 9,908 | 2,000 |
| 2026-10-18 | 8,612 | 2,000 |
| 2026-10-19 | 5,112 | 2,000 |
| 2026-10-20 | 9,514 | 2,000 |
| 2026-10-21 | 9,475 | 2,000 |
| 2026-10-22 | 10,338 | 2,000 |
| 2026-10-23 | 12,338 | 2,000 |
| 2026-10-24 | 15,007 | 2,000 |
| 2026-10-25 | 11,058 | 2,000 |
| 2026-10-26 | 9,409 | 2,000 |
| 2026-10-27 | 35,111 | 2,000 |
| 2026-10-28 | 11,250 | 2,000 |
| 2026-10-29 | 9,808 | 2,000 |
| 2026-10-30 | 20,052 | 2,000 |
| 2026-10-31 | 16,911 | 2,000 |
| 2026-11-01 | 15,319 | 2,000 |
| 2026-11-02 | 11,880 | 2,000 |
| 2026-11-03 | 16,591 | 2,000 |
| 2026-11-04 | 10,049 | 2,000 |
| 2026-11-05 | 7,231 | 2,000 |
| 2026-11-06 | 12,056 | 2,000 |
| 2026-11-07 | 13,355 | 2,000 |
| 2026-11-08 | 6,266 | 2,000 |
| 2026-11-09 | 11,487 | 2,000 |
| 2026-11-10 | 23,856 | 2,000 |
| 2026-11-11 | 9,913 | 2,000 |
| 2026-11-12 | 8,074 | 2,000 |
| 2026-11-13 | 3,364 | 2,000 |
| 2026-11-14 | 11,707 | 2,000 |

> Hinweis: Der Rueckstau von 2,978,878 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-16 | 51,128 |
| 2026-10-17 | 24,154 |
| 2026-10-18 | 14,160 |
| 2026-10-19 | 21,975 |
| 2026-10-20 | 11,056 |
| 2026-10-21 | 11,019 |
| 2026-10-22 | 30,472 |
| 2026-10-23 | 50,213 |
| 2026-10-24 | 41,574 |
| 2026-10-25 | 21,481 |
| 2026-10-26 | 20,190 |
| 2026-10-27 | 20,459 |
| 2026-10-28 | 15,608 |
| 2026-10-29 | 9,560 |
| 2026-10-30 | 61,595 |
| 2026-10-31 | 88,044 |
| 2026-11-01 | 27,734 |
| 2026-11-02 | 28,683 |
| 2026-11-03 | 29,626 |
| 2026-11-04 | 29,483 |
| 2026-11-05 | 25,161 |
| 2026-11-06 | 36,218 |
| 2026-11-07 | 24,364 |
| 2026-11-08 | 26,022 |
| 2026-11-09 | 25,453 |
| 2026-11-10 | 32,615 |
| 2026-11-11 | 22,285 |
| 2026-11-12 | 20,447 |
| 2026-11-13 | 19,597 |
| 2026-11-14 | 22,895 |
| 2026-11-15 | 17,413 |
| 2026-11-16 | 17,913 |
| 2026-11-17 | 15,196 |
| 2026-11-18 | 19,450 |
| 2026-11-19 | 173,462 |
| 2026-11-20 | 26,083 |
| 2026-11-21 | 61,253 |
| 2026-11-22 | 30,342 |
| 2026-11-23 | 25,605 |
| 2026-11-24 | 26,413 |
| 2026-11-25 | 27,463 |
| 2026-11-26 | 28,602 |
| 2026-11-27 | 27,791 |
| 2026-11-28 | 109,137 |
| 2026-11-29 | 28,128 |
| 2026-11-30 | 25,489 |
| 2026-12-01 | 26,501 |
| 2026-12-02 | 26,159 |
| 2026-12-03 | 25,972 |
| 2026-12-04 | 27,879 |
| 2026-12-05 | 25,925 |
| 2026-12-06 | 30,101 |
| 2026-12-07 | 23,718 |
| 2026-12-08 | 39,344 |
| 2026-12-09 | 55,110 |
| 2026-12-10 | 25,076 |
| 2026-12-11 | 27,747 |
| 2026-12-12 | 24,377 |
| 2026-12-13 | 23,846 |
| 2026-12-14 | 23,465 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
