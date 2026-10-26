# Seen-DB Expiry Forecast

Lauf: 2026-10-26 08:42 CET (Europe/Berlin)
Gesamt: 11,158,996 IPs in seen_db.json (8,007,867 aktiv/180-Tage-Pfad, 3,151,129 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 251,150 |
| 8-14 Tage | 196,046 |
| 15-30 Tage | 557,790 |
| 31-60 Tage | 868,246 |
| 61-90 Tage | 734,652 |
| 91-180 Tage | 5,399,983 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,772,531 |
| 0-3 Tage | 65,445 |
| 4-7 Tage | 64,070 |
| 8-14 Tage | 76,836 |
| 15-30 Tage | 172,247 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-26 | 9,393 |
| 2026-10-27 | 35,026 |
| 2026-10-28 | 11,237 |
| 2026-10-29 | 9,789 |
| 2026-10-30 | 20,021 |
| 2026-10-31 | 16,885 |
| 2026-11-01 | 15,302 |
| 2026-11-02 | 11,862 |
| 2026-11-03 | 16,568 |
| 2026-11-04 | 10,027 |
| 2026-11-05 | 7,208 |
| 2026-11-06 | 12,034 |
| 2026-11-07 | 13,319 |
| 2026-11-08 | 6,241 |
| 2026-11-09 | 11,439 |
| 2026-11-10 | 23,623 |
| 2026-11-11 | 9,864 |
| 2026-11-12 | 8,017 |
| 2026-11-13 | 3,318 |
| 2026-11-14 | 11,579 |
| 2026-11-15 | 14,305 |
| 2026-11-16 | 18,880 |
| 2026-11-17 | 9,319 |
| 2026-11-18 | 3,489 |
| 2026-11-19 | 8,821 |
| 2026-11-20 | 10,910 |
| 2026-11-21 | 10,016 |
| 2026-11-22 | 10,051 |
| 2026-11-23 | 10,097 |
| 2026-11-24 | 10,187 |
| 2026-11-25 | 7,692 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,772,531** IPs. Brutto faellig in den naechsten 30 Tagen: **376,519**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,087,050**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-26 | 9,393 | 2,000 |
| 2026-10-27 | 35,026 | 2,000 |
| 2026-10-28 | 11,237 | 2,000 |
| 2026-10-29 | 9,789 | 2,000 |
| 2026-10-30 | 20,021 | 2,000 |
| 2026-10-31 | 16,885 | 2,000 |
| 2026-11-01 | 15,302 | 2,000 |
| 2026-11-02 | 11,862 | 2,000 |
| 2026-11-03 | 16,568 | 2,000 |
| 2026-11-04 | 10,027 | 2,000 |
| 2026-11-05 | 7,208 | 2,000 |
| 2026-11-06 | 12,034 | 2,000 |
| 2026-11-07 | 13,319 | 2,000 |
| 2026-11-08 | 6,241 | 2,000 |
| 2026-11-09 | 11,439 | 2,000 |
| 2026-11-10 | 23,623 | 2,000 |
| 2026-11-11 | 9,864 | 2,000 |
| 2026-11-12 | 8,017 | 2,000 |
| 2026-11-13 | 3,318 | 2,000 |
| 2026-11-14 | 11,579 | 2,000 |
| 2026-11-15 | 14,305 | 2,000 |
| 2026-11-16 | 18,880 | 2,000 |
| 2026-11-17 | 9,319 | 2,000 |
| 2026-11-18 | 3,489 | 2,000 |
| 2026-11-19 | 8,821 | 2,000 |
| 2026-11-20 | 10,910 | 2,000 |
| 2026-11-21 | 10,016 | 2,000 |
| 2026-11-22 | 10,051 | 2,000 |
| 2026-11-23 | 10,097 | 2,000 |
| 2026-11-24 | 10,187 | 2,000 |
| 2026-11-25 | 7,692 | 2,000 |

> Hinweis: Der Rueckstau von 3,087,050 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-27 | 20,367 |
| 2026-10-28 | 15,468 |
| 2026-10-29 | 9,475 |
| 2026-10-30 | 61,508 |
| 2026-10-31 | 88,000 |
| 2026-11-01 | 27,695 |
| 2026-11-02 | 28,637 |
| 2026-11-03 | 29,581 |
| 2026-11-04 | 29,438 |
| 2026-11-05 | 25,128 |
| 2026-11-06 | 36,170 |
| 2026-11-07 | 24,325 |
| 2026-11-08 | 25,993 |
| 2026-11-09 | 25,411 |
| 2026-11-10 | 32,571 |
| 2026-11-11 | 22,242 |
| 2026-11-12 | 20,422 |
| 2026-11-13 | 19,563 |
| 2026-11-14 | 22,860 |
| 2026-11-15 | 17,391 |
| 2026-11-16 | 17,875 |
| 2026-11-17 | 15,174 |
| 2026-11-18 | 19,422 |
| 2026-11-19 | 173,354 |
| 2026-11-20 | 26,044 |
| 2026-11-21 | 61,198 |
| 2026-11-22 | 30,305 |
| 2026-11-23 | 25,568 |
| 2026-11-24 | 26,373 |
| 2026-11-25 | 27,428 |
| 2026-11-26 | 28,579 |
| 2026-11-27 | 27,764 |
| 2026-11-28 | 109,084 |
| 2026-11-29 | 28,101 |
| 2026-11-30 | 25,458 |
| 2026-12-01 | 26,473 |
| 2026-12-02 | 26,115 |
| 2026-12-03 | 25,935 |
| 2026-12-04 | 27,856 |
| 2026-12-05 | 25,900 |
| 2026-12-06 | 30,065 |
| 2026-12-07 | 23,688 |
| 2026-12-08 | 39,306 |
| 2026-12-09 | 54,960 |
| 2026-12-10 | 25,044 |
| 2026-12-11 | 27,717 |
| 2026-12-12 | 24,337 |
| 2026-12-13 | 23,812 |
| 2026-12-14 | 23,430 |
| 2026-12-15 | 26,202 |
| 2026-12-16 | 16,607 |
| 2026-12-17 | 24,974 |
| 2026-12-18 | 22,476 |
| 2026-12-19 | 25,567 |
| 2026-12-20 | 14,297 |
| 2026-12-21 | 27,313 |
| 2026-12-22 | 24,090 |
| 2026-12-23 | 21,108 |
| 2026-12-24 | 20,392 |
| 2026-12-25 | 21,596 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
