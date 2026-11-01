# Seen-DB Expiry Forecast

Lauf: 2026-11-01 14:07 CET (Europe/Berlin)
Gesamt: 11,164,109 IPs in seen_db.json (7,979,670 aktiv/180-Tage-Pfad, 3,184,439 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 199,140 |
| 8-14 Tage | 160,333 |
| 15-30 Tage | 667,900 |
| 31-60 Tage | 755,608 |
| 61-90 Tage | 876,674 |
| 91-180 Tage | 5,320,015 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,873,565 |
| 0-3 Tage | 53,707 |
| 4-7 Tage | 38,751 |
| 8-14 Tage | 82,010 |
| 15-30 Tage | 136,406 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-01 | 15,289 |
| 2026-11-02 | 11,851 |
| 2026-11-03 | 16,549 |
| 2026-11-04 | 10,018 |
| 2026-11-05 | 7,200 |
| 2026-11-06 | 12,020 |
| 2026-11-07 | 13,305 |
| 2026-11-08 | 6,226 |
| 2026-11-09 | 11,421 |
| 2026-11-10 | 23,601 |
| 2026-11-11 | 9,851 |
| 2026-11-12 | 7,992 |
| 2026-11-13 | 3,309 |
| 2026-11-14 | 11,558 |
| 2026-11-15 | 14,278 |
| 2026-11-16 | 18,835 |
| 2026-11-17 | 9,301 |
| 2026-11-18 | 3,480 |
| 2026-11-19 | 8,794 |
| 2026-11-20 | 10,871 |
| 2026-11-21 | 9,978 |
| 2026-11-22 | 10,009 |
| 2026-11-23 | 10,054 |
| 2026-11-24 | 10,135 |
| 2026-11-25 | 7,635 |
| 2026-11-26 | 3,361 |
| 2026-11-27 | 3,884 |
| 2026-11-28 | 3,568 |
| 2026-11-29 | 8,171 |
| 2026-11-30 | 7,220 |
| 2026-12-01 | 8,133 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,873,565** IPs. Brutto faellig in den naechsten 30 Tagen: **307,897**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,119,462**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-01 | 15,289 | 2,000 |
| 2026-11-02 | 11,851 | 2,000 |
| 2026-11-03 | 16,549 | 2,000 |
| 2026-11-04 | 10,018 | 2,000 |
| 2026-11-05 | 7,200 | 2,000 |
| 2026-11-06 | 12,020 | 2,000 |
| 2026-11-07 | 13,305 | 2,000 |
| 2026-11-08 | 6,226 | 2,000 |
| 2026-11-09 | 11,421 | 2,000 |
| 2026-11-10 | 23,601 | 2,000 |
| 2026-11-11 | 9,851 | 2,000 |
| 2026-11-12 | 7,992 | 2,000 |
| 2026-11-13 | 3,309 | 2,000 |
| 2026-11-14 | 11,558 | 2,000 |
| 2026-11-15 | 14,278 | 2,000 |
| 2026-11-16 | 18,835 | 2,000 |
| 2026-11-17 | 9,301 | 2,000 |
| 2026-11-18 | 3,480 | 2,000 |
| 2026-11-19 | 8,794 | 2,000 |
| 2026-11-20 | 10,871 | 2,000 |
| 2026-11-21 | 9,978 | 2,000 |
| 2026-11-22 | 10,009 | 2,000 |
| 2026-11-23 | 10,054 | 2,000 |
| 2026-11-24 | 10,135 | 2,000 |
| 2026-11-25 | 7,635 | 2,000 |
| 2026-11-26 | 3,361 | 2,000 |
| 2026-11-27 | 3,884 | 2,000 |
| 2026-11-28 | 3,568 | 2,000 |
| 2026-11-29 | 8,171 | 2,000 |
| 2026-11-30 | 7,220 | 2,000 |
| 2026-12-01 | 8,133 | 2,000 |

> Hinweis: Der Rueckstau von 3,119,462 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-02 | 28,622 |
| 2026-11-03 | 29,562 |
| 2026-11-04 | 29,418 |
| 2026-11-05 | 25,108 |
| 2026-11-06 | 36,136 |
| 2026-11-07 | 24,312 |
| 2026-11-08 | 25,982 |
| 2026-11-09 | 25,394 |
| 2026-11-10 | 32,544 |
| 2026-11-11 | 22,223 |
| 2026-11-12 | 20,404 |
| 2026-11-13 | 19,543 |
| 2026-11-14 | 22,842 |
| 2026-11-15 | 17,383 |
| 2026-11-16 | 17,865 |
| 2026-11-17 | 15,165 |
| 2026-11-18 | 19,410 |
| 2026-11-19 | 173,307 |
| 2026-11-20 | 26,026 |
| 2026-11-21 | 61,174 |
| 2026-11-22 | 30,284 |
| 2026-11-23 | 25,543 |
| 2026-11-24 | 26,365 |
| 2026-11-25 | 27,398 |
| 2026-11-26 | 28,565 |
| 2026-11-27 | 27,749 |
| 2026-11-28 | 109,054 |
| 2026-11-29 | 28,091 |
| 2026-11-30 | 25,442 |
| 2026-12-01 | 26,462 |
| 2026-12-02 | 26,105 |
| 2026-12-03 | 25,921 |
| 2026-12-04 | 27,842 |
| 2026-12-05 | 25,876 |
| 2026-12-06 | 30,049 |
| 2026-12-07 | 23,673 |
| 2026-12-08 | 39,290 |
| 2026-12-09 | 54,877 |
| 2026-12-10 | 25,024 |
| 2026-12-11 | 27,700 |
| 2026-12-12 | 24,317 |
| 2026-12-13 | 23,788 |
| 2026-12-14 | 23,405 |
| 2026-12-15 | 26,177 |
| 2026-12-16 | 16,585 |
| 2026-12-17 | 24,960 |
| 2026-12-18 | 22,451 |
| 2026-12-19 | 25,547 |
| 2026-12-20 | 14,281 |
| 2026-12-21 | 27,286 |
| 2026-12-22 | 24,059 |
| 2026-12-23 | 21,088 |
| 2026-12-24 | 20,377 |
| 2026-12-25 | 21,588 |
| 2026-12-26 | 17,798 |
| 2026-12-27 | 24,629 |
| 2026-12-28 | 21,725 |
| 2026-12-29 | 22,548 |
| 2026-12-30 | 26,502 |
| 2026-12-31 | 20,140 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
