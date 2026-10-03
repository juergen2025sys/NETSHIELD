# Seen-DB Expiry Forecast

Lauf: 2026-10-03 07:40 CEST (Europe/Berlin)
Gesamt: 12,113,975 IPs in seen_db.json (9,172,652 aktiv/180-Tage-Pfad, 2,941,323 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 396,866 |
| 8-14 Tage | 1,814,485 |
| 15-30 Tage | 475,683 |
| 31-60 Tage | 1,029,349 |
| 61-90 Tage | 753,077 |
| 91-180 Tage | 4,703,192 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,612,815 |
| 0-3 Tage | 20,567 |
| 4-7 Tage | 32,817 |
| 8-14 Tage | 59,503 |
| 15-30 Tage | 215,621 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-03 | 2,944 |
| 2026-10-04 | 6,826 |
| 2026-10-05 | 2,860 |
| 2026-10-06 | 7,937 |
| 2026-10-07 | 7,897 |
| 2026-10-08 | 7,255 |
| 2026-10-09 | 10,131 |
| 2026-10-10 | 7,534 |
| 2026-10-11 | 6,241 |
| 2026-10-12 | 3,864 |
| 2026-10-13 | 8,262 |
| 2026-10-14 | 7,422 |
| 2026-10-15 | 8,302 |
| 2026-10-16 | 15,471 |
| 2026-10-17 | 9,941 |
| 2026-10-18 | 8,658 |
| 2026-10-19 | 5,151 |
| 2026-10-20 | 9,594 |
| 2026-10-21 | 9,547 |
| 2026-10-22 | 10,399 |
| 2026-10-23 | 12,425 |
| 2026-10-24 | 15,093 |
| 2026-10-25 | 11,121 |
| 2026-10-26 | 9,483 |
| 2026-10-27 | 35,326 |
| 2026-10-28 | 11,312 |
| 2026-10-29 | 9,881 |
| 2026-10-30 | 20,212 |
| 2026-10-31 | 17,185 |
| 2026-11-01 | 15,474 |
| 2026-11-02 | 12,168 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,612,815** IPs. Brutto faellig in den naechsten 30 Tagen: **325,916**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **2,876,731**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-03 | 2,944 | 2,000 |
| 2026-10-04 | 6,826 | 2,000 |
| 2026-10-05 | 2,860 | 2,000 |
| 2026-10-06 | 7,937 | 2,000 |
| 2026-10-07 | 7,897 | 2,000 |
| 2026-10-08 | 7,255 | 2,000 |
| 2026-10-09 | 10,131 | 2,000 |
| 2026-10-10 | 7,534 | 2,000 |
| 2026-10-11 | 6,241 | 2,000 |
| 2026-10-12 | 3,864 | 2,000 |
| 2026-10-13 | 8,262 | 2,000 |
| 2026-10-14 | 7,422 | 2,000 |
| 2026-10-15 | 8,302 | 2,000 |
| 2026-10-16 | 15,471 | 2,000 |
| 2026-10-17 | 9,941 | 2,000 |
| 2026-10-18 | 8,658 | 2,000 |
| 2026-10-19 | 5,151 | 2,000 |
| 2026-10-20 | 9,594 | 2,000 |
| 2026-10-21 | 9,547 | 2,000 |
| 2026-10-22 | 10,399 | 2,000 |
| 2026-10-23 | 12,425 | 2,000 |
| 2026-10-24 | 15,093 | 2,000 |
| 2026-10-25 | 11,121 | 2,000 |
| 2026-10-26 | 9,483 | 2,000 |
| 2026-10-27 | 35,326 | 2,000 |
| 2026-10-28 | 11,312 | 2,000 |
| 2026-10-29 | 9,881 | 2,000 |
| 2026-10-30 | 20,212 | 2,000 |
| 2026-10-31 | 17,185 | 2,000 |
| 2026-11-01 | 15,474 | 2,000 |
| 2026-11-02 | 12,168 | 2,000 |

> Hinweis: Der Rueckstau von 2,876,731 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-04 | 12,542 |
| 2026-10-05 | 17,464 |
| 2026-10-06 | 16,039 |
| 2026-10-07 | 14,974 |
| 2026-10-08 | 61,092 |
| 2026-10-09 | 221,460 |
| 2026-10-10 | 53,295 |
| 2026-10-11 | 16,013 |
| 2026-10-12 | 66,527 |
| 2026-10-13 | 1,582,293 |
| 2026-10-14 | 32,912 |
| 2026-10-15 | 41,300 |
| 2026-10-16 | 51,223 |
| 2026-10-17 | 24,217 |
| 2026-10-18 | 14,229 |
| 2026-10-19 | 22,184 |
| 2026-10-20 | 11,114 |
| 2026-10-21 | 11,074 |
| 2026-10-22 | 30,673 |
| 2026-10-23 | 50,339 |
| 2026-10-24 | 41,657 |
| 2026-10-25 | 21,565 |
| 2026-10-26 | 20,284 |
| 2026-10-27 | 20,614 |
| 2026-10-28 | 15,749 |
| 2026-10-29 | 9,641 |
| 2026-10-30 | 61,811 |
| 2026-10-31 | 88,157 |
| 2026-11-01 | 27,818 |
| 2026-11-02 | 28,774 |
| 2026-11-03 | 29,746 |
| 2026-11-04 | 29,586 |
| 2026-11-05 | 25,243 |
| 2026-11-06 | 36,341 |
| 2026-11-07 | 24,445 |
| 2026-11-08 | 26,097 |
| 2026-11-09 | 25,542 |
| 2026-11-10 | 32,711 |
| 2026-11-11 | 22,355 |
| 2026-11-12 | 20,498 |
| 2026-11-13 | 19,651 |
| 2026-11-14 | 22,967 |
| 2026-11-15 | 17,453 |
| 2026-11-16 | 17,967 |
| 2026-11-17 | 15,256 |
| 2026-11-18 | 19,504 |
| 2026-11-19 | 173,826 |
| 2026-11-20 | 26,170 |
| 2026-11-21 | 61,413 |
| 2026-11-22 | 30,440 |
| 2026-11-23 | 25,695 |
| 2026-11-24 | 26,492 |
| 2026-11-25 | 27,570 |
| 2026-11-26 | 28,684 |
| 2026-11-27 | 27,858 |
| 2026-11-28 | 109,240 |
| 2026-11-29 | 28,208 |
| 2026-11-30 | 25,576 |
| 2026-12-01 | 26,589 |
| 2026-12-02 | 26,226 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
