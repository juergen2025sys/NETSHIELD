# Seen-DB Expiry Forecast

Lauf: 2026-10-06 23:11 CEST (Europe/Berlin)
Gesamt: 12,331,014 IPs in seen_db.json (9,356,202 aktiv/180-Tage-Pfad, 2,974,812 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 2,013,451 |
| 8-14 Tage | 196,965 |
| 15-30 Tage | 512,032 |
| 31-60 Tage | 1,023,619 |
| 61-90 Tage | 741,576 |
| 91-180 Tage | 4,868,559 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,616,675 |
| 0-3 Tage | 33,152 |
| 4-7 Tage | 25,814 |
| 8-14 Tage | 64,378 |
| 15-30 Tage | 234,793 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-06 | 7,917 |
| 2026-10-07 | 7,879 |
| 2026-10-08 | 7,244 |
| 2026-10-09 | 10,112 |
| 2026-10-10 | 7,519 |
| 2026-10-11 | 6,224 |
| 2026-10-12 | 3,849 |
| 2026-10-13 | 8,222 |
| 2026-10-14 | 7,402 |
| 2026-10-15 | 8,269 |
| 2026-10-16 | 15,436 |
| 2026-10-17 | 9,928 |
| 2026-10-18 | 8,644 |
| 2026-10-19 | 5,135 |
| 2026-10-20 | 9,564 |
| 2026-10-21 | 9,514 |
| 2026-10-22 | 10,375 |
| 2026-10-23 | 12,381 |
| 2026-10-24 | 15,055 |
| 2026-10-25 | 11,093 |
| 2026-10-26 | 9,450 |
| 2026-10-27 | 35,263 |
| 2026-10-28 | 11,287 |
| 2026-10-29 | 9,849 |
| 2026-10-30 | 20,147 |
| 2026-10-31 | 17,084 |
| 2026-11-01 | 15,385 |
| 2026-11-02 | 11,963 |
| 2026-11-03 | 16,676 |
| 2026-11-04 | 10,114 |
| 2026-11-05 | 7,324 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,616,675** IPs. Brutto faellig in den naechsten 30 Tagen: **346,304**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **2,900,979**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-06 | 7,917 | 2,000 |
| 2026-10-07 | 7,879 | 2,000 |
| 2026-10-08 | 7,244 | 2,000 |
| 2026-10-09 | 10,112 | 2,000 |
| 2026-10-10 | 7,519 | 2,000 |
| 2026-10-11 | 6,224 | 2,000 |
| 2026-10-12 | 3,849 | 2,000 |
| 2026-10-13 | 8,222 | 2,000 |
| 2026-10-14 | 7,402 | 2,000 |
| 2026-10-15 | 8,269 | 2,000 |
| 2026-10-16 | 15,436 | 2,000 |
| 2026-10-17 | 9,928 | 2,000 |
| 2026-10-18 | 8,644 | 2,000 |
| 2026-10-19 | 5,135 | 2,000 |
| 2026-10-20 | 9,564 | 2,000 |
| 2026-10-21 | 9,514 | 2,000 |
| 2026-10-22 | 10,375 | 2,000 |
| 2026-10-23 | 12,381 | 2,000 |
| 2026-10-24 | 15,055 | 2,000 |
| 2026-10-25 | 11,093 | 2,000 |
| 2026-10-26 | 9,450 | 2,000 |
| 2026-10-27 | 35,263 | 2,000 |
| 2026-10-28 | 11,287 | 2,000 |
| 2026-10-29 | 9,849 | 2,000 |
| 2026-10-30 | 20,147 | 2,000 |
| 2026-10-31 | 17,084 | 2,000 |
| 2026-11-01 | 15,385 | 2,000 |
| 2026-11-02 | 11,963 | 2,000 |
| 2026-11-03 | 16,676 | 2,000 |
| 2026-11-04 | 10,114 | 2,000 |
| 2026-11-05 | 7,324 | 2,000 |

> Hinweis: Der Rueckstau von 2,900,979 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-07 | 14,942 |
| 2026-10-08 | 60,961 |
| 2026-10-09 | 220,947 |
| 2026-10-10 | 53,271 |
| 2026-10-11 | 15,999 |
| 2026-10-12 | 66,512 |
| 2026-10-13 | 1,580,819 |
| 2026-10-14 | 32,908 |
| 2026-10-15 | 41,292 |
| 2026-10-16 | 51,176 |
| 2026-10-17 | 24,187 |
| 2026-10-18 | 14,198 |
| 2026-10-19 | 22,115 |
| 2026-10-20 | 11,089 |
| 2026-10-21 | 11,048 |
| 2026-10-22 | 30,544 |
| 2026-10-23 | 50,289 |
| 2026-10-24 | 41,626 |
| 2026-10-25 | 21,531 |
| 2026-10-26 | 20,255 |
| 2026-10-27 | 20,587 |
| 2026-10-28 | 15,725 |
| 2026-10-29 | 9,622 |
| 2026-10-30 | 61,723 |
| 2026-10-31 | 88,115 |
| 2026-11-01 | 27,780 |
| 2026-11-02 | 28,734 |
| 2026-11-03 | 29,690 |
| 2026-11-04 | 29,550 |
| 2026-11-05 | 25,213 |
| 2026-11-06 | 36,284 |
| 2026-11-07 | 24,409 |
| 2026-11-08 | 26,076 |
| 2026-11-09 | 25,508 |
| 2026-11-10 | 32,658 |
| 2026-11-11 | 22,325 |
| 2026-11-12 | 20,474 |
| 2026-11-13 | 19,631 |
| 2026-11-14 | 22,935 |
| 2026-11-15 | 17,440 |
| 2026-11-16 | 17,940 |
| 2026-11-17 | 15,228 |
| 2026-11-18 | 19,481 |
| 2026-11-19 | 173,669 |
| 2026-11-20 | 26,129 |
| 2026-11-21 | 61,337 |
| 2026-11-22 | 30,404 |
| 2026-11-23 | 25,653 |
| 2026-11-24 | 26,450 |
| 2026-11-25 | 27,522 |
| 2026-11-26 | 28,645 |
| 2026-11-27 | 27,832 |
| 2026-11-28 | 109,198 |
| 2026-11-29 | 28,178 |
| 2026-11-30 | 25,546 |
| 2026-12-01 | 26,551 |
| 2026-12-02 | 26,198 |
| 2026-12-03 | 26,033 |
| 2026-12-04 | 27,920 |
| 2026-12-05 | 25,965 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
