# Seen-DB Expiry Forecast

Lauf: 2026-09-25 21:31 CEST (Europe/Berlin)
Gesamt: 11,694,193 IPs in seen_db.json (8,868,152 aktiv/180-Tage-Pfad, 2,826,041 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 87,775 |
| 8-14 Tage | 352,280 |
| 15-30 Tage | 2,073,419 |
| 31-60 Tage | 1,004,357 |
| 61-90 Tage | 880,443 |
| 91-180 Tage | 4,469,878 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 611,096 |
| 0-3 Tage | 636,128 |
| 4-7 Tage | 1,373,851 |
| 8-14 Tage | 46,177 |
| 15-30 Tage | 158,789 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-25 | 5,439 |
| 2026-09-26 | 623,659 |
| 2026-09-27 | 6,260 |
| 2026-09-28 | 770 |
| 2026-09-30 | 59,628 |
| 2026-10-01 | 7,631 |
| 2026-10-02 | 1,306,592 |
| 2026-10-03 | 2,962 |
| 2026-10-04 | 6,910 |
| 2026-10-05 | 2,898 |
| 2026-10-06 | 8,014 |
| 2026-10-07 | 7,941 |
| 2026-10-08 | 7,283 |
| 2026-10-09 | 10,169 |
| 2026-10-10 | 7,574 |
| 2026-10-11 | 6,264 |
| 2026-10-12 | 3,879 |
| 2026-10-13 | 8,319 |
| 2026-10-14 | 7,460 |
| 2026-10-15 | 8,338 |
| 2026-10-16 | 15,519 |
| 2026-10-17 | 9,971 |
| 2026-10-18 | 8,704 |
| 2026-10-19 | 5,181 |
| 2026-10-20 | 9,681 |
| 2026-10-21 | 9,622 |
| 2026-10-22 | 10,508 |
| 2026-10-23 | 12,560 |
| 2026-10-24 | 15,262 |
| 2026-10-25 | 11,225 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **611,096** IPs. Brutto faellig in den naechsten 30 Tagen: **2,206,223**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,757,319**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-25 | 5,439 | 2,000 |
| 2026-09-26 | 623,659 | 2,000 |
| 2026-09-27 | 6,260 | 2,000 |
| 2026-09-28 | 770 | 2,000 |
| 2026-09-30 | 59,628 | 2,000 |
| 2026-10-01 | 7,631 | 2,000 |
| 2026-10-02 | 1,306,592 | 2,000 |
| 2026-10-03 | 2,962 | 2,000 |
| 2026-10-04 | 6,910 | 2,000 |
| 2026-10-05 | 2,898 | 2,000 |
| 2026-10-06 | 8,014 | 2,000 |
| 2026-10-07 | 7,941 | 2,000 |
| 2026-10-08 | 7,283 | 2,000 |
| 2026-10-09 | 10,169 | 2,000 |
| 2026-10-10 | 7,574 | 2,000 |
| 2026-10-11 | 6,264 | 2,000 |
| 2026-10-12 | 3,879 | 2,000 |
| 2026-10-13 | 8,319 | 2,000 |
| 2026-10-14 | 7,460 | 2,000 |
| 2026-10-15 | 8,338 | 2,000 |
| 2026-10-16 | 15,519 | 2,000 |
| 2026-10-17 | 9,971 | 2,000 |
| 2026-10-18 | 8,704 | 2,000 |
| 2026-10-19 | 5,181 | 2,000 |
| 2026-10-20 | 9,681 | 2,000 |
| 2026-10-21 | 9,622 | 2,000 |
| 2026-10-22 | 10,508 | 2,000 |
| 2026-10-23 | 12,560 | 2,000 |
| 2026-10-24 | 15,262 | 2,000 |
| 2026-10-25 | 11,225 | 2,000 |

> Hinweis: Der Rueckstau von 2,757,319 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-26 | 17,410 |
| 2026-09-27 | 14,998 |
| 2026-09-28 | 11,592 |
| 2026-09-29 | 9,337 |
| 2026-09-30 | 10,153 |
| 2026-10-01 | 16,574 |
| 2026-10-02 | 7,711 |
| 2026-10-03 | 7,319 |
| 2026-10-04 | 12,596 |
| 2026-10-05 | 17,515 |
| 2026-10-06 | 16,099 |
| 2026-10-07 | 15,026 |
| 2026-10-08 | 61,322 |
| 2026-10-09 | 222,403 |
| 2026-10-10 | 53,353 |
| 2026-10-11 | 16,042 |
| 2026-10-12 | 66,569 |
| 2026-10-13 | 1,584,306 |
| 2026-10-14 | 32,919 |
| 2026-10-15 | 41,333 |
| 2026-10-16 | 51,290 |
| 2026-10-17 | 24,270 |
| 2026-10-18 | 14,265 |
| 2026-10-19 | 22,328 |
| 2026-10-20 | 11,138 |
| 2026-10-21 | 11,111 |
| 2026-10-22 | 30,737 |
| 2026-10-23 | 50,417 |
| 2026-10-24 | 41,722 |
| 2026-10-25 | 21,619 |
| 2026-10-26 | 20,342 |
| 2026-10-27 | 20,699 |
| 2026-10-28 | 15,805 |
| 2026-10-29 | 9,684 |
| 2026-10-30 | 61,955 |
| 2026-10-31 | 88,242 |
| 2026-11-01 | 27,876 |
| 2026-11-02 | 28,841 |
| 2026-11-03 | 29,825 |
| 2026-11-04 | 29,658 |
| 2026-11-05 | 25,305 |
| 2026-11-06 | 36,435 |
| 2026-11-07 | 24,497 |
| 2026-11-08 | 26,154 |
| 2026-11-09 | 25,591 |
| 2026-11-10 | 32,780 |
| 2026-11-11 | 22,416 |
| 2026-11-12 | 20,533 |
| 2026-11-13 | 19,689 |
| 2026-11-14 | 23,005 |
| 2026-11-15 | 17,489 |
| 2026-11-16 | 18,000 |
| 2026-11-17 | 15,275 |
| 2026-11-18 | 19,538 |
| 2026-11-19 | 174,116 |
| 2026-11-20 | 26,235 |
| 2026-11-21 | 61,551 |
| 2026-11-22 | 30,522 |
| 2026-11-23 | 25,758 |
| 2026-11-24 | 26,541 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
