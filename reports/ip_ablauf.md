# Seen-DB Expiry Forecast

Lauf: 2026-09-25 17:29 CEST (Europe/Berlin)
Gesamt: 11,678,981 IPs in seen_db.json (8,854,142 aktiv/180-Tage-Pfad, 2,824,839 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 87,784 |
| 8-14 Tage | 352,304 |
| 15-30 Tage | 2,073,484 |
| 31-60 Tage | 1,004,401 |
| 61-90 Tage | 880,496 |
| 91-180 Tage | 4,455,673 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 611,120 |
| 0-3 Tage | 636,139 |
| 4-7 Tage | 1,373,866 |
| 8-14 Tage | 46,183 |
| 15-30 Tage | 157,531 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-25 | 5,439 |
| 2026-09-26 | 623,670 |
| 2026-09-27 | 6,260 |
| 2026-09-28 | 770 |
| 2026-09-30 | 59,628 |
| 2026-10-01 | 7,631 |
| 2026-10-02 | 1,306,607 |
| 2026-10-03 | 2,962 |
| 2026-10-04 | 6,910 |
| 2026-10-05 | 2,898 |
| 2026-10-06 | 8,018 |
| 2026-10-07 | 7,942 |
| 2026-10-08 | 7,284 |
| 2026-10-09 | 10,169 |
| 2026-10-10 | 7,575 |
| 2026-10-11 | 6,265 |
| 2026-10-12 | 3,879 |
| 2026-10-13 | 8,320 |
| 2026-10-14 | 7,460 |
| 2026-10-15 | 8,339 |
| 2026-10-16 | 15,522 |
| 2026-10-17 | 9,971 |
| 2026-10-18 | 8,706 |
| 2026-10-19 | 5,183 |
| 2026-10-20 | 9,681 |
| 2026-10-21 | 9,624 |
| 2026-10-22 | 10,511 |
| 2026-10-23 | 12,566 |
| 2026-10-24 | 15,273 |
| 2026-10-25 | 11,228 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **611,120** IPs. Brutto faellig in den naechsten 30 Tagen: **2,206,291**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,757,411**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-25 | 5,439 | 2,000 |
| 2026-09-26 | 623,670 | 2,000 |
| 2026-09-27 | 6,260 | 2,000 |
| 2026-09-28 | 770 | 2,000 |
| 2026-09-30 | 59,628 | 2,000 |
| 2026-10-01 | 7,631 | 2,000 |
| 2026-10-02 | 1,306,607 | 2,000 |
| 2026-10-03 | 2,962 | 2,000 |
| 2026-10-04 | 6,910 | 2,000 |
| 2026-10-05 | 2,898 | 2,000 |
| 2026-10-06 | 8,018 | 2,000 |
| 2026-10-07 | 7,942 | 2,000 |
| 2026-10-08 | 7,284 | 2,000 |
| 2026-10-09 | 10,169 | 2,000 |
| 2026-10-10 | 7,575 | 2,000 |
| 2026-10-11 | 6,265 | 2,000 |
| 2026-10-12 | 3,879 | 2,000 |
| 2026-10-13 | 8,320 | 2,000 |
| 2026-10-14 | 7,460 | 2,000 |
| 2026-10-15 | 8,339 | 2,000 |
| 2026-10-16 | 15,522 | 2,000 |
| 2026-10-17 | 9,971 | 2,000 |
| 2026-10-18 | 8,706 | 2,000 |
| 2026-10-19 | 5,183 | 2,000 |
| 2026-10-20 | 9,681 | 2,000 |
| 2026-10-21 | 9,624 | 2,000 |
| 2026-10-22 | 10,511 | 2,000 |
| 2026-10-23 | 12,566 | 2,000 |
| 2026-10-24 | 15,273 | 2,000 |
| 2026-10-25 | 11,228 | 2,000 |

> Hinweis: Der Rueckstau von 2,757,411 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-26 | 17,413 |
| 2026-09-27 | 15,000 |
| 2026-09-28 | 11,592 |
| 2026-09-29 | 9,339 |
| 2026-09-30 | 10,155 |
| 2026-10-01 | 16,574 |
| 2026-10-02 | 7,711 |
| 2026-10-03 | 7,319 |
| 2026-10-04 | 12,596 |
| 2026-10-05 | 17,516 |
| 2026-10-06 | 16,099 |
| 2026-10-07 | 15,027 |
| 2026-10-08 | 61,325 |
| 2026-10-09 | 222,422 |
| 2026-10-10 | 53,354 |
| 2026-10-11 | 16,042 |
| 2026-10-12 | 66,569 |
| 2026-10-13 | 1,584,362 |
| 2026-10-14 | 32,919 |
| 2026-10-15 | 41,334 |
| 2026-10-16 | 51,291 |
| 2026-10-17 | 24,271 |
| 2026-10-18 | 14,265 |
| 2026-10-19 | 22,330 |
| 2026-10-20 | 11,138 |
| 2026-10-21 | 11,112 |
| 2026-10-22 | 30,738 |
| 2026-10-23 | 50,417 |
| 2026-10-24 | 41,722 |
| 2026-10-25 | 21,620 |
| 2026-10-26 | 20,343 |
| 2026-10-27 | 20,700 |
| 2026-10-28 | 15,805 |
| 2026-10-29 | 9,685 |
| 2026-10-30 | 61,956 |
| 2026-10-31 | 88,243 |
| 2026-11-01 | 27,876 |
| 2026-11-02 | 28,843 |
| 2026-11-03 | 29,830 |
| 2026-11-04 | 29,660 |
| 2026-11-05 | 25,305 |
| 2026-11-06 | 36,435 |
| 2026-11-07 | 24,498 |
| 2026-11-08 | 26,155 |
| 2026-11-09 | 25,591 |
| 2026-11-10 | 32,782 |
| 2026-11-11 | 22,416 |
| 2026-11-12 | 20,534 |
| 2026-11-13 | 19,690 |
| 2026-11-14 | 23,009 |
| 2026-11-15 | 17,489 |
| 2026-11-16 | 18,001 |
| 2026-11-17 | 15,275 |
| 2026-11-18 | 19,540 |
| 2026-11-19 | 174,123 |
| 2026-11-20 | 26,236 |
| 2026-11-21 | 61,556 |
| 2026-11-22 | 30,523 |
| 2026-11-23 | 25,758 |
| 2026-11-24 | 26,544 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
