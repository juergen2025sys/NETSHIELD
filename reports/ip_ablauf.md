# Seen-DB Expiry Forecast

Lauf: 2026-09-25 06:40 CEST (Europe/Berlin)
Gesamt: 11,640,965 IPs in seen_db.json (8,823,720 aktiv/180-Tage-Pfad, 2,817,245 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 87,810 |
| 8-14 Tage | 352,397 |
| 15-30 Tage | 2,073,659 |
| 31-60 Tage | 1,004,587 |
| 61-90 Tage | 880,663 |
| 91-180 Tage | 4,424,604 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 609,250 |
| 0-3 Tage | 636,162 |
| 4-7 Tage | 1,373,973 |
| 8-14 Tage | 46,208 |
| 15-30 Tage | 151,652 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-25 | 5,440 |
| 2026-09-26 | 623,690 |
| 2026-09-27 | 6,261 |
| 2026-09-28 | 771 |
| 2026-09-30 | 59,633 |
| 2026-10-01 | 7,632 |
| 2026-10-02 | 1,306,708 |
| 2026-10-03 | 2,965 |
| 2026-10-04 | 6,912 |
| 2026-10-05 | 2,900 |
| 2026-10-06 | 8,025 |
| 2026-10-07 | 7,947 |
| 2026-10-08 | 7,284 |
| 2026-10-09 | 10,175 |
| 2026-10-10 | 7,575 |
| 2026-10-11 | 6,270 |
| 2026-10-12 | 3,879 |
| 2026-10-13 | 8,321 |
| 2026-10-14 | 7,465 |
| 2026-10-15 | 8,342 |
| 2026-10-16 | 15,526 |
| 2026-10-17 | 9,973 |
| 2026-10-18 | 8,714 |
| 2026-10-19 | 5,186 |
| 2026-10-20 | 9,687 |
| 2026-10-21 | 9,630 |
| 2026-10-22 | 10,524 |
| 2026-10-23 | 12,590 |
| 2026-10-24 | 15,316 |
| 2026-10-25 | 11,474 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **609,250** IPs. Brutto faellig in den naechsten 30 Tagen: **2,206,815**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,756,065**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-25 | 5,440 | 2,000 |
| 2026-09-26 | 623,690 | 2,000 |
| 2026-09-27 | 6,261 | 2,000 |
| 2026-09-28 | 771 | 2,000 |
| 2026-09-30 | 59,633 | 2,000 |
| 2026-10-01 | 7,632 | 2,000 |
| 2026-10-02 | 1,306,708 | 2,000 |
| 2026-10-03 | 2,965 | 2,000 |
| 2026-10-04 | 6,912 | 2,000 |
| 2026-10-05 | 2,900 | 2,000 |
| 2026-10-06 | 8,025 | 2,000 |
| 2026-10-07 | 7,947 | 2,000 |
| 2026-10-08 | 7,284 | 2,000 |
| 2026-10-09 | 10,175 | 2,000 |
| 2026-10-10 | 7,575 | 2,000 |
| 2026-10-11 | 6,270 | 2,000 |
| 2026-10-12 | 3,879 | 2,000 |
| 2026-10-13 | 8,321 | 2,000 |
| 2026-10-14 | 7,465 | 2,000 |
| 2026-10-15 | 8,342 | 2,000 |
| 2026-10-16 | 15,526 | 2,000 |
| 2026-10-17 | 9,973 | 2,000 |
| 2026-10-18 | 8,714 | 2,000 |
| 2026-10-19 | 5,186 | 2,000 |
| 2026-10-20 | 9,687 | 2,000 |
| 2026-10-21 | 9,630 | 2,000 |
| 2026-10-22 | 10,524 | 2,000 |
| 2026-10-23 | 12,590 | 2,000 |
| 2026-10-24 | 15,316 | 2,000 |
| 2026-10-25 | 11,474 | 2,000 |

> Hinweis: Der Rueckstau von 2,756,065 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-26 | 17,418 |
| 2026-09-27 | 15,007 |
| 2026-09-28 | 11,593 |
| 2026-09-29 | 9,341 |
| 2026-09-30 | 10,160 |
| 2026-10-01 | 16,579 |
| 2026-10-02 | 7,712 |
| 2026-10-03 | 7,320 |
| 2026-10-04 | 12,601 |
| 2026-10-05 | 17,518 |
| 2026-10-06 | 16,101 |
| 2026-10-07 | 15,031 |
| 2026-10-08 | 61,341 |
| 2026-10-09 | 222,485 |
| 2026-10-10 | 53,357 |
| 2026-10-11 | 16,043 |
| 2026-10-12 | 66,573 |
| 2026-10-13 | 1,584,483 |
| 2026-10-14 | 32,919 |
| 2026-10-15 | 41,337 |
| 2026-10-16 | 51,294 |
| 2026-10-17 | 24,282 |
| 2026-10-18 | 14,269 |
| 2026-10-19 | 22,339 |
| 2026-10-20 | 11,140 |
| 2026-10-21 | 11,114 |
| 2026-10-22 | 30,741 |
| 2026-10-23 | 50,419 |
| 2026-10-24 | 41,726 |
| 2026-10-25 | 21,623 |
| 2026-10-26 | 20,345 |
| 2026-10-27 | 20,703 |
| 2026-10-28 | 15,808 |
| 2026-10-29 | 9,687 |
| 2026-10-30 | 61,968 |
| 2026-10-31 | 88,247 |
| 2026-11-01 | 27,882 |
| 2026-11-02 | 28,845 |
| 2026-11-03 | 29,847 |
| 2026-11-04 | 29,664 |
| 2026-11-05 | 25,309 |
| 2026-11-06 | 36,444 |
| 2026-11-07 | 24,501 |
| 2026-11-08 | 26,164 |
| 2026-11-09 | 25,596 |
| 2026-11-10 | 32,788 |
| 2026-11-11 | 22,423 |
| 2026-11-12 | 20,540 |
| 2026-11-13 | 19,692 |
| 2026-11-14 | 23,012 |
| 2026-11-15 | 17,492 |
| 2026-11-16 | 18,008 |
| 2026-11-17 | 15,277 |
| 2026-11-18 | 19,542 |
| 2026-11-19 | 174,153 |
| 2026-11-20 | 26,244 |
| 2026-11-21 | 61,567 |
| 2026-11-22 | 30,526 |
| 2026-11-23 | 25,762 |
| 2026-11-24 | 26,551 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
