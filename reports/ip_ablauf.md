# Seen-DB Expiry Forecast

Lauf: 2026-09-29 02:20 CEST (Europe/Berlin)
Gesamt: 11,847,341 IPs in seen_db.json (8,965,883 aktiv/180-Tage-Pfad, 2,881,458 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 97,181 |
| 8-14 Tage | 2,017,763 |
| 15-30 Tage | 419,403 |
| 31-60 Tage | 1,130,658 |
| 61-90 Tage | 772,822 |
| 91-180 Tage | 4,528,056 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 1,246,029 |
| 0-3 Tage | 1,373,254 |
| 4-7 Tage | 20,657 |
| 8-14 Tage | 51,333 |
| 15-30 Tage | 190,185 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-30 | 59,457 |
| 2026-10-01 | 7,616 |
| 2026-10-02 | 1,306,181 |
| 2026-10-03 | 2,954 |
| 2026-10-04 | 6,861 |
| 2026-10-05 | 2,871 |
| 2026-10-06 | 7,971 |
| 2026-10-07 | 7,922 |
| 2026-10-08 | 7,273 |
| 2026-10-09 | 10,153 |
| 2026-10-10 | 7,561 |
| 2026-10-11 | 6,255 |
| 2026-10-12 | 3,874 |
| 2026-10-13 | 8,295 |
| 2026-10-14 | 7,443 |
| 2026-10-15 | 8,324 |
| 2026-10-16 | 15,502 |
| 2026-10-17 | 9,960 |
| 2026-10-18 | 8,688 |
| 2026-10-19 | 5,170 |
| 2026-10-20 | 9,650 |
| 2026-10-21 | 9,587 |
| 2026-10-22 | 10,468 |
| 2026-10-23 | 12,502 |
| 2026-10-24 | 15,175 |
| 2026-10-25 | 11,164 |
| 2026-10-26 | 9,533 |
| 2026-10-27 | 35,444 |
| 2026-10-28 | 11,420 |
| 2026-10-29 | 10,155 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **1,246,029** IPs. Brutto faellig in den naechsten 30 Tagen: **1,635,429**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,821,458**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-30 | 59,457 | 2,000 |
| 2026-10-01 | 7,616 | 2,000 |
| 2026-10-02 | 1,306,181 | 2,000 |
| 2026-10-03 | 2,954 | 2,000 |
| 2026-10-04 | 6,861 | 2,000 |
| 2026-10-05 | 2,871 | 2,000 |
| 2026-10-06 | 7,971 | 2,000 |
| 2026-10-07 | 7,922 | 2,000 |
| 2026-10-08 | 7,273 | 2,000 |
| 2026-10-09 | 10,153 | 2,000 |
| 2026-10-10 | 7,561 | 2,000 |
| 2026-10-11 | 6,255 | 2,000 |
| 2026-10-12 | 3,874 | 2,000 |
| 2026-10-13 | 8,295 | 2,000 |
| 2026-10-14 | 7,443 | 2,000 |
| 2026-10-15 | 8,324 | 2,000 |
| 2026-10-16 | 15,502 | 2,000 |
| 2026-10-17 | 9,960 | 2,000 |
| 2026-10-18 | 8,688 | 2,000 |
| 2026-10-19 | 5,170 | 2,000 |
| 2026-10-20 | 9,650 | 2,000 |
| 2026-10-21 | 9,587 | 2,000 |
| 2026-10-22 | 10,468 | 2,000 |
| 2026-10-23 | 12,502 | 2,000 |
| 2026-10-24 | 15,175 | 2,000 |
| 2026-10-25 | 11,164 | 2,000 |
| 2026-10-26 | 9,533 | 2,000 |
| 2026-10-27 | 35,444 | 2,000 |
| 2026-10-28 | 11,420 | 2,000 |
| 2026-10-29 | 10,155 | 2,000 |

> Hinweis: Der Rueckstau von 2,821,458 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-29 | 9,326 |
| 2026-09-30 | 10,138 |
| 2026-10-01 | 16,558 |
| 2026-10-02 | 7,697 |
| 2026-10-03 | 7,309 |
| 2026-10-04 | 12,579 |
| 2026-10-05 | 17,500 |
| 2026-10-06 | 16,074 |
| 2026-10-07 | 15,011 |
| 2026-10-08 | 61,247 |
| 2026-10-09 | 222,043 |
| 2026-10-10 | 53,330 |
| 2026-10-11 | 16,030 |
| 2026-10-12 | 66,556 |
| 2026-10-13 | 1,583,546 |
| 2026-10-14 | 32,915 |
| 2026-10-15 | 41,323 |
| 2026-10-16 | 51,274 |
| 2026-10-17 | 24,256 |
| 2026-10-18 | 14,254 |
| 2026-10-19 | 22,286 |
| 2026-10-20 | 11,131 |
| 2026-10-21 | 11,096 |
| 2026-10-22 | 30,715 |
| 2026-10-23 | 50,400 |
| 2026-10-24 | 41,701 |
| 2026-10-25 | 21,599 |
| 2026-10-26 | 20,317 |
| 2026-10-27 | 20,673 |
| 2026-10-28 | 15,791 |
| 2026-10-29 | 9,672 |
| 2026-10-30 | 61,912 |
| 2026-10-31 | 88,210 |
| 2026-11-01 | 27,864 |
| 2026-11-02 | 28,817 |
| 2026-11-03 | 29,792 |
| 2026-11-04 | 29,633 |
| 2026-11-05 | 25,284 |
| 2026-11-06 | 36,393 |
| 2026-11-07 | 24,481 |
| 2026-11-08 | 26,133 |
| 2026-11-09 | 25,573 |
| 2026-11-10 | 32,754 |
| 2026-11-11 | 22,391 |
| 2026-11-12 | 20,523 |
| 2026-11-13 | 19,673 |
| 2026-11-14 | 22,996 |
| 2026-11-15 | 17,481 |
| 2026-11-16 | 17,989 |
| 2026-11-17 | 15,274 |
| 2026-11-18 | 19,529 |
| 2026-11-19 | 173,996 |
| 2026-11-20 | 26,211 |
| 2026-11-21 | 61,497 |
| 2026-11-22 | 30,494 |
| 2026-11-23 | 25,730 |
| 2026-11-24 | 26,524 |
| 2026-11-25 | 27,608 |
| 2026-11-26 | 28,709 |
| 2026-11-27 | 27,889 |
| 2026-11-28 | 109,298 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
