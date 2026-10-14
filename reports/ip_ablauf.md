# Seen-DB Expiry Forecast

Lauf: 2026-10-14 23:33 CEST (Europe/Berlin)
Gesamt: 10,810,021 IPs in seen_db.json (7,768,185 aktiv/180-Tage-Pfad, 3,041,836 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 174,776 |
| 8-14 Tage | 200,029 |
| 15-30 Tage | 506,929 |
| 31-60 Tage | 1,064,457 |
| 61-90 Tage | 692,283 |
| 91-180 Tage | 5,129,711 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,656,880 |
| 0-3 Tage | 40,944 |
| 4-7 Tage | 32,716 |
| 8-14 Tage | 104,519 |
| 15-30 Tage | 206,777 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-14 | 7,380 |
| 2026-10-15 | 8,250 |
| 2026-10-16 | 15,406 |
| 2026-10-17 | 9,908 |
| 2026-10-18 | 8,613 |
| 2026-10-19 | 5,113 |
| 2026-10-20 | 9,515 |
| 2026-10-21 | 9,475 |
| 2026-10-22 | 10,339 |
| 2026-10-23 | 12,338 |
| 2026-10-24 | 15,007 |
| 2026-10-25 | 11,060 |
| 2026-10-26 | 9,409 |
| 2026-10-27 | 35,116 |
| 2026-10-28 | 11,250 |
| 2026-10-29 | 9,810 |
| 2026-10-30 | 20,057 |
| 2026-10-31 | 16,920 |
| 2026-11-01 | 15,321 |
| 2026-11-02 | 11,882 |
| 2026-11-03 | 16,593 |
| 2026-11-04 | 10,050 |
| 2026-11-05 | 7,233 |
| 2026-11-06 | 12,057 |
| 2026-11-07 | 13,359 |
| 2026-11-08 | 6,268 |
| 2026-11-09 | 11,489 |
| 2026-11-10 | 23,864 |
| 2026-11-11 | 9,919 |
| 2026-11-12 | 8,083 |
| 2026-11-13 | 3,391 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,656,880** IPs. Brutto faellig in den naechsten 30 Tagen: **374,475**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **2,969,355**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-14 | 7,380 | 2,000 |
| 2026-10-15 | 8,250 | 2,000 |
| 2026-10-16 | 15,406 | 2,000 |
| 2026-10-17 | 9,908 | 2,000 |
| 2026-10-18 | 8,613 | 2,000 |
| 2026-10-19 | 5,113 | 2,000 |
| 2026-10-20 | 9,515 | 2,000 |
| 2026-10-21 | 9,475 | 2,000 |
| 2026-10-22 | 10,339 | 2,000 |
| 2026-10-23 | 12,338 | 2,000 |
| 2026-10-24 | 15,007 | 2,000 |
| 2026-10-25 | 11,060 | 2,000 |
| 2026-10-26 | 9,409 | 2,000 |
| 2026-10-27 | 35,116 | 2,000 |
| 2026-10-28 | 11,250 | 2,000 |
| 2026-10-29 | 9,810 | 2,000 |
| 2026-10-30 | 20,057 | 2,000 |
| 2026-10-31 | 16,920 | 2,000 |
| 2026-11-01 | 15,321 | 2,000 |
| 2026-11-02 | 11,882 | 2,000 |
| 2026-11-03 | 16,593 | 2,000 |
| 2026-11-04 | 10,050 | 2,000 |
| 2026-11-05 | 7,233 | 2,000 |
| 2026-11-06 | 12,057 | 2,000 |
| 2026-11-07 | 13,359 | 2,000 |
| 2026-11-08 | 6,268 | 2,000 |
| 2026-11-09 | 11,489 | 2,000 |
| 2026-11-10 | 23,864 | 2,000 |
| 2026-11-11 | 9,919 | 2,000 |
| 2026-11-12 | 8,083 | 2,000 |
| 2026-11-13 | 3,391 | 2,000 |

> Hinweis: Der Rueckstau von 2,969,355 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-15 | 41,267 |
| 2026-10-16 | 51,130 |
| 2026-10-17 | 24,156 |
| 2026-10-18 | 14,161 |
| 2026-10-19 | 21,984 |
| 2026-10-20 | 11,057 |
| 2026-10-21 | 11,021 |
| 2026-10-22 | 30,477 |
| 2026-10-23 | 50,218 |
| 2026-10-24 | 41,575 |
| 2026-10-25 | 21,484 |
| 2026-10-26 | 20,196 |
| 2026-10-27 | 20,466 |
| 2026-10-28 | 15,613 |
| 2026-10-29 | 9,566 |
| 2026-10-30 | 61,599 |
| 2026-10-31 | 88,050 |
| 2026-11-01 | 27,739 |
| 2026-11-02 | 28,684 |
| 2026-11-03 | 29,627 |
| 2026-11-04 | 29,486 |
| 2026-11-05 | 25,162 |
| 2026-11-06 | 36,220 |
| 2026-11-07 | 24,365 |
| 2026-11-08 | 26,024 |
| 2026-11-09 | 25,454 |
| 2026-11-10 | 32,617 |
| 2026-11-11 | 22,286 |
| 2026-11-12 | 20,450 |
| 2026-11-13 | 19,600 |
| 2026-11-14 | 22,900 |
| 2026-11-15 | 17,414 |
| 2026-11-16 | 17,915 |
| 2026-11-17 | 15,197 |
| 2026-11-18 | 19,451 |
| 2026-11-19 | 173,466 |
| 2026-11-20 | 26,086 |
| 2026-11-21 | 61,254 |
| 2026-11-22 | 30,347 |
| 2026-11-23 | 25,605 |
| 2026-11-24 | 26,415 |
| 2026-11-25 | 27,465 |
| 2026-11-26 | 28,605 |
| 2026-11-27 | 27,792 |
| 2026-11-28 | 109,140 |
| 2026-11-29 | 28,129 |
| 2026-11-30 | 25,491 |
| 2026-12-01 | 26,505 |
| 2026-12-02 | 26,160 |
| 2026-12-03 | 25,972 |
| 2026-12-04 | 27,881 |
| 2026-12-05 | 25,926 |
| 2026-12-06 | 30,106 |
| 2026-12-07 | 23,718 |
| 2026-12-08 | 39,345 |
| 2026-12-09 | 55,121 |
| 2026-12-10 | 25,077 |
| 2026-12-11 | 27,749 |
| 2026-12-12 | 24,379 |
| 2026-12-13 | 23,846 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
