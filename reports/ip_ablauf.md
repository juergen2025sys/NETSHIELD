# Seen-DB Expiry Forecast

Lauf: 2026-11-18 11:38 CET (Europe/Berlin)
Gesamt: 11,378,459 IPs in seen_db.json (8,115,495 aktiv/180-Tage-Pfad, 3,262,964 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 369,565 |
| 8-14 Tage | 271,140 |
| 15-30 Tage | 441,000 |
| 31-60 Tage | 690,567 |
| 61-90 Tage | 1,420,101 |
| 91-180 Tage | 4,923,122 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 3,052,844 |
| 0-3 Tage | 32,926 |
| 4-7 Tage | 37,643 |
| 8-14 Tage | 38,578 |
| 15-30 Tage | 100,973 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-18 | 3,455 |
| 2026-11-19 | 8,741 |
| 2026-11-20 | 10,820 |
| 2026-11-21 | 9,910 |
| 2026-11-22 | 9,966 |
| 2026-11-23 | 9,993 |
| 2026-11-24 | 10,084 |
| 2026-11-25 | 7,600 |
| 2026-11-26 | 3,332 |
| 2026-11-27 | 3,852 |
| 2026-11-28 | 3,531 |
| 2026-11-29 | 8,121 |
| 2026-11-30 | 7,102 |
| 2026-12-01 | 8,068 |
| 2026-12-02 | 4,572 |
| 2026-12-03 | 7,712 |
| 2026-12-04 | 5,751 |
| 2026-12-05 | 5,394 |
| 2026-12-06 | 3,088 |
| 2026-12-07 | 7,786 |
| 2026-12-08 | 4,461 |
| 2026-12-09 | 9,015 |
| 2026-12-10 | 6,004 |
| 2026-12-11 | 4,660 |
| 2026-12-12 | 2,594 |
| 2026-12-13 | 3,007 |
| 2026-12-14 | 7,640 |
| 2026-12-15 | 8,136 |
| 2026-12-16 | 7,561 |
| 2026-12-17 | 7,729 |
| 2026-12-18 | 9,427 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **3,052,844** IPs. Brutto faellig in den naechsten 30 Tagen: **209,112**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,199,956**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-18 | 3,455 | 2,000 |
| 2026-11-19 | 8,741 | 2,000 |
| 2026-11-20 | 10,820 | 2,000 |
| 2026-11-21 | 9,910 | 2,000 |
| 2026-11-22 | 9,966 | 2,000 |
| 2026-11-23 | 9,993 | 2,000 |
| 2026-11-24 | 10,084 | 2,000 |
| 2026-11-25 | 7,600 | 2,000 |
| 2026-11-26 | 3,332 | 2,000 |
| 2026-11-27 | 3,852 | 2,000 |
| 2026-11-28 | 3,531 | 2,000 |
| 2026-11-29 | 8,121 | 2,000 |
| 2026-11-30 | 7,102 | 2,000 |
| 2026-12-01 | 8,068 | 2,000 |
| 2026-12-02 | 4,572 | 2,000 |
| 2026-12-03 | 7,712 | 2,000 |
| 2026-12-04 | 5,751 | 2,000 |
| 2026-12-05 | 5,394 | 2,000 |
| 2026-12-06 | 3,088 | 2,000 |
| 2026-12-07 | 7,786 | 2,000 |
| 2026-12-08 | 4,461 | 2,000 |
| 2026-12-09 | 9,015 | 2,000 |
| 2026-12-10 | 6,004 | 2,000 |
| 2026-12-11 | 4,660 | 2,000 |
| 2026-12-12 | 2,594 | 2,000 |
| 2026-12-13 | 3,007 | 2,000 |
| 2026-12-14 | 7,640 | 2,000 |
| 2026-12-15 | 8,136 | 2,000 |
| 2026-12-16 | 7,561 | 2,000 |
| 2026-12-17 | 7,729 | 2,000 |
| 2026-12-18 | 9,427 | 2,000 |

> Hinweis: Der Rueckstau von 3,199,956 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-19 | 173,112 |
| 2026-11-20 | 25,984 |
| 2026-11-21 | 61,076 |
| 2026-11-22 | 30,230 |
| 2026-11-23 | 25,510 |
| 2026-11-24 | 26,313 |
| 2026-11-25 | 27,340 |
| 2026-11-26 | 28,520 |
| 2026-11-27 | 27,711 |
| 2026-11-28 | 108,973 |
| 2026-11-29 | 28,051 |
| 2026-11-30 | 25,401 |
| 2026-12-01 | 26,428 |
| 2026-12-02 | 26,056 |
| 2026-12-03 | 25,869 |
| 2026-12-04 | 27,796 |
| 2026-12-05 | 25,842 |
| 2026-12-06 | 29,995 |
| 2026-12-07 | 23,637 |
| 2026-12-08 | 39,226 |
| 2026-12-09 | 54,672 |
| 2026-12-10 | 24,981 |
| 2026-12-11 | 27,641 |
| 2026-12-12 | 24,274 |
| 2026-12-13 | 23,735 |
| 2026-12-14 | 23,351 |
| 2026-12-15 | 26,125 |
| 2026-12-16 | 16,540 |
| 2026-12-17 | 24,907 |
| 2026-12-18 | 22,409 |
| 2026-12-19 | 25,475 |
| 2026-12-20 | 14,250 |
| 2026-12-21 | 27,224 |
| 2026-12-22 | 23,999 |
| 2026-12-23 | 21,035 |
| 2026-12-24 | 20,329 |
| 2026-12-25 | 21,550 |
| 2026-12-26 | 17,743 |
| 2026-12-27 | 24,565 |
| 2026-12-28 | 21,673 |
| 2026-12-29 | 22,507 |
| 2026-12-30 | 26,452 |
| 2026-12-31 | 20,106 |
| 2027-01-01 | 18,458 |
| 2027-01-02 | 26,059 |
| 2027-01-03 | 14,778 |
| 2027-01-04 | 28,404 |
| 2027-01-05 | 22,334 |
| 2027-01-06 | 35,517 |
| 2027-01-07 | 23,910 |
| 2027-01-08 | 25,813 |
| 2027-01-09 | 21,571 |
| 2027-01-10 | 24,681 |
| 2027-01-11 | 24,086 |
| 2027-01-12 | 22,962 |
| 2027-01-13 | 23,251 |
| 2027-01-14 | 21,859 |
| 2027-01-15 | 22,691 |
| 2027-01-16 | 26,758 |
| 2027-01-17 | 20,527 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
