# Seen-DB Expiry Forecast

Lauf: 2026-10-21 21:32 CEST (Europe/Berlin)
Gesamt: 11,076,630 IPs in seen_db.json (7,964,494 aktiv/180-Tage-Pfad, 3,112,136 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 199,699 |
| 8-14 Tage | 274,492 |
| 15-30 Tage | 524,197 |
| 31-60 Tage | 925,140 |
| 61-90 Tage | 700,815 |
| 91-180 Tage | 5,340,151 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,715,377 |
| 0-3 Tage | 47,111 |
| 4-7 Tage | 66,761 |
| 8-14 Tage | 100,533 |
| 15-30 Tage | 182,354 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-21 | 9,466 |
| 2026-10-22 | 10,327 |
| 2026-10-23 | 12,325 |
| 2026-10-24 | 14,993 |
| 2026-10-25 | 11,047 |
| 2026-10-26 | 9,401 |
| 2026-10-27 | 35,070 |
| 2026-10-28 | 11,243 |
| 2026-10-29 | 9,799 |
| 2026-10-30 | 20,041 |
| 2026-10-31 | 16,896 |
| 2026-11-01 | 15,307 |
| 2026-11-02 | 11,870 |
| 2026-11-03 | 16,581 |
| 2026-11-04 | 10,039 |
| 2026-11-05 | 7,216 |
| 2026-11-06 | 12,043 |
| 2026-11-07 | 13,333 |
| 2026-11-08 | 6,253 |
| 2026-11-09 | 11,460 |
| 2026-11-10 | 23,806 |
| 2026-11-11 | 9,879 |
| 2026-11-12 | 8,036 |
| 2026-11-13 | 3,328 |
| 2026-11-14 | 11,601 |
| 2026-11-15 | 14,331 |
| 2026-11-16 | 18,931 |
| 2026-11-17 | 9,340 |
| 2026-11-18 | 3,511 |
| 2026-11-19 | 8,874 |
| 2026-11-20 | 10,996 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,715,377** IPs. Brutto faellig in den naechsten 30 Tagen: **387,343**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,040,720**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-21 | 9,466 | 2,000 |
| 2026-10-22 | 10,327 | 2,000 |
| 2026-10-23 | 12,325 | 2,000 |
| 2026-10-24 | 14,993 | 2,000 |
| 2026-10-25 | 11,047 | 2,000 |
| 2026-10-26 | 9,401 | 2,000 |
| 2026-10-27 | 35,070 | 2,000 |
| 2026-10-28 | 11,243 | 2,000 |
| 2026-10-29 | 9,799 | 2,000 |
| 2026-10-30 | 20,041 | 2,000 |
| 2026-10-31 | 16,896 | 2,000 |
| 2026-11-01 | 15,307 | 2,000 |
| 2026-11-02 | 11,870 | 2,000 |
| 2026-11-03 | 16,581 | 2,000 |
| 2026-11-04 | 10,039 | 2,000 |
| 2026-11-05 | 7,216 | 2,000 |
| 2026-11-06 | 12,043 | 2,000 |
| 2026-11-07 | 13,333 | 2,000 |
| 2026-11-08 | 6,253 | 2,000 |
| 2026-11-09 | 11,460 | 2,000 |
| 2026-11-10 | 23,806 | 2,000 |
| 2026-11-11 | 9,879 | 2,000 |
| 2026-11-12 | 8,036 | 2,000 |
| 2026-11-13 | 3,328 | 2,000 |
| 2026-11-14 | 11,601 | 2,000 |
| 2026-11-15 | 14,331 | 2,000 |
| 2026-11-16 | 18,931 | 2,000 |
| 2026-11-17 | 9,340 | 2,000 |
| 2026-11-18 | 3,511 | 2,000 |
| 2026-11-19 | 8,874 | 2,000 |
| 2026-11-20 | 10,996 | 2,000 |

> Hinweis: Der Rueckstau von 3,040,720 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-22 | 30,437 |
| 2026-10-23 | 50,179 |
| 2026-10-24 | 41,546 |
| 2026-10-25 | 21,465 |
| 2026-10-26 | 20,174 |
| 2026-10-27 | 20,391 |
| 2026-10-28 | 15,507 |
| 2026-10-29 | 9,495 |
| 2026-10-30 | 61,555 |
| 2026-10-31 | 88,021 |
| 2026-11-01 | 27,710 |
| 2026-11-02 | 28,658 |
| 2026-11-03 | 29,597 |
| 2026-11-04 | 29,456 |
| 2026-11-05 | 25,142 |
| 2026-11-06 | 36,189 |
| 2026-11-07 | 24,341 |
| 2026-11-08 | 26,002 |
| 2026-11-09 | 25,431 |
| 2026-11-10 | 32,589 |
| 2026-11-11 | 22,258 |
| 2026-11-12 | 20,432 |
| 2026-11-13 | 19,577 |
| 2026-11-14 | 22,872 |
| 2026-11-15 | 17,396 |
| 2026-11-16 | 17,889 |
| 2026-11-17 | 15,180 |
| 2026-11-18 | 19,438 |
| 2026-11-19 | 173,400 |
| 2026-11-20 | 26,061 |
| 2026-11-21 | 61,224 |
| 2026-11-22 | 30,325 |
| 2026-11-23 | 25,583 |
| 2026-11-24 | 26,395 |
| 2026-11-25 | 27,440 |
| 2026-11-26 | 28,589 |
| 2026-11-27 | 27,776 |
| 2026-11-28 | 109,108 |
| 2026-11-29 | 28,117 |
| 2026-11-30 | 25,471 |
| 2026-12-01 | 26,483 |
| 2026-12-02 | 26,132 |
| 2026-12-03 | 25,954 |
| 2026-12-04 | 27,864 |
| 2026-12-05 | 25,908 |
| 2026-12-06 | 30,080 |
| 2026-12-07 | 23,694 |
| 2026-12-08 | 39,323 |
| 2026-12-09 | 55,020 |
| 2026-12-10 | 25,052 |
| 2026-12-11 | 27,732 |
| 2026-12-12 | 24,357 |
| 2026-12-13 | 23,824 |
| 2026-12-14 | 23,440 |
| 2026-12-15 | 26,221 |
| 2026-12-16 | 16,641 |
| 2026-12-17 | 24,991 |
| 2026-12-18 | 22,493 |
| 2026-12-19 | 25,590 |
| 2026-12-20 | 14,313 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
