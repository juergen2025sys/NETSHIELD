# Seen-DB Expiry Forecast

Lauf: 2026-11-22 18:45 CET (Europe/Berlin)
Gesamt: 11,262,927 IPs in seen_db.json (7,940,370 aktiv/180-Tage-Pfad, 3,322,557 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 272,348 |
| 8-14 Tage | 187,326 |
| 15-30 Tage | 422,207 |
| 31-60 Tage | 715,208 |
| 61-90 Tage | 1,447,902 |
| 91-180 Tage | 4,895,379 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 3,080,264 |
| 0-3 Tage | 37,621 |
| 4-7 Tage | 18,819 |
| 8-14 Tage | 41,640 |
| 15-30 Tage | 144,213 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-22 | 9,960 |
| 2026-11-23 | 9,988 |
| 2026-11-24 | 10,080 |
| 2026-11-25 | 7,593 |
| 2026-11-26 | 3,327 |
| 2026-11-27 | 3,847 |
| 2026-11-28 | 3,527 |
| 2026-11-29 | 8,118 |
| 2026-11-30 | 7,095 |
| 2026-12-01 | 8,058 |
| 2026-12-02 | 4,562 |
| 2026-12-03 | 7,706 |
| 2026-12-04 | 5,747 |
| 2026-12-05 | 5,390 |
| 2026-12-06 | 3,082 |
| 2026-12-07 | 7,779 |
| 2026-12-08 | 4,445 |
| 2026-12-09 | 9,006 |
| 2026-12-10 | 5,999 |
| 2026-12-11 | 4,647 |
| 2026-12-12 | 2,582 |
| 2026-12-13 | 2,996 |
| 2026-12-14 | 7,605 |
| 2026-12-15 | 8,094 |
| 2026-12-16 | 7,500 |
| 2026-12-17 | 7,641 |
| 2026-12-18 | 9,376 |
| 2026-12-19 | 1,641 |
| 2026-12-20 | 10,096 |
| 2026-12-21 | 9,035 |
| 2026-12-22 | 31,813 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **3,080,264** IPs. Brutto faellig in den naechsten 30 Tagen: **228,335**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,246,599**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-22 | 9,960 | 2,000 |
| 2026-11-23 | 9,988 | 2,000 |
| 2026-11-24 | 10,080 | 2,000 |
| 2026-11-25 | 7,593 | 2,000 |
| 2026-11-26 | 3,327 | 2,000 |
| 2026-11-27 | 3,847 | 2,000 |
| 2026-11-28 | 3,527 | 2,000 |
| 2026-11-29 | 8,118 | 2,000 |
| 2026-11-30 | 7,095 | 2,000 |
| 2026-12-01 | 8,058 | 2,000 |
| 2026-12-02 | 4,562 | 2,000 |
| 2026-12-03 | 7,706 | 2,000 |
| 2026-12-04 | 5,747 | 2,000 |
| 2026-12-05 | 5,390 | 2,000 |
| 2026-12-06 | 3,082 | 2,000 |
| 2026-12-07 | 7,779 | 2,000 |
| 2026-12-08 | 4,445 | 2,000 |
| 2026-12-09 | 9,006 | 2,000 |
| 2026-12-10 | 5,999 | 2,000 |
| 2026-12-11 | 4,647 | 2,000 |
| 2026-12-12 | 2,582 | 2,000 |
| 2026-12-13 | 2,996 | 2,000 |
| 2026-12-14 | 7,605 | 2,000 |
| 2026-12-15 | 8,094 | 2,000 |
| 2026-12-16 | 7,500 | 2,000 |
| 2026-12-17 | 7,641 | 2,000 |
| 2026-12-18 | 9,376 | 2,000 |
| 2026-12-19 | 1,641 | 2,000 |
| 2026-12-20 | 10,096 | 2,000 |
| 2026-12-21 | 9,035 | 2,000 |
| 2026-12-22 | 31,813 | 2,000 |

> Hinweis: Der Rueckstau von 3,246,599 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-23 | 25,500 |
| 2026-11-24 | 26,306 |
| 2026-11-25 | 27,329 |
| 2026-11-26 | 28,515 |
| 2026-11-27 | 27,703 |
| 2026-11-28 | 108,953 |
| 2026-11-29 | 28,042 |
| 2026-11-30 | 25,395 |
| 2026-12-01 | 26,420 |
| 2026-12-02 | 26,043 |
| 2026-12-03 | 25,861 |
| 2026-12-04 | 27,793 |
| 2026-12-05 | 25,829 |
| 2026-12-06 | 29,985 |
| 2026-12-07 | 23,631 |
| 2026-12-08 | 39,217 |
| 2026-12-09 | 54,625 |
| 2026-12-10 | 24,971 |
| 2026-12-11 | 27,626 |
| 2026-12-12 | 24,264 |
| 2026-12-13 | 23,718 |
| 2026-12-14 | 23,334 |
| 2026-12-15 | 26,112 |
| 2026-12-16 | 16,521 |
| 2026-12-17 | 24,899 |
| 2026-12-18 | 22,400 |
| 2026-12-19 | 25,464 |
| 2026-12-20 | 14,234 |
| 2026-12-21 | 27,209 |
| 2026-12-22 | 23,982 |
| 2026-12-23 | 21,018 |
| 2026-12-24 | 20,319 |
| 2026-12-25 | 21,538 |
| 2026-12-26 | 17,728 |
| 2026-12-27 | 24,553 |
| 2026-12-28 | 21,659 |
| 2026-12-29 | 22,496 |
| 2026-12-30 | 26,435 |
| 2026-12-31 | 20,095 |
| 2027-01-01 | 18,449 |
| 2027-01-02 | 26,041 |
| 2027-01-03 | 14,763 |
| 2027-01-04 | 28,390 |
| 2027-01-05 | 22,315 |
| 2027-01-06 | 35,493 |
| 2027-01-07 | 23,900 |
| 2027-01-08 | 25,800 |
| 2027-01-09 | 21,558 |
| 2027-01-10 | 24,667 |
| 2027-01-11 | 24,075 |
| 2027-01-12 | 22,951 |
| 2027-01-13 | 23,238 |
| 2027-01-14 | 21,851 |
| 2027-01-15 | 22,682 |
| 2027-01-16 | 26,739 |
| 2027-01-17 | 20,513 |
| 2027-01-18 | 24,829 |
| 2027-01-19 | 22,477 |
| 2027-01-20 | 23,161 |
| 2027-01-21 | 45,475 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
