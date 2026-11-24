# Seen-DB Expiry Forecast

Lauf: 2026-11-24 23:43 CET (Europe/Berlin)
Gesamt: 11,288,357 IPs in seen_db.json (7,933,798 aktiv/180-Tage-Pfad, 3,354,559 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 272,316 |
| 8-14 Tage | 198,327 |
| 15-30 Tage | 400,573 |
| 31-60 Tage | 728,038 |
| 61-90 Tage | 1,580,952 |
| 91-180 Tage | 4,753,592 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 3,097,699 |
| 0-3 Tage | 24,839 |
| 4-7 Tage | 26,783 |
| 8-14 Tage | 38,684 |
| 15-30 Tage | 166,554 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-24 | 10,077 |
| 2026-11-25 | 7,590 |
| 2026-11-26 | 3,325 |
| 2026-11-27 | 3,847 |
| 2026-11-28 | 3,524 |
| 2026-11-29 | 8,111 |
| 2026-11-30 | 7,090 |
| 2026-12-01 | 8,058 |
| 2026-12-02 | 4,559 |
| 2026-12-03 | 7,704 |
| 2026-12-04 | 5,742 |
| 2026-12-05 | 5,384 |
| 2026-12-06 | 3,079 |
| 2026-12-07 | 7,774 |
| 2026-12-08 | 4,442 |
| 2026-12-09 | 8,999 |
| 2026-12-10 | 5,996 |
| 2026-12-11 | 4,640 |
| 2026-12-12 | 2,579 |
| 2026-12-13 | 2,993 |
| 2026-12-14 | 7,596 |
| 2026-12-15 | 8,083 |
| 2026-12-16 | 7,486 |
| 2026-12-17 | 7,633 |
| 2026-12-18 | 9,348 |
| 2026-12-19 | 1,633 |
| 2026-12-20 | 10,069 |
| 2026-12-21 | 9,016 |
| 2026-12-22 | 31,735 |
| 2026-12-23 | 14,739 |
| 2026-12-24 | 19,485 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **3,097,699** IPs. Brutto faellig in den naechsten 30 Tagen: **242,336**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,278,035**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-24 | 10,077 | 2,000 |
| 2026-11-25 | 7,590 | 2,000 |
| 2026-11-26 | 3,325 | 2,000 |
| 2026-11-27 | 3,847 | 2,000 |
| 2026-11-28 | 3,524 | 2,000 |
| 2026-11-29 | 8,111 | 2,000 |
| 2026-11-30 | 7,090 | 2,000 |
| 2026-12-01 | 8,058 | 2,000 |
| 2026-12-02 | 4,559 | 2,000 |
| 2026-12-03 | 7,704 | 2,000 |
| 2026-12-04 | 5,742 | 2,000 |
| 2026-12-05 | 5,384 | 2,000 |
| 2026-12-06 | 3,079 | 2,000 |
| 2026-12-07 | 7,774 | 2,000 |
| 2026-12-08 | 4,442 | 2,000 |
| 2026-12-09 | 8,999 | 2,000 |
| 2026-12-10 | 5,996 | 2,000 |
| 2026-12-11 | 4,640 | 2,000 |
| 2026-12-12 | 2,579 | 2,000 |
| 2026-12-13 | 2,993 | 2,000 |
| 2026-12-14 | 7,596 | 2,000 |
| 2026-12-15 | 8,083 | 2,000 |
| 2026-12-16 | 7,486 | 2,000 |
| 2026-12-17 | 7,633 | 2,000 |
| 2026-12-18 | 9,348 | 2,000 |
| 2026-12-19 | 1,633 | 2,000 |
| 2026-12-20 | 10,069 | 2,000 |
| 2026-12-21 | 9,016 | 2,000 |
| 2026-12-22 | 31,735 | 2,000 |
| 2026-12-23 | 14,739 | 2,000 |
| 2026-12-24 | 19,485 | 2,000 |

> Hinweis: Der Rueckstau von 3,278,035 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-25 | 27,323 |
| 2026-11-26 | 28,511 |
| 2026-11-27 | 27,697 |
| 2026-11-28 | 108,943 |
| 2026-11-29 | 28,038 |
| 2026-11-30 | 25,389 |
| 2026-12-01 | 26,415 |
| 2026-12-02 | 26,039 |
| 2026-12-03 | 25,855 |
| 2026-12-04 | 27,790 |
| 2026-12-05 | 25,828 |
| 2026-12-06 | 29,976 |
| 2026-12-07 | 23,628 |
| 2026-12-08 | 39,211 |
| 2026-12-09 | 54,605 |
| 2026-12-10 | 24,965 |
| 2026-12-11 | 27,623 |
| 2026-12-12 | 24,260 |
| 2026-12-13 | 23,710 |
| 2026-12-14 | 23,329 |
| 2026-12-15 | 26,106 |
| 2026-12-16 | 16,512 |
| 2026-12-17 | 24,877 |
| 2026-12-18 | 22,397 |
| 2026-12-19 | 25,456 |
| 2026-12-20 | 14,227 |
| 2026-12-21 | 27,205 |
| 2026-12-22 | 23,977 |
| 2026-12-23 | 21,011 |
| 2026-12-24 | 20,313 |
| 2026-12-25 | 21,533 |
| 2026-12-26 | 17,722 |
| 2026-12-27 | 24,547 |
| 2026-12-28 | 21,652 |
| 2026-12-29 | 22,490 |
| 2026-12-30 | 26,427 |
| 2026-12-31 | 20,085 |
| 2027-01-01 | 18,444 |
| 2027-01-02 | 26,033 |
| 2027-01-03 | 14,756 |
| 2027-01-04 | 28,382 |
| 2027-01-05 | 22,307 |
| 2027-01-06 | 35,484 |
| 2027-01-07 | 23,893 |
| 2027-01-08 | 25,788 |
| 2027-01-09 | 21,551 |
| 2027-01-10 | 24,663 |
| 2027-01-11 | 24,067 |
| 2027-01-12 | 22,943 |
| 2027-01-13 | 23,236 |
| 2027-01-14 | 21,847 |
| 2027-01-15 | 22,674 |
| 2027-01-16 | 26,733 |
| 2027-01-17 | 20,507 |
| 2027-01-18 | 24,824 |
| 2027-01-19 | 22,470 |
| 2027-01-20 | 23,155 |
| 2027-01-21 | 45,468 |
| 2027-01-22 | 28,534 |
| 2027-01-23 | 25,823 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
