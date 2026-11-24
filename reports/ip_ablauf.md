# Seen-DB Expiry Forecast

Lauf: 2026-11-24 13:20 CET (Europe/Berlin)
Gesamt: 11,276,403 IPs in seen_db.json (7,923,594 aktiv/180-Tage-Pfad, 3,352,809 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 272,332 |
| 8-14 Tage | 198,335 |
| 15-30 Tage | 400,598 |
| 31-60 Tage | 728,091 |
| 61-90 Tage | 1,581,045 |
| 91-180 Tage | 4,743,193 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 3,097,787 |
| 0-3 Tage | 24,843 |
| 4-7 Tage | 26,789 |
| 8-14 Tage | 38,694 |
| 15-30 Tage | 164,696 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-24 | 10,078 |
| 2026-11-25 | 7,592 |
| 2026-11-26 | 3,326 |
| 2026-11-27 | 3,847 |
| 2026-11-28 | 3,524 |
| 2026-11-29 | 8,113 |
| 2026-11-30 | 7,094 |
| 2026-12-01 | 8,058 |
| 2026-12-02 | 4,559 |
| 2026-12-03 | 7,705 |
| 2026-12-04 | 5,745 |
| 2026-12-05 | 5,386 |
| 2026-12-06 | 3,080 |
| 2026-12-07 | 7,776 |
| 2026-12-08 | 4,443 |
| 2026-12-09 | 9,000 |
| 2026-12-10 | 5,997 |
| 2026-12-11 | 4,641 |
| 2026-12-12 | 2,580 |
| 2026-12-13 | 2,994 |
| 2026-12-14 | 7,600 |
| 2026-12-15 | 8,085 |
| 2026-12-16 | 7,487 |
| 2026-12-17 | 7,634 |
| 2026-12-18 | 9,356 |
| 2026-12-19 | 1,634 |
| 2026-12-20 | 10,073 |
| 2026-12-21 | 9,019 |
| 2026-12-22 | 31,754 |
| 2026-12-23 | 14,744 |
| 2026-12-24 | 19,509 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **3,097,787** IPs. Brutto faellig in den naechsten 30 Tagen: **242,433**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,278,220**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-24 | 10,078 | 2,000 |
| 2026-11-25 | 7,592 | 2,000 |
| 2026-11-26 | 3,326 | 2,000 |
| 2026-11-27 | 3,847 | 2,000 |
| 2026-11-28 | 3,524 | 2,000 |
| 2026-11-29 | 8,113 | 2,000 |
| 2026-11-30 | 7,094 | 2,000 |
| 2026-12-01 | 8,058 | 2,000 |
| 2026-12-02 | 4,559 | 2,000 |
| 2026-12-03 | 7,705 | 2,000 |
| 2026-12-04 | 5,745 | 2,000 |
| 2026-12-05 | 5,386 | 2,000 |
| 2026-12-06 | 3,080 | 2,000 |
| 2026-12-07 | 7,776 | 2,000 |
| 2026-12-08 | 4,443 | 2,000 |
| 2026-12-09 | 9,000 | 2,000 |
| 2026-12-10 | 5,997 | 2,000 |
| 2026-12-11 | 4,641 | 2,000 |
| 2026-12-12 | 2,580 | 2,000 |
| 2026-12-13 | 2,994 | 2,000 |
| 2026-12-14 | 7,600 | 2,000 |
| 2026-12-15 | 8,085 | 2,000 |
| 2026-12-16 | 7,487 | 2,000 |
| 2026-12-17 | 7,634 | 2,000 |
| 2026-12-18 | 9,356 | 2,000 |
| 2026-12-19 | 1,634 | 2,000 |
| 2026-12-20 | 10,073 | 2,000 |
| 2026-12-21 | 9,019 | 2,000 |
| 2026-12-22 | 31,754 | 2,000 |
| 2026-12-23 | 14,744 | 2,000 |
| 2026-12-24 | 19,509 | 2,000 |

> Hinweis: Der Rueckstau von 3,278,220 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-25 | 27,325 |
| 2026-11-26 | 28,512 |
| 2026-11-27 | 27,698 |
| 2026-11-28 | 108,946 |
| 2026-11-29 | 28,040 |
| 2026-11-30 | 25,393 |
| 2026-12-01 | 26,418 |
| 2026-12-02 | 26,040 |
| 2026-12-03 | 25,856 |
| 2026-12-04 | 27,792 |
| 2026-12-05 | 25,828 |
| 2026-12-06 | 29,978 |
| 2026-12-07 | 23,629 |
| 2026-12-08 | 39,212 |
| 2026-12-09 | 54,609 |
| 2026-12-10 | 24,965 |
| 2026-12-11 | 27,624 |
| 2026-12-12 | 24,262 |
| 2026-12-13 | 23,711 |
| 2026-12-14 | 23,330 |
| 2026-12-15 | 26,106 |
| 2026-12-16 | 16,513 |
| 2026-12-17 | 24,880 |
| 2026-12-18 | 22,397 |
| 2026-12-19 | 25,457 |
| 2026-12-20 | 14,227 |
| 2026-12-21 | 27,207 |
| 2026-12-22 | 23,979 |
| 2026-12-23 | 21,014 |
| 2026-12-24 | 20,317 |
| 2026-12-25 | 21,536 |
| 2026-12-26 | 17,725 |
| 2026-12-27 | 24,548 |
| 2026-12-28 | 21,653 |
| 2026-12-29 | 22,491 |
| 2026-12-30 | 26,429 |
| 2026-12-31 | 20,089 |
| 2027-01-01 | 18,445 |
| 2027-01-02 | 26,035 |
| 2027-01-03 | 14,758 |
| 2027-01-04 | 28,383 |
| 2027-01-05 | 22,308 |
| 2027-01-06 | 35,488 |
| 2027-01-07 | 23,895 |
| 2027-01-08 | 25,791 |
| 2027-01-09 | 21,553 |
| 2027-01-10 | 24,664 |
| 2027-01-11 | 24,070 |
| 2027-01-12 | 22,945 |
| 2027-01-13 | 23,237 |
| 2027-01-14 | 21,847 |
| 2027-01-15 | 22,675 |
| 2027-01-16 | 26,736 |
| 2027-01-17 | 20,507 |
| 2027-01-18 | 24,824 |
| 2027-01-19 | 22,472 |
| 2027-01-20 | 23,158 |
| 2027-01-21 | 45,468 |
| 2027-01-22 | 28,536 |
| 2027-01-23 | 25,825 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
