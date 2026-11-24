# Seen-DB Expiry Forecast

Lauf: 2026-11-24 02:51 CET (Europe/Berlin)
Gesamt: 11,255,087 IPs in seen_db.json (7,915,478 aktiv/180-Tage-Pfad, 3,339,609 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 272,337 |
| 8-14 Tage | 198,340 |
| 15-30 Tage | 400,612 |
| 31-60 Tage | 728,115 |
| 61-90 Tage | 1,581,101 |
| 91-180 Tage | 4,734,973 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 3,096,876 |
| 0-3 Tage | 24,843 |
| 4-7 Tage | 26,789 |
| 8-14 Tage | 38,697 |
| 15-30 Tage | 152,404 |

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
| 2026-12-02 | 4,560 |
| 2026-12-03 | 7,705 |
| 2026-12-04 | 5,745 |
| 2026-12-05 | 5,388 |
| 2026-12-06 | 3,080 |
| 2026-12-07 | 7,776 |
| 2026-12-08 | 4,443 |
| 2026-12-09 | 9,003 |
| 2026-12-10 | 5,997 |
| 2026-12-11 | 4,641 |
| 2026-12-12 | 2,580 |
| 2026-12-13 | 2,994 |
| 2026-12-14 | 7,601 |
| 2026-12-15 | 8,086 |
| 2026-12-16 | 7,488 |
| 2026-12-17 | 7,636 |
| 2026-12-18 | 9,358 |
| 2026-12-19 | 1,635 |
| 2026-12-20 | 10,078 |
| 2026-12-21 | 9,021 |
| 2026-12-22 | 31,760 |
| 2026-12-23 | 14,747 |
| 2026-12-24 | 19,542 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **3,096,876** IPs. Brutto faellig in den naechsten 30 Tagen: **242,496**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,277,372**.

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
| 2026-12-02 | 4,560 | 2,000 |
| 2026-12-03 | 7,705 | 2,000 |
| 2026-12-04 | 5,745 | 2,000 |
| 2026-12-05 | 5,388 | 2,000 |
| 2026-12-06 | 3,080 | 2,000 |
| 2026-12-07 | 7,776 | 2,000 |
| 2026-12-08 | 4,443 | 2,000 |
| 2026-12-09 | 9,003 | 2,000 |
| 2026-12-10 | 5,997 | 2,000 |
| 2026-12-11 | 4,641 | 2,000 |
| 2026-12-12 | 2,580 | 2,000 |
| 2026-12-13 | 2,994 | 2,000 |
| 2026-12-14 | 7,601 | 2,000 |
| 2026-12-15 | 8,086 | 2,000 |
| 2026-12-16 | 7,488 | 2,000 |
| 2026-12-17 | 7,636 | 2,000 |
| 2026-12-18 | 9,358 | 2,000 |
| 2026-12-19 | 1,635 | 2,000 |
| 2026-12-20 | 10,078 | 2,000 |
| 2026-12-21 | 9,021 | 2,000 |
| 2026-12-22 | 31,760 | 2,000 |
| 2026-12-23 | 14,747 | 2,000 |
| 2026-12-24 | 19,542 | 2,000 |

> Hinweis: Der Rueckstau von 3,277,372 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-25 | 27,326 |
| 2026-11-26 | 28,513 |
| 2026-11-27 | 27,699 |
| 2026-11-28 | 108,946 |
| 2026-11-29 | 28,041 |
| 2026-11-30 | 25,393 |
| 2026-12-01 | 26,419 |
| 2026-12-02 | 26,040 |
| 2026-12-03 | 25,858 |
| 2026-12-04 | 27,792 |
| 2026-12-05 | 25,828 |
| 2026-12-06 | 29,978 |
| 2026-12-07 | 23,629 |
| 2026-12-08 | 39,215 |
| 2026-12-09 | 54,611 |
| 2026-12-10 | 24,965 |
| 2026-12-11 | 27,625 |
| 2026-12-12 | 24,263 |
| 2026-12-13 | 23,713 |
| 2026-12-14 | 23,330 |
| 2026-12-15 | 26,107 |
| 2026-12-16 | 16,516 |
| 2026-12-17 | 24,881 |
| 2026-12-18 | 22,397 |
| 2026-12-19 | 25,458 |
| 2026-12-20 | 14,227 |
| 2026-12-21 | 27,207 |
| 2026-12-22 | 23,979 |
| 2026-12-23 | 21,016 |
| 2026-12-24 | 20,317 |
| 2026-12-25 | 21,536 |
| 2026-12-26 | 17,725 |
| 2026-12-27 | 24,549 |
| 2026-12-28 | 21,654 |
| 2026-12-29 | 22,491 |
| 2026-12-30 | 26,431 |
| 2026-12-31 | 20,089 |
| 2027-01-01 | 18,445 |
| 2027-01-02 | 26,035 |
| 2027-01-03 | 14,758 |
| 2027-01-04 | 28,385 |
| 2027-01-05 | 22,308 |
| 2027-01-06 | 35,489 |
| 2027-01-07 | 23,895 |
| 2027-01-08 | 25,792 |
| 2027-01-09 | 21,555 |
| 2027-01-10 | 24,664 |
| 2027-01-11 | 24,070 |
| 2027-01-12 | 22,947 |
| 2027-01-13 | 23,237 |
| 2027-01-14 | 21,849 |
| 2027-01-15 | 22,675 |
| 2027-01-16 | 26,736 |
| 2027-01-17 | 20,508 |
| 2027-01-18 | 24,825 |
| 2027-01-19 | 22,472 |
| 2027-01-20 | 23,159 |
| 2027-01-21 | 45,468 |
| 2027-01-22 | 28,537 |
| 2027-01-23 | 25,831 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
