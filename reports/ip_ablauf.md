# Seen-DB Expiry Forecast

Lauf: 2026-11-23 15:26 CET (Europe/Berlin)
Gesamt: 11,269,936 IPs in seen_db.json (7,932,468 aktiv/180-Tage-Pfad, 3,337,468 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 272,229 |
| 8-14 Tage | 185,553 |
| 15-30 Tage | 419,545 |
| 31-60 Tage | 722,647 |
| 61-90 Tage | 1,577,610 |
| 91-180 Tage | 4,754,884 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 3,088,995 |
| 0-3 Tage | 30,984 |
| 4-7 Tage | 22,584 |
| 8-14 Tage | 42,320 |
| 15-30 Tage | 152,585 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-23 | 9,986 |
| 2026-11-24 | 10,080 |
| 2026-11-25 | 7,592 |
| 2026-11-26 | 3,326 |
| 2026-11-27 | 3,847 |
| 2026-11-28 | 3,527 |
| 2026-11-29 | 8,116 |
| 2026-11-30 | 7,094 |
| 2026-12-01 | 8,058 |
| 2026-12-02 | 4,560 |
| 2026-12-03 | 7,706 |
| 2026-12-04 | 5,747 |
| 2026-12-05 | 5,389 |
| 2026-12-06 | 3,082 |
| 2026-12-07 | 7,778 |
| 2026-12-08 | 4,444 |
| 2026-12-09 | 9,003 |
| 2026-12-10 | 5,997 |
| 2026-12-11 | 4,644 |
| 2026-12-12 | 2,581 |
| 2026-12-13 | 2,996 |
| 2026-12-14 | 7,603 |
| 2026-12-15 | 8,089 |
| 2026-12-16 | 7,493 |
| 2026-12-17 | 7,638 |
| 2026-12-18 | 9,363 |
| 2026-12-19 | 1,635 |
| 2026-12-20 | 10,084 |
| 2026-12-21 | 9,024 |
| 2026-12-22 | 31,776 |
| 2026-12-23 | 14,754 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **3,088,995** IPs. Brutto faellig in den naechsten 30 Tagen: **233,012**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,260,007**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-23 | 9,986 | 2,000 |
| 2026-11-24 | 10,080 | 2,000 |
| 2026-11-25 | 7,592 | 2,000 |
| 2026-11-26 | 3,326 | 2,000 |
| 2026-11-27 | 3,847 | 2,000 |
| 2026-11-28 | 3,527 | 2,000 |
| 2026-11-29 | 8,116 | 2,000 |
| 2026-11-30 | 7,094 | 2,000 |
| 2026-12-01 | 8,058 | 2,000 |
| 2026-12-02 | 4,560 | 2,000 |
| 2026-12-03 | 7,706 | 2,000 |
| 2026-12-04 | 5,747 | 2,000 |
| 2026-12-05 | 5,389 | 2,000 |
| 2026-12-06 | 3,082 | 2,000 |
| 2026-12-07 | 7,778 | 2,000 |
| 2026-12-08 | 4,444 | 2,000 |
| 2026-12-09 | 9,003 | 2,000 |
| 2026-12-10 | 5,997 | 2,000 |
| 2026-12-11 | 4,644 | 2,000 |
| 2026-12-12 | 2,581 | 2,000 |
| 2026-12-13 | 2,996 | 2,000 |
| 2026-12-14 | 7,603 | 2,000 |
| 2026-12-15 | 8,089 | 2,000 |
| 2026-12-16 | 7,493 | 2,000 |
| 2026-12-17 | 7,638 | 2,000 |
| 2026-12-18 | 9,363 | 2,000 |
| 2026-12-19 | 1,635 | 2,000 |
| 2026-12-20 | 10,084 | 2,000 |
| 2026-12-21 | 9,024 | 2,000 |
| 2026-12-22 | 31,776 | 2,000 |
| 2026-12-23 | 14,754 | 2,000 |

> Hinweis: Der Rueckstau von 3,260,007 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-24 | 26,303 |
| 2026-11-25 | 27,327 |
| 2026-11-26 | 28,514 |
| 2026-11-27 | 27,701 |
| 2026-11-28 | 108,948 |
| 2026-11-29 | 28,042 |
| 2026-11-30 | 25,394 |
| 2026-12-01 | 26,420 |
| 2026-12-02 | 26,041 |
| 2026-12-03 | 25,858 |
| 2026-12-04 | 27,792 |
| 2026-12-05 | 25,829 |
| 2026-12-06 | 29,983 |
| 2026-12-07 | 23,630 |
| 2026-12-08 | 39,216 |
| 2026-12-09 | 54,615 |
| 2026-12-10 | 24,969 |
| 2026-12-11 | 27,625 |
| 2026-12-12 | 24,264 |
| 2026-12-13 | 23,713 |
| 2026-12-14 | 23,330 |
| 2026-12-15 | 26,108 |
| 2026-12-16 | 16,518 |
| 2026-12-17 | 24,895 |
| 2026-12-18 | 22,398 |
| 2026-12-19 | 25,461 |
| 2026-12-20 | 14,229 |
| 2026-12-21 | 27,209 |
| 2026-12-22 | 23,979 |
| 2026-12-23 | 21,016 |
| 2026-12-24 | 20,317 |
| 2026-12-25 | 21,536 |
| 2026-12-26 | 17,728 |
| 2026-12-27 | 24,551 |
| 2026-12-28 | 21,655 |
| 2026-12-29 | 22,493 |
| 2026-12-30 | 26,433 |
| 2026-12-31 | 20,092 |
| 2027-01-01 | 18,446 |
| 2027-01-02 | 26,035 |
| 2027-01-03 | 14,758 |
| 2027-01-04 | 28,388 |
| 2027-01-05 | 22,311 |
| 2027-01-06 | 35,489 |
| 2027-01-07 | 23,897 |
| 2027-01-08 | 25,798 |
| 2027-01-09 | 21,555 |
| 2027-01-10 | 24,664 |
| 2027-01-11 | 24,071 |
| 2027-01-12 | 22,948 |
| 2027-01-13 | 23,237 |
| 2027-01-14 | 21,850 |
| 2027-01-15 | 22,678 |
| 2027-01-16 | 26,738 |
| 2027-01-17 | 20,510 |
| 2027-01-18 | 24,827 |
| 2027-01-19 | 22,472 |
| 2027-01-20 | 23,159 |
| 2027-01-21 | 45,471 |
| 2027-01-22 | 28,540 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
