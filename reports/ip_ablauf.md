# Seen-DB Expiry Forecast

Lauf: 2026-11-13 09:42 CET (Europe/Berlin)
Gesamt: 11,305,931 IPs in seen_db.json (8,071,589 aktiv/180-Tage-Pfad, 3,234,342 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 291,697 |
| 8-14 Tage | 226,776 |
| 15-30 Tage | 542,889 |
| 31-60 Tage | 689,242 |
| 61-90 Tage | 1,208,467 |
| 91-180 Tage | 5,112,518 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 3,002,523 |
| 0-3 Tage | 47,835 |
| 4-7 Tage | 32,308 |
| 8-14 Tage | 54,802 |
| 15-30 Tage | 96,874 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-13 | 3,299 |
| 2026-11-14 | 11,525 |
| 2026-11-15 | 14,229 |
| 2026-11-16 | 18,782 |
| 2026-11-17 | 9,266 |
| 2026-11-18 | 3,461 |
| 2026-11-19 | 8,752 |
| 2026-11-20 | 10,829 |
| 2026-11-21 | 9,924 |
| 2026-11-22 | 9,972 |
| 2026-11-23 | 10,012 |
| 2026-11-24 | 10,092 |
| 2026-11-25 | 7,606 |
| 2026-11-26 | 3,337 |
| 2026-11-27 | 3,859 |
| 2026-11-28 | 3,536 |
| 2026-11-29 | 8,126 |
| 2026-11-30 | 7,107 |
| 2026-12-01 | 8,078 |
| 2026-12-02 | 4,580 |
| 2026-12-03 | 7,723 |
| 2026-12-04 | 5,758 |
| 2026-12-05 | 5,410 |
| 2026-12-06 | 3,101 |
| 2026-12-07 | 7,801 |
| 2026-12-08 | 4,488 |
| 2026-12-09 | 9,031 |
| 2026-12-10 | 6,035 |
| 2026-12-11 | 4,697 |
| 2026-12-12 | 2,616 |
| 2026-12-13 | 3,048 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **3,002,523** IPs. Brutto faellig in den naechsten 30 Tagen: **226,080**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,166,603**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-13 | 3,299 | 2,000 |
| 2026-11-14 | 11,525 | 2,000 |
| 2026-11-15 | 14,229 | 2,000 |
| 2026-11-16 | 18,782 | 2,000 |
| 2026-11-17 | 9,266 | 2,000 |
| 2026-11-18 | 3,461 | 2,000 |
| 2026-11-19 | 8,752 | 2,000 |
| 2026-11-20 | 10,829 | 2,000 |
| 2026-11-21 | 9,924 | 2,000 |
| 2026-11-22 | 9,972 | 2,000 |
| 2026-11-23 | 10,012 | 2,000 |
| 2026-11-24 | 10,092 | 2,000 |
| 2026-11-25 | 7,606 | 2,000 |
| 2026-11-26 | 3,337 | 2,000 |
| 2026-11-27 | 3,859 | 2,000 |
| 2026-11-28 | 3,536 | 2,000 |
| 2026-11-29 | 8,126 | 2,000 |
| 2026-11-30 | 7,107 | 2,000 |
| 2026-12-01 | 8,078 | 2,000 |
| 2026-12-02 | 4,580 | 2,000 |
| 2026-12-03 | 7,723 | 2,000 |
| 2026-12-04 | 5,758 | 2,000 |
| 2026-12-05 | 5,410 | 2,000 |
| 2026-12-06 | 3,101 | 2,000 |
| 2026-12-07 | 7,801 | 2,000 |
| 2026-12-08 | 4,488 | 2,000 |
| 2026-12-09 | 9,031 | 2,000 |
| 2026-12-10 | 6,035 | 2,000 |
| 2026-12-11 | 4,697 | 2,000 |
| 2026-12-12 | 2,616 | 2,000 |
| 2026-12-13 | 3,048 | 2,000 |

> Hinweis: Der Rueckstau von 3,166,603 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-14 | 22,797 |
| 2026-11-15 | 17,366 |
| 2026-11-16 | 17,837 |
| 2026-11-17 | 15,149 |
| 2026-11-18 | 19,390 |
| 2026-11-19 | 173,166 |
| 2026-11-20 | 25,992 |
| 2026-11-21 | 61,092 |
| 2026-11-22 | 30,244 |
| 2026-11-23 | 25,518 |
| 2026-11-24 | 26,320 |
| 2026-11-25 | 27,353 |
| 2026-11-26 | 28,528 |
| 2026-11-27 | 27,721 |
| 2026-11-28 | 108,998 |
| 2026-11-29 | 28,060 |
| 2026-11-30 | 25,422 |
| 2026-12-01 | 26,441 |
| 2026-12-02 | 26,070 |
| 2026-12-03 | 25,884 |
| 2026-12-04 | 27,813 |
| 2026-12-05 | 25,857 |
| 2026-12-06 | 30,015 |
| 2026-12-07 | 23,652 |
| 2026-12-08 | 39,235 |
| 2026-12-09 | 54,737 |
| 2026-12-10 | 24,998 |
| 2026-12-11 | 27,665 |
| 2026-12-12 | 24,289 |
| 2026-12-13 | 23,753 |
| 2026-12-14 | 23,362 |
| 2026-12-15 | 26,137 |
| 2026-12-16 | 16,558 |
| 2026-12-17 | 24,927 |
| 2026-12-18 | 22,420 |
| 2026-12-19 | 25,489 |
| 2026-12-20 | 14,255 |
| 2026-12-21 | 27,241 |
| 2026-12-22 | 24,009 |
| 2026-12-23 | 21,053 |
| 2026-12-24 | 20,343 |
| 2026-12-25 | 21,560 |
| 2026-12-26 | 17,763 |
| 2026-12-27 | 24,586 |
| 2026-12-28 | 21,686 |
| 2026-12-29 | 22,521 |
| 2026-12-30 | 26,469 |
| 2026-12-31 | 20,114 |
| 2027-01-01 | 18,470 |
| 2027-01-02 | 26,075 |
| 2027-01-03 | 14,792 |
| 2027-01-04 | 28,415 |
| 2027-01-05 | 22,350 |
| 2027-01-06 | 35,537 |
| 2027-01-07 | 23,928 |
| 2027-01-08 | 25,831 |
| 2027-01-09 | 21,585 |
| 2027-01-10 | 24,689 |
| 2027-01-11 | 24,102 |
| 2027-01-12 | 22,975 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
