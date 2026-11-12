# Seen-DB Expiry Forecast

Lauf: 2026-11-12 21:23 CET (Europe/Berlin)
Gesamt: 11,299,112 IPs in seen_db.json (8,070,635 aktiv/180-Tage-Pfad, 3,228,477 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 285,237 |
| 8-14 Tage | 225,055 |
| 15-30 Tage | 546,887 |
| 31-60 Tage | 690,065 |
| 61-90 Tage | 1,180,314 |
| 91-180 Tage | 5,143,077 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,995,782 |
| 0-3 Tage | 37,025 |
| 4-7 Tage | 40,264 |
| 8-14 Tage | 61,782 |
| 15-30 Tage | 93,624 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-12 | 7,966 |
| 2026-11-13 | 3,300 |
| 2026-11-14 | 11,526 |
| 2026-11-15 | 14,233 |
| 2026-11-16 | 18,784 |
| 2026-11-17 | 9,267 |
| 2026-11-18 | 3,461 |
| 2026-11-19 | 8,752 |
| 2026-11-20 | 10,831 |
| 2026-11-21 | 9,925 |
| 2026-11-22 | 9,973 |
| 2026-11-23 | 10,015 |
| 2026-11-24 | 10,094 |
| 2026-11-25 | 7,606 |
| 2026-11-26 | 3,338 |
| 2026-11-27 | 3,859 |
| 2026-11-28 | 3,538 |
| 2026-11-29 | 8,126 |
| 2026-11-30 | 7,109 |
| 2026-12-01 | 8,079 |
| 2026-12-02 | 4,581 |
| 2026-12-03 | 7,723 |
| 2026-12-04 | 5,759 |
| 2026-12-05 | 5,410 |
| 2026-12-06 | 3,101 |
| 2026-12-07 | 7,803 |
| 2026-12-08 | 4,495 |
| 2026-12-09 | 9,039 |
| 2026-12-10 | 6,042 |
| 2026-12-11 | 4,704 |
| 2026-12-12 | 2,621 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,995,782** IPs. Brutto faellig in den naechsten 30 Tagen: **231,060**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,164,842**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-12 | 7,966 | 2,000 |
| 2026-11-13 | 3,300 | 2,000 |
| 2026-11-14 | 11,526 | 2,000 |
| 2026-11-15 | 14,233 | 2,000 |
| 2026-11-16 | 18,784 | 2,000 |
| 2026-11-17 | 9,267 | 2,000 |
| 2026-11-18 | 3,461 | 2,000 |
| 2026-11-19 | 8,752 | 2,000 |
| 2026-11-20 | 10,831 | 2,000 |
| 2026-11-21 | 9,925 | 2,000 |
| 2026-11-22 | 9,973 | 2,000 |
| 2026-11-23 | 10,015 | 2,000 |
| 2026-11-24 | 10,094 | 2,000 |
| 2026-11-25 | 7,606 | 2,000 |
| 2026-11-26 | 3,338 | 2,000 |
| 2026-11-27 | 3,859 | 2,000 |
| 2026-11-28 | 3,538 | 2,000 |
| 2026-11-29 | 8,126 | 2,000 |
| 2026-11-30 | 7,109 | 2,000 |
| 2026-12-01 | 8,079 | 2,000 |
| 2026-12-02 | 4,581 | 2,000 |
| 2026-12-03 | 7,723 | 2,000 |
| 2026-12-04 | 5,759 | 2,000 |
| 2026-12-05 | 5,410 | 2,000 |
| 2026-12-06 | 3,101 | 2,000 |
| 2026-12-07 | 7,803 | 2,000 |
| 2026-12-08 | 4,495 | 2,000 |
| 2026-12-09 | 9,039 | 2,000 |
| 2026-12-10 | 6,042 | 2,000 |
| 2026-12-11 | 4,704 | 2,000 |
| 2026-12-12 | 2,621 | 2,000 |

> Hinweis: Der Rueckstau von 3,164,842 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-13 | 19,523 |
| 2026-11-14 | 22,798 |
| 2026-11-15 | 17,367 |
| 2026-11-16 | 17,838 |
| 2026-11-17 | 15,149 |
| 2026-11-18 | 19,390 |
| 2026-11-19 | 173,172 |
| 2026-11-20 | 25,992 |
| 2026-11-21 | 61,093 |
| 2026-11-22 | 30,245 |
| 2026-11-23 | 25,519 |
| 2026-11-24 | 26,322 |
| 2026-11-25 | 27,353 |
| 2026-11-26 | 28,531 |
| 2026-11-27 | 27,722 |
| 2026-11-28 | 109,000 |
| 2026-11-29 | 28,062 |
| 2026-11-30 | 25,424 |
| 2026-12-01 | 26,441 |
| 2026-12-02 | 26,075 |
| 2026-12-03 | 25,885 |
| 2026-12-04 | 27,813 |
| 2026-12-05 | 25,858 |
| 2026-12-06 | 30,015 |
| 2026-12-07 | 23,653 |
| 2026-12-08 | 39,236 |
| 2026-12-09 | 54,748 |
| 2026-12-10 | 25,000 |
| 2026-12-11 | 27,666 |
| 2026-12-12 | 24,289 |
| 2026-12-13 | 23,755 |
| 2026-12-14 | 23,363 |
| 2026-12-15 | 26,139 |
| 2026-12-16 | 16,559 |
| 2026-12-17 | 24,930 |
| 2026-12-18 | 22,420 |
| 2026-12-19 | 25,491 |
| 2026-12-20 | 14,255 |
| 2026-12-21 | 27,244 |
| 2026-12-22 | 24,011 |
| 2026-12-23 | 21,055 |
| 2026-12-24 | 20,343 |
| 2026-12-25 | 21,561 |
| 2026-12-26 | 17,765 |
| 2026-12-27 | 24,589 |
| 2026-12-28 | 21,689 |
| 2026-12-29 | 22,522 |
| 2026-12-30 | 26,471 |
| 2026-12-31 | 20,116 |
| 2027-01-01 | 18,472 |
| 2027-01-02 | 26,076 |
| 2027-01-03 | 14,792 |
| 2027-01-04 | 28,415 |
| 2027-01-05 | 22,351 |
| 2027-01-06 | 35,539 |
| 2027-01-07 | 23,931 |
| 2027-01-08 | 25,831 |
| 2027-01-09 | 21,586 |
| 2027-01-10 | 24,690 |
| 2027-01-11 | 24,104 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
