# Seen-DB Expiry Forecast

Lauf: 2026-11-08 20:01 CET (Europe/Berlin)
Gesamt: 11,197,257 IPs in seen_db.json (7,978,059 aktiv/180-Tage-Pfad, 3,219,198 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 160,204 |
| 8-14 Tage | 343,023 |
| 15-30 Tage | 523,115 |
| 31-60 Tage | 725,985 |
| 61-90 Tage | 1,137,777 |
| 91-180 Tage | 5,087,955 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,950,139 |
| 0-3 Tage | 51,023 |
| 4-7 Tage | 37,067 |
| 8-14 Tage | 71,075 |
| 15-30 Tage | 109,894 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-08 | 6,215 |
| 2026-11-09 | 11,403 |
| 2026-11-10 | 23,575 |
| 2026-11-11 | 9,830 |
| 2026-11-12 | 7,972 |
| 2026-11-13 | 3,302 |
| 2026-11-14 | 11,536 |
| 2026-11-15 | 14,257 |
| 2026-11-16 | 18,798 |
| 2026-11-17 | 9,279 |
| 2026-11-18 | 3,463 |
| 2026-11-19 | 8,765 |
| 2026-11-20 | 10,847 |
| 2026-11-21 | 9,942 |
| 2026-11-22 | 9,981 |
| 2026-11-23 | 10,030 |
| 2026-11-24 | 10,105 |
| 2026-11-25 | 7,616 |
| 2026-11-26 | 3,340 |
| 2026-11-27 | 3,863 |
| 2026-11-28 | 3,546 |
| 2026-11-29 | 8,140 |
| 2026-11-30 | 7,130 |
| 2026-12-01 | 8,088 |
| 2026-12-02 | 4,601 |
| 2026-12-03 | 7,736 |
| 2026-12-04 | 5,773 |
| 2026-12-05 | 5,428 |
| 2026-12-06 | 3,121 |
| 2026-12-07 | 7,840 |
| 2026-12-08 | 4,566 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,950,139** IPs. Brutto faellig in den naechsten 30 Tagen: **260,088**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,148,227**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-08 | 6,215 | 2,000 |
| 2026-11-09 | 11,403 | 2,000 |
| 2026-11-10 | 23,575 | 2,000 |
| 2026-11-11 | 9,830 | 2,000 |
| 2026-11-12 | 7,972 | 2,000 |
| 2026-11-13 | 3,302 | 2,000 |
| 2026-11-14 | 11,536 | 2,000 |
| 2026-11-15 | 14,257 | 2,000 |
| 2026-11-16 | 18,798 | 2,000 |
| 2026-11-17 | 9,279 | 2,000 |
| 2026-11-18 | 3,463 | 2,000 |
| 2026-11-19 | 8,765 | 2,000 |
| 2026-11-20 | 10,847 | 2,000 |
| 2026-11-21 | 9,942 | 2,000 |
| 2026-11-22 | 9,981 | 2,000 |
| 2026-11-23 | 10,030 | 2,000 |
| 2026-11-24 | 10,105 | 2,000 |
| 2026-11-25 | 7,616 | 2,000 |
| 2026-11-26 | 3,340 | 2,000 |
| 2026-11-27 | 3,863 | 2,000 |
| 2026-11-28 | 3,546 | 2,000 |
| 2026-11-29 | 8,140 | 2,000 |
| 2026-11-30 | 7,130 | 2,000 |
| 2026-12-01 | 8,088 | 2,000 |
| 2026-12-02 | 4,601 | 2,000 |
| 2026-12-03 | 7,736 | 2,000 |
| 2026-12-04 | 5,773 | 2,000 |
| 2026-12-05 | 5,428 | 2,000 |
| 2026-12-06 | 3,121 | 2,000 |
| 2026-12-07 | 7,840 | 2,000 |
| 2026-12-08 | 4,566 | 2,000 |

> Hinweis: Der Rueckstau von 3,148,227 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-09 | 25,367 |
| 2026-11-10 | 32,522 |
| 2026-11-11 | 22,201 |
| 2026-11-12 | 20,391 |
| 2026-11-13 | 19,533 |
| 2026-11-14 | 22,817 |
| 2026-11-15 | 17,373 |
| 2026-11-16 | 17,847 |
| 2026-11-17 | 15,154 |
| 2026-11-18 | 19,399 |
| 2026-11-19 | 173,244 |
| 2026-11-20 | 26,002 |
| 2026-11-21 | 61,119 |
| 2026-11-22 | 30,258 |
| 2026-11-23 | 25,523 |
| 2026-11-24 | 26,345 |
| 2026-11-25 | 27,379 |
| 2026-11-26 | 28,548 |
| 2026-11-27 | 27,735 |
| 2026-11-28 | 109,019 |
| 2026-11-29 | 28,077 |
| 2026-11-30 | 25,431 |
| 2026-12-01 | 26,453 |
| 2026-12-02 | 26,086 |
| 2026-12-03 | 25,894 |
| 2026-12-04 | 27,823 |
| 2026-12-05 | 25,864 |
| 2026-12-06 | 30,023 |
| 2026-12-07 | 23,660 |
| 2026-12-08 | 39,255 |
| 2026-12-09 | 54,795 |
| 2026-12-10 | 25,014 |
| 2026-12-11 | 27,679 |
| 2026-12-12 | 24,299 |
| 2026-12-13 | 23,767 |
| 2026-12-14 | 23,371 |
| 2026-12-15 | 26,150 |
| 2026-12-16 | 16,573 |
| 2026-12-17 | 24,942 |
| 2026-12-18 | 22,432 |
| 2026-12-19 | 25,518 |
| 2026-12-20 | 14,268 |
| 2026-12-21 | 27,256 |
| 2026-12-22 | 24,030 |
| 2026-12-23 | 21,066 |
| 2026-12-24 | 20,360 |
| 2026-12-25 | 21,573 |
| 2026-12-26 | 17,779 |
| 2026-12-27 | 24,599 |
| 2026-12-28 | 21,700 |
| 2026-12-29 | 22,534 |
| 2026-12-30 | 26,485 |
| 2026-12-31 | 20,130 |
| 2027-01-01 | 18,487 |
| 2027-01-02 | 26,084 |
| 2027-01-03 | 14,799 |
| 2027-01-04 | 28,428 |
| 2027-01-05 | 22,364 |
| 2027-01-06 | 35,558 |
| 2027-01-07 | 23,945 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
