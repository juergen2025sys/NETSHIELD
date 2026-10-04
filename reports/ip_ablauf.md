# Seen-DB Expiry Forecast

Lauf: 2026-10-04 23:52 CEST (Europe/Berlin)
Gesamt: 12,238,086 IPs in seen_db.json (9,277,493 aktiv/180-Tage-Pfad, 2,960,593 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 400,018 |
| 8-14 Tage | 1,811,783 |
| 15-30 Tage | 490,999 |
| 31-60 Tage | 1,025,326 |
| 61-90 Tage | 752,801 |
| 91-180 Tage | 4,796,566 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,613,253 |
| 0-3 Tage | 25,503 |
| 4-7 Tage | 31,137 |
| 8-14 Tage | 61,865 |
| 15-30 Tage | 228,835 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-04 | 6,820 |
| 2026-10-05 | 2,859 |
| 2026-10-06 | 7,931 |
| 2026-10-07 | 7,893 |
| 2026-10-08 | 7,250 |
| 2026-10-09 | 10,125 |
| 2026-10-10 | 7,526 |
| 2026-10-11 | 6,236 |
| 2026-10-12 | 3,861 |
| 2026-10-13 | 8,250 |
| 2026-10-14 | 7,413 |
| 2026-10-15 | 8,290 |
| 2026-10-16 | 15,461 |
| 2026-10-17 | 9,936 |
| 2026-10-18 | 8,654 |
| 2026-10-19 | 5,147 |
| 2026-10-20 | 9,582 |
| 2026-10-21 | 9,529 |
| 2026-10-22 | 10,386 |
| 2026-10-23 | 12,411 |
| 2026-10-24 | 15,083 |
| 2026-10-25 | 11,108 |
| 2026-10-26 | 9,474 |
| 2026-10-27 | 35,307 |
| 2026-10-28 | 11,296 |
| 2026-10-29 | 9,867 |
| 2026-10-30 | 20,182 |
| 2026-10-31 | 17,158 |
| 2026-11-01 | 15,419 |
| 2026-11-02 | 12,014 |
| 2026-11-03 | 16,787 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,613,253** IPs. Brutto faellig in den naechsten 30 Tagen: **339,255**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **2,890,508**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-04 | 6,820 | 2,000 |
| 2026-10-05 | 2,859 | 2,000 |
| 2026-10-06 | 7,931 | 2,000 |
| 2026-10-07 | 7,893 | 2,000 |
| 2026-10-08 | 7,250 | 2,000 |
| 2026-10-09 | 10,125 | 2,000 |
| 2026-10-10 | 7,526 | 2,000 |
| 2026-10-11 | 6,236 | 2,000 |
| 2026-10-12 | 3,861 | 2,000 |
| 2026-10-13 | 8,250 | 2,000 |
| 2026-10-14 | 7,413 | 2,000 |
| 2026-10-15 | 8,290 | 2,000 |
| 2026-10-16 | 15,461 | 2,000 |
| 2026-10-17 | 9,936 | 2,000 |
| 2026-10-18 | 8,654 | 2,000 |
| 2026-10-19 | 5,147 | 2,000 |
| 2026-10-20 | 9,582 | 2,000 |
| 2026-10-21 | 9,529 | 2,000 |
| 2026-10-22 | 10,386 | 2,000 |
| 2026-10-23 | 12,411 | 2,000 |
| 2026-10-24 | 15,083 | 2,000 |
| 2026-10-25 | 11,108 | 2,000 |
| 2026-10-26 | 9,474 | 2,000 |
| 2026-10-27 | 35,307 | 2,000 |
| 2026-10-28 | 11,296 | 2,000 |
| 2026-10-29 | 9,867 | 2,000 |
| 2026-10-30 | 20,182 | 2,000 |
| 2026-10-31 | 17,158 | 2,000 |
| 2026-11-01 | 15,419 | 2,000 |
| 2026-11-02 | 12,014 | 2,000 |
| 2026-11-03 | 16,787 | 2,000 |

> Hinweis: Der Rueckstau von 2,890,508 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-05 | 17,446 |
| 2026-10-06 | 16,025 |
| 2026-10-07 | 14,961 |
| 2026-10-08 | 61,062 |
| 2026-10-09 | 221,228 |
| 2026-10-10 | 53,287 |
| 2026-10-11 | 16,009 |
| 2026-10-12 | 66,520 |
| 2026-10-13 | 1,581,407 |
| 2026-10-14 | 32,912 |
| 2026-10-15 | 41,298 |
| 2026-10-16 | 51,214 |
| 2026-10-17 | 24,210 |
| 2026-10-18 | 14,222 |
| 2026-10-19 | 22,163 |
| 2026-10-20 | 11,100 |
| 2026-10-21 | 11,063 |
| 2026-10-22 | 30,661 |
| 2026-10-23 | 50,324 |
| 2026-10-24 | 41,646 |
| 2026-10-25 | 21,554 |
| 2026-10-26 | 20,271 |
| 2026-10-27 | 20,604 |
| 2026-10-28 | 15,745 |
| 2026-10-29 | 9,634 |
| 2026-10-30 | 61,788 |
| 2026-10-31 | 88,145 |
| 2026-11-01 | 27,806 |
| 2026-11-02 | 28,764 |
| 2026-11-03 | 29,731 |
| 2026-11-04 | 29,579 |
| 2026-11-05 | 25,237 |
| 2026-11-06 | 36,322 |
| 2026-11-07 | 24,437 |
| 2026-11-08 | 26,094 |
| 2026-11-09 | 25,535 |
| 2026-11-10 | 32,705 |
| 2026-11-11 | 22,349 |
| 2026-11-12 | 20,487 |
| 2026-11-13 | 19,645 |
| 2026-11-14 | 22,960 |
| 2026-11-15 | 17,449 |
| 2026-11-16 | 17,954 |
| 2026-11-17 | 15,251 |
| 2026-11-18 | 19,499 |
| 2026-11-19 | 173,756 |
| 2026-11-20 | 26,160 |
| 2026-11-21 | 61,389 |
| 2026-11-22 | 30,434 |
| 2026-11-23 | 25,680 |
| 2026-11-24 | 26,481 |
| 2026-11-25 | 27,561 |
| 2026-11-26 | 28,673 |
| 2026-11-27 | 27,850 |
| 2026-11-28 | 109,222 |
| 2026-11-29 | 28,196 |
| 2026-11-30 | 25,562 |
| 2026-12-01 | 26,581 |
| 2026-12-02 | 26,216 |
| 2026-12-03 | 26,062 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
