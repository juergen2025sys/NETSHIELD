# Seen-DB Expiry Forecast

Lauf: 2026-10-11 20:24 CEST (Europe/Berlin)
Gesamt: 12,301,285 IPs in seen_db.json (9,275,543 aktiv/180-Tage-Pfad, 3,025,742 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 1,809,939 |
| 8-14 Tage | 187,925 |
| 15-30 Tage | 501,165 |
| 31-60 Tage | 1,051,183 |
| 61-90 Tage | 696,573 |
| 91-180 Tage | 5,028,758 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,645,075 |
| 0-3 Tage | 25,637 |
| 4-7 Tage | 42,196 |
| 8-14 Tage | 72,888 |
| 15-30 Tage | 239,946 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-11 | 6,206 |
| 2026-10-12 | 3,841 |
| 2026-10-13 | 8,207 |
| 2026-10-14 | 7,383 |
| 2026-10-15 | 8,252 |
| 2026-10-16 | 15,412 |
| 2026-10-17 | 9,913 |
| 2026-10-18 | 8,619 |
| 2026-10-19 | 5,118 |
| 2026-10-20 | 9,523 |
| 2026-10-21 | 9,480 |
| 2026-10-22 | 10,344 |
| 2026-10-23 | 12,345 |
| 2026-10-24 | 15,012 |
| 2026-10-25 | 11,066 |
| 2026-10-26 | 9,416 |
| 2026-10-27 | 35,174 |
| 2026-10-28 | 11,254 |
| 2026-10-29 | 9,816 |
| 2026-10-30 | 20,076 |
| 2026-10-31 | 16,949 |
| 2026-11-01 | 15,332 |
| 2026-11-02 | 11,892 |
| 2026-11-03 | 16,598 |
| 2026-11-04 | 10,060 |
| 2026-11-05 | 7,244 |
| 2026-11-06 | 12,071 |
| 2026-11-07 | 13,386 |
| 2026-11-08 | 6,285 |
| 2026-11-09 | 11,528 |
| 2026-11-10 | 23,910 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,645,075** IPs. Brutto faellig in den naechsten 30 Tagen: **371,712**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **2,954,787**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-11 | 6,206 | 2,000 |
| 2026-10-12 | 3,841 | 2,000 |
| 2026-10-13 | 8,207 | 2,000 |
| 2026-10-14 | 7,383 | 2,000 |
| 2026-10-15 | 8,252 | 2,000 |
| 2026-10-16 | 15,412 | 2,000 |
| 2026-10-17 | 9,913 | 2,000 |
| 2026-10-18 | 8,619 | 2,000 |
| 2026-10-19 | 5,118 | 2,000 |
| 2026-10-20 | 9,523 | 2,000 |
| 2026-10-21 | 9,480 | 2,000 |
| 2026-10-22 | 10,344 | 2,000 |
| 2026-10-23 | 12,345 | 2,000 |
| 2026-10-24 | 15,012 | 2,000 |
| 2026-10-25 | 11,066 | 2,000 |
| 2026-10-26 | 9,416 | 2,000 |
| 2026-10-27 | 35,174 | 2,000 |
| 2026-10-28 | 11,254 | 2,000 |
| 2026-10-29 | 9,816 | 2,000 |
| 2026-10-30 | 20,076 | 2,000 |
| 2026-10-31 | 16,949 | 2,000 |
| 2026-11-01 | 15,332 | 2,000 |
| 2026-11-02 | 11,892 | 2,000 |
| 2026-11-03 | 16,598 | 2,000 |
| 2026-11-04 | 10,060 | 2,000 |
| 2026-11-05 | 7,244 | 2,000 |
| 2026-11-06 | 12,071 | 2,000 |
| 2026-11-07 | 13,386 | 2,000 |
| 2026-11-08 | 6,285 | 2,000 |
| 2026-11-09 | 11,528 | 2,000 |
| 2026-11-10 | 23,910 | 2,000 |

> Hinweis: Der Rueckstau von 2,954,787 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-12 | 66,480 |
| 2026-10-13 | 1,579,819 |
| 2026-10-14 | 32,901 |
| 2026-10-15 | 41,271 |
| 2026-10-16 | 51,137 |
| 2026-10-17 | 24,161 |
| 2026-10-18 | 14,170 |
| 2026-10-19 | 22,026 |
| 2026-10-20 | 11,065 |
| 2026-10-21 | 11,029 |
| 2026-10-22 | 30,491 |
| 2026-10-23 | 50,235 |
| 2026-10-24 | 41,581 |
| 2026-10-25 | 21,498 |
| 2026-10-26 | 20,210 |
| 2026-10-27 | 20,514 |
| 2026-10-28 | 15,669 |
| 2026-10-29 | 9,590 |
| 2026-10-30 | 61,617 |
| 2026-10-31 | 88,060 |
| 2026-11-01 | 27,749 |
| 2026-11-02 | 28,697 |
| 2026-11-03 | 29,645 |
| 2026-11-04 | 29,504 |
| 2026-11-05 | 25,171 |
| 2026-11-06 | 36,237 |
| 2026-11-07 | 24,369 |
| 2026-11-08 | 26,036 |
| 2026-11-09 | 25,467 |
| 2026-11-10 | 32,630 |
| 2026-11-11 | 22,297 |
| 2026-11-12 | 20,456 |
| 2026-11-13 | 19,606 |
| 2026-11-14 | 22,906 |
| 2026-11-15 | 17,419 |
| 2026-11-16 | 17,919 |
| 2026-11-17 | 15,206 |
| 2026-11-18 | 19,463 |
| 2026-11-19 | 173,497 |
| 2026-11-20 | 26,095 |
| 2026-11-21 | 61,273 |
| 2026-11-22 | 30,359 |
| 2026-11-23 | 25,619 |
| 2026-11-24 | 26,424 |
| 2026-11-25 | 27,480 |
| 2026-11-26 | 28,623 |
| 2026-11-27 | 27,800 |
| 2026-11-28 | 109,153 |
| 2026-11-29 | 28,135 |
| 2026-11-30 | 25,501 |
| 2026-12-01 | 26,516 |
| 2026-12-02 | 26,169 |
| 2026-12-03 | 25,990 |
| 2026-12-04 | 27,892 |
| 2026-12-05 | 25,936 |
| 2026-12-06 | 30,114 |
| 2026-12-07 | 23,729 |
| 2026-12-08 | 39,360 |
| 2026-12-09 | 55,162 |
| 2026-12-10 | 25,084 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
