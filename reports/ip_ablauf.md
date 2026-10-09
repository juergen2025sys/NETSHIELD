# Seen-DB Expiry Forecast

Lauf: 2026-10-09 22:18 CEST (Europe/Berlin)
Gesamt: 12,236,513 IPs in seen_db.json (9,239,453 aktiv/180-Tage-Pfad, 2,997,060 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 1,841,010 |
| 8-14 Tage | 163,234 |
| 15-30 Tage | 506,273 |
| 31-60 Tage | 1,029,201 |
| 61-90 Tage | 729,392 |
| 91-180 Tage | 4,970,343 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,631,763 |
| 0-3 Tage | 27,649 |
| 4-7 Tage | 39,261 |
| 8-14 Tage | 65,367 |
| 15-30 Tage | 233,020 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-09 | 10,096 |
| 2026-10-10 | 7,505 |
| 2026-10-11 | 6,206 |
| 2026-10-12 | 3,842 |
| 2026-10-13 | 8,208 |
| 2026-10-14 | 7,385 |
| 2026-10-15 | 8,254 |
| 2026-10-16 | 15,414 |
| 2026-10-17 | 9,913 |
| 2026-10-18 | 8,621 |
| 2026-10-19 | 5,122 |
| 2026-10-20 | 9,526 |
| 2026-10-21 | 9,483 |
| 2026-10-22 | 10,354 |
| 2026-10-23 | 12,348 |
| 2026-10-24 | 15,021 |
| 2026-10-25 | 11,070 |
| 2026-10-26 | 9,417 |
| 2026-10-27 | 35,191 |
| 2026-10-28 | 11,259 |
| 2026-10-29 | 9,823 |
| 2026-10-30 | 20,085 |
| 2026-10-31 | 16,970 |
| 2026-11-01 | 15,340 |
| 2026-11-02 | 11,898 |
| 2026-11-03 | 16,604 |
| 2026-11-04 | 10,066 |
| 2026-11-05 | 7,250 |
| 2026-11-06 | 12,080 |
| 2026-11-07 | 13,397 |
| 2026-11-08 | 6,306 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,631,763** IPs. Brutto faellig in den naechsten 30 Tagen: **354,054**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **2,923,817**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-09 | 10,096 | 2,000 |
| 2026-10-10 | 7,505 | 2,000 |
| 2026-10-11 | 6,206 | 2,000 |
| 2026-10-12 | 3,842 | 2,000 |
| 2026-10-13 | 8,208 | 2,000 |
| 2026-10-14 | 7,385 | 2,000 |
| 2026-10-15 | 8,254 | 2,000 |
| 2026-10-16 | 15,414 | 2,000 |
| 2026-10-17 | 9,913 | 2,000 |
| 2026-10-18 | 8,621 | 2,000 |
| 2026-10-19 | 5,122 | 2,000 |
| 2026-10-20 | 9,526 | 2,000 |
| 2026-10-21 | 9,483 | 2,000 |
| 2026-10-22 | 10,354 | 2,000 |
| 2026-10-23 | 12,348 | 2,000 |
| 2026-10-24 | 15,021 | 2,000 |
| 2026-10-25 | 11,070 | 2,000 |
| 2026-10-26 | 9,417 | 2,000 |
| 2026-10-27 | 35,191 | 2,000 |
| 2026-10-28 | 11,259 | 2,000 |
| 2026-10-29 | 9,823 | 2,000 |
| 2026-10-30 | 20,085 | 2,000 |
| 2026-10-31 | 16,970 | 2,000 |
| 2026-11-01 | 15,340 | 2,000 |
| 2026-11-02 | 11,898 | 2,000 |
| 2026-11-03 | 16,604 | 2,000 |
| 2026-11-04 | 10,066 | 2,000 |
| 2026-11-05 | 7,250 | 2,000 |
| 2026-11-06 | 12,080 | 2,000 |
| 2026-11-07 | 13,397 | 2,000 |
| 2026-11-08 | 6,306 | 2,000 |

> Hinweis: Der Rueckstau von 2,923,817 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-10 | 53,244 |
| 2026-10-11 | 15,989 |
| 2026-10-12 | 66,488 |
| 2026-10-13 | 1,579,967 |
| 2026-10-14 | 32,902 |
| 2026-10-15 | 41,277 |
| 2026-10-16 | 51,143 |
| 2026-10-17 | 24,167 |
| 2026-10-18 | 14,175 |
| 2026-10-19 | 22,040 |
| 2026-10-20 | 11,072 |
| 2026-10-21 | 11,036 |
| 2026-10-22 | 30,499 |
| 2026-10-23 | 50,245 |
| 2026-10-24 | 41,583 |
| 2026-10-25 | 21,505 |
| 2026-10-26 | 20,219 |
| 2026-10-27 | 20,522 |
| 2026-10-28 | 15,676 |
| 2026-10-29 | 9,593 |
| 2026-10-30 | 61,634 |
| 2026-10-31 | 88,071 |
| 2026-11-01 | 27,756 |
| 2026-11-02 | 28,703 |
| 2026-11-03 | 29,657 |
| 2026-11-04 | 29,515 |
| 2026-11-05 | 25,181 |
| 2026-11-06 | 36,246 |
| 2026-11-07 | 24,372 |
| 2026-11-08 | 26,040 |
| 2026-11-09 | 25,473 |
| 2026-11-10 | 32,630 |
| 2026-11-11 | 22,302 |
| 2026-11-12 | 20,461 |
| 2026-11-13 | 19,610 |
| 2026-11-14 | 22,912 |
| 2026-11-15 | 17,422 |
| 2026-11-16 | 17,921 |
| 2026-11-17 | 15,210 |
| 2026-11-18 | 19,465 |
| 2026-11-19 | 173,517 |
| 2026-11-20 | 26,099 |
| 2026-11-21 | 61,281 |
| 2026-11-22 | 30,370 |
| 2026-11-23 | 25,624 |
| 2026-11-24 | 26,425 |
| 2026-11-25 | 27,484 |
| 2026-11-26 | 28,627 |
| 2026-11-27 | 27,806 |
| 2026-11-28 | 109,161 |
| 2026-11-29 | 28,144 |
| 2026-11-30 | 25,506 |
| 2026-12-01 | 26,523 |
| 2026-12-02 | 26,173 |
| 2026-12-03 | 25,999 |
| 2026-12-04 | 27,897 |
| 2026-12-05 | 25,938 |
| 2026-12-06 | 30,121 |
| 2026-12-07 | 23,732 |
| 2026-12-08 | 39,368 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
