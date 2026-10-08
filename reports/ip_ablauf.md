# Seen-DB Expiry Forecast

Lauf: 2026-10-08 16:51 CEST (Europe/Berlin)
Gesamt: 12,370,968 IPs in seen_db.json (9,381,765 aktiv/180-Tage-Pfad, 2,989,203 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 2,010,953 |
| 8-14 Tage | 164,217 |
| 15-30 Tage | 530,705 |
| 31-60 Tage | 1,016,250 |
| 61-90 Tage | 745,171 |
| 91-180 Tage | 4,914,469 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,627,243 |
| 0-3 Tage | 31,059 |
| 4-7 Tage | 27,712 |
| 8-14 Tage | 68,491 |
| 15-30 Tage | 234,698 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-08 | 7,235 |
| 2026-10-09 | 10,101 |
| 2026-10-10 | 7,509 |
| 2026-10-11 | 6,214 |
| 2026-10-12 | 3,846 |
| 2026-10-13 | 8,214 |
| 2026-10-14 | 7,391 |
| 2026-10-15 | 8,261 |
| 2026-10-16 | 15,422 |
| 2026-10-17 | 9,921 |
| 2026-10-18 | 8,625 |
| 2026-10-19 | 5,128 |
| 2026-10-20 | 9,538 |
| 2026-10-21 | 9,498 |
| 2026-10-22 | 10,359 |
| 2026-10-23 | 12,361 |
| 2026-10-24 | 15,039 |
| 2026-10-25 | 11,081 |
| 2026-10-26 | 9,434 |
| 2026-10-27 | 35,220 |
| 2026-10-28 | 11,267 |
| 2026-10-29 | 9,833 |
| 2026-10-30 | 20,104 |
| 2026-10-31 | 17,046 |
| 2026-11-01 | 15,354 |
| 2026-11-02 | 11,923 |
| 2026-11-03 | 16,630 |
| 2026-11-04 | 10,075 |
| 2026-11-05 | 7,272 |
| 2026-11-06 | 12,130 |
| 2026-11-07 | 13,476 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,627,243** IPs. Brutto faellig in den naechsten 30 Tagen: **355,507**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **2,920,750**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-08 | 7,235 | 2,000 |
| 2026-10-09 | 10,101 | 2,000 |
| 2026-10-10 | 7,509 | 2,000 |
| 2026-10-11 | 6,214 | 2,000 |
| 2026-10-12 | 3,846 | 2,000 |
| 2026-10-13 | 8,214 | 2,000 |
| 2026-10-14 | 7,391 | 2,000 |
| 2026-10-15 | 8,261 | 2,000 |
| 2026-10-16 | 15,422 | 2,000 |
| 2026-10-17 | 9,921 | 2,000 |
| 2026-10-18 | 8,625 | 2,000 |
| 2026-10-19 | 5,128 | 2,000 |
| 2026-10-20 | 9,538 | 2,000 |
| 2026-10-21 | 9,498 | 2,000 |
| 2026-10-22 | 10,359 | 2,000 |
| 2026-10-23 | 12,361 | 2,000 |
| 2026-10-24 | 15,039 | 2,000 |
| 2026-10-25 | 11,081 | 2,000 |
| 2026-10-26 | 9,434 | 2,000 |
| 2026-10-27 | 35,220 | 2,000 |
| 2026-10-28 | 11,267 | 2,000 |
| 2026-10-29 | 9,833 | 2,000 |
| 2026-10-30 | 20,104 | 2,000 |
| 2026-10-31 | 17,046 | 2,000 |
| 2026-11-01 | 15,354 | 2,000 |
| 2026-11-02 | 11,923 | 2,000 |
| 2026-11-03 | 16,630 | 2,000 |
| 2026-11-04 | 10,075 | 2,000 |
| 2026-11-05 | 7,272 | 2,000 |
| 2026-11-06 | 12,130 | 2,000 |
| 2026-11-07 | 13,476 | 2,000 |

> Hinweis: Der Rueckstau von 2,920,750 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-09 | 220,692 |
| 2026-10-10 | 53,252 |
| 2026-10-11 | 15,991 |
| 2026-10-12 | 66,497 |
| 2026-10-13 | 1,580,337 |
| 2026-10-14 | 32,903 |
| 2026-10-15 | 41,281 |
| 2026-10-16 | 51,156 |
| 2026-10-17 | 24,171 |
| 2026-10-18 | 14,185 |
| 2026-10-19 | 22,077 |
| 2026-10-20 | 11,078 |
| 2026-10-21 | 11,039 |
| 2026-10-22 | 30,511 |
| 2026-10-23 | 50,262 |
| 2026-10-24 | 41,606 |
| 2026-10-25 | 21,513 |
| 2026-10-26 | 20,231 |
| 2026-10-27 | 20,540 |
| 2026-10-28 | 15,689 |
| 2026-10-29 | 9,596 |
| 2026-10-30 | 61,670 |
| 2026-10-31 | 88,083 |
| 2026-11-01 | 27,763 |
| 2026-11-02 | 28,714 |
| 2026-11-03 | 29,668 |
| 2026-11-04 | 29,531 |
| 2026-11-05 | 25,194 |
| 2026-11-06 | 36,261 |
| 2026-11-07 | 24,384 |
| 2026-11-08 | 26,053 |
| 2026-11-09 | 25,483 |
| 2026-11-10 | 32,642 |
| 2026-11-11 | 22,314 |
| 2026-11-12 | 20,467 |
| 2026-11-13 | 19,618 |
| 2026-11-14 | 22,924 |
| 2026-11-15 | 17,431 |
| 2026-11-16 | 17,930 |
| 2026-11-17 | 15,216 |
| 2026-11-18 | 19,470 |
| 2026-11-19 | 173,576 |
| 2026-11-20 | 26,106 |
| 2026-11-21 | 61,306 |
| 2026-11-22 | 30,382 |
| 2026-11-23 | 25,635 |
| 2026-11-24 | 26,437 |
| 2026-11-25 | 27,497 |
| 2026-11-26 | 28,633 |
| 2026-11-27 | 27,817 |
| 2026-11-28 | 109,173 |
| 2026-11-29 | 28,160 |
| 2026-11-30 | 25,524 |
| 2026-12-01 | 26,538 |
| 2026-12-02 | 26,181 |
| 2026-12-03 | 26,009 |
| 2026-12-04 | 27,903 |
| 2026-12-05 | 25,944 |
| 2026-12-06 | 30,138 |
| 2026-12-07 | 23,743 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
