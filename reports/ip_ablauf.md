# Seen-DB Expiry Forecast

Lauf: 2026-10-09 03:09 CEST (Europe/Berlin)
Gesamt: 12,179,127 IPs in seen_db.json (9,190,543 aktiv/180-Tage-Pfad, 2,988,584 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 1,841,267 |
| 8-14 Tage | 163,267 |
| 15-30 Tage | 506,381 |
| 31-60 Tage | 1,029,425 |
| 61-90 Tage | 729,668 |
| 91-180 Tage | 4,920,535 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,632,159 |
| 0-3 Tage | 27,665 |
| 4-7 Tage | 39,275 |
| 8-14 Tage | 65,414 |
| 15-30 Tage | 224,071 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-09 | 10,100 |
| 2026-10-10 | 7,507 |
| 2026-10-11 | 6,212 |
| 2026-10-12 | 3,846 |
| 2026-10-13 | 8,212 |
| 2026-10-14 | 7,389 |
| 2026-10-15 | 8,257 |
| 2026-10-16 | 15,417 |
| 2026-10-17 | 9,919 |
| 2026-10-18 | 8,625 |
| 2026-10-19 | 5,126 |
| 2026-10-20 | 9,534 |
| 2026-10-21 | 9,494 |
| 2026-10-22 | 10,358 |
| 2026-10-23 | 12,358 |
| 2026-10-24 | 15,036 |
| 2026-10-25 | 11,077 |
| 2026-10-26 | 9,431 |
| 2026-10-27 | 35,210 |
| 2026-10-28 | 11,264 |
| 2026-10-29 | 9,831 |
| 2026-10-30 | 20,098 |
| 2026-10-31 | 17,038 |
| 2026-11-01 | 15,352 |
| 2026-11-02 | 11,913 |
| 2026-11-03 | 16,623 |
| 2026-11-04 | 10,073 |
| 2026-11-05 | 7,262 |
| 2026-11-06 | 12,105 |
| 2026-11-07 | 13,451 |
| 2026-11-08 | 6,402 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,632,159** IPs. Brutto faellig in den naechsten 30 Tagen: **354,520**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **2,924,679**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-09 | 10,100 | 2,000 |
| 2026-10-10 | 7,507 | 2,000 |
| 2026-10-11 | 6,212 | 2,000 |
| 2026-10-12 | 3,846 | 2,000 |
| 2026-10-13 | 8,212 | 2,000 |
| 2026-10-14 | 7,389 | 2,000 |
| 2026-10-15 | 8,257 | 2,000 |
| 2026-10-16 | 15,417 | 2,000 |
| 2026-10-17 | 9,919 | 2,000 |
| 2026-10-18 | 8,625 | 2,000 |
| 2026-10-19 | 5,126 | 2,000 |
| 2026-10-20 | 9,534 | 2,000 |
| 2026-10-21 | 9,494 | 2,000 |
| 2026-10-22 | 10,358 | 2,000 |
| 2026-10-23 | 12,358 | 2,000 |
| 2026-10-24 | 15,036 | 2,000 |
| 2026-10-25 | 11,077 | 2,000 |
| 2026-10-26 | 9,431 | 2,000 |
| 2026-10-27 | 35,210 | 2,000 |
| 2026-10-28 | 11,264 | 2,000 |
| 2026-10-29 | 9,831 | 2,000 |
| 2026-10-30 | 20,098 | 2,000 |
| 2026-10-31 | 17,038 | 2,000 |
| 2026-11-01 | 15,352 | 2,000 |
| 2026-11-02 | 11,913 | 2,000 |
| 2026-11-03 | 16,623 | 2,000 |
| 2026-11-04 | 10,073 | 2,000 |
| 2026-11-05 | 7,262 | 2,000 |
| 2026-11-06 | 12,105 | 2,000 |
| 2026-11-07 | 13,451 | 2,000 |
| 2026-11-08 | 6,402 | 2,000 |

> Hinweis: Der Rueckstau von 2,924,679 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-10 | 53,248 |
| 2026-10-11 | 15,990 |
| 2026-10-12 | 66,493 |
| 2026-10-13 | 1,580,203 |
| 2026-10-14 | 32,903 |
| 2026-10-15 | 41,280 |
| 2026-10-16 | 51,150 |
| 2026-10-17 | 24,168 |
| 2026-10-18 | 14,179 |
| 2026-10-19 | 22,050 |
| 2026-10-20 | 11,075 |
| 2026-10-21 | 11,038 |
| 2026-10-22 | 30,506 |
| 2026-10-23 | 50,251 |
| 2026-10-24 | 41,592 |
| 2026-10-25 | 21,509 |
| 2026-10-26 | 20,226 |
| 2026-10-27 | 20,529 |
| 2026-10-28 | 15,682 |
| 2026-10-29 | 9,595 |
| 2026-10-30 | 61,650 |
| 2026-10-31 | 88,078 |
| 2026-11-01 | 27,761 |
| 2026-11-02 | 28,709 |
| 2026-11-03 | 29,664 |
| 2026-11-04 | 29,521 |
| 2026-11-05 | 25,187 |
| 2026-11-06 | 36,254 |
| 2026-11-07 | 24,376 |
| 2026-11-08 | 26,048 |
| 2026-11-09 | 25,480 |
| 2026-11-10 | 32,636 |
| 2026-11-11 | 22,310 |
| 2026-11-12 | 20,464 |
| 2026-11-13 | 19,614 |
| 2026-11-14 | 22,917 |
| 2026-11-15 | 17,427 |
| 2026-11-16 | 17,923 |
| 2026-11-17 | 15,212 |
| 2026-11-18 | 19,467 |
| 2026-11-19 | 173,558 |
| 2026-11-20 | 26,105 |
| 2026-11-21 | 61,290 |
| 2026-11-22 | 30,373 |
| 2026-11-23 | 25,628 |
| 2026-11-24 | 26,435 |
| 2026-11-25 | 27,495 |
| 2026-11-26 | 28,632 |
| 2026-11-27 | 27,812 |
| 2026-11-28 | 109,169 |
| 2026-11-29 | 28,151 |
| 2026-11-30 | 25,519 |
| 2026-12-01 | 26,534 |
| 2026-12-02 | 26,176 |
| 2026-12-03 | 26,006 |
| 2026-12-04 | 27,898 |
| 2026-12-05 | 25,942 |
| 2026-12-06 | 30,127 |
| 2026-12-07 | 23,742 |
| 2026-12-08 | 39,383 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
