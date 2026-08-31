# Seen-DB Expiry Forecast

Lauf: 2026-08-31 08:00 CEST (Europe/Berlin)
Gesamt: 9,589,256 IPs in seen_db.json (8,387,543 aktiv/180-Tage-Pfad, 1,201,713 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 837,800 |
| 8-14 Tage | 0 |
| 15-30 Tage | 139,179 |
| 31-60 Tage | 2,671,352 |
| 61-90 Tage | 1,045,243 |
| 91-180 Tage | 3,693,969 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 0 |
| 0-3 Tage | 221,527 |
| 4-7 Tage | 119,663 |
| 8-14 Tage | 90,456 |
| 15-30 Tage | 770,067 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-08-31 | 52,991 |
| 2026-09-01 | 9,354 |
| 2026-09-02 | 10,994 |
| 2026-09-03 | 148,188 |
| 2026-09-04 | 69,554 |
| 2026-09-05 | 20,573 |
| 2026-09-06 | 16,396 |
| 2026-09-07 | 13,140 |
| 2026-09-08 | 17,072 |
| 2026-09-09 | 8,887 |
| 2026-09-10 | 11,448 |
| 2026-09-11 | 12,030 |
| 2026-09-12 | 12,185 |
| 2026-09-13 | 13,022 |
| 2026-09-14 | 15,812 |
| 2026-09-15 | 6,322 |
| 2026-09-16 | 5,867 |
| 2026-09-17 | 8,915 |
| 2026-09-18 | 5,235 |
| 2026-09-19 | 5,132 |
| 2026-09-20 | 5,130 |
| 2026-09-21 | 11,344 |
| 2026-09-22 | 5,240 |
| 2026-09-23 | 11,546 |
| 2026-09-24 | 5,613 |
| 2026-09-25 | 624,974 |
| 2026-09-26 | 6,513 |
| 2026-09-27 | 801 |
| 2026-09-29 | 61,018 |
| 2026-09-30 | 6,417 |

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-04 | 173,704 |
| 2026-09-07 | 664,096 |
| 2026-09-21 | 6,511 |
| 2026-09-22 | 13,227 |
| 2026-09-23 | 16,919 |
| 2026-09-24 | 21,214 |
| 2026-09-25 | 17,711 |
| 2026-09-26 | 15,285 |
| 2026-09-27 | 11,710 |
| 2026-09-28 | 9,470 |
| 2026-09-29 | 10,346 |
| 2026-09-30 | 16,786 |
| 2026-10-01 | 7,847 |
| 2026-10-02 | 7,435 |
| 2026-10-03 | 12,850 |
| 2026-10-04 | 17,767 |
| 2026-10-05 | 16,346 |
| 2026-10-06 | 15,263 |
| 2026-10-07 | 62,459 |
| 2026-10-08 | 226,971 |
| 2026-10-09 | 53,573 |
| 2026-10-10 | 16,142 |
| 2026-10-11 | 66,750 |
| 2026-10-12 | 1,592,948 |
| 2026-10-13 | 32,986 |
| 2026-10-14 | 41,489 |
| 2026-10-15 | 51,576 |
| 2026-10-16 | 24,544 |
| 2026-10-17 | 14,427 |
| 2026-10-18 | 22,933 |
| 2026-10-19 | 11,270 |
| 2026-10-20 | 11,259 |
| 2026-10-21 | 31,080 |
| 2026-10-22 | 50,729 |
| 2026-10-23 | 42,046 |
| 2026-10-24 | 21,903 |
| 2026-10-25 | 20,639 |
| 2026-10-26 | 20,984 |
| 2026-10-27 | 16,002 |
| 2026-10-28 | 9,874 |
| 2026-10-29 | 62,680 |
| 2026-10-30 | 88,580 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
