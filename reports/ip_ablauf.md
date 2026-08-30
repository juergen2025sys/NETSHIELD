# Seen-DB Expiry Forecast

Lauf: 2026-08-30 23:53 CEST (Europe/Berlin)
Gesamt: 9,586,079 IPs in seen_db.json (8,381,987 aktiv/180-Tage-Pfad, 1,204,092 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 173,704 |
| 8-14 Tage | 664,158 |
| 15-30 Tage | 122,402 |
| 31-60 Tage | 2,599,676 |
| 61-90 Tage | 1,108,025 |
| 91-180 Tage | 3,714,022 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 0 |
| 0-3 Tage | 83,414 |
| 4-7 Tage | 254,741 |
| 8-14 Tage | 87,802 |
| 15-30 Tage | 778,135 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-08-30 | 10,066 |
| 2026-08-31 | 52,996 |
| 2026-09-01 | 9,356 |
| 2026-09-02 | 10,996 |
| 2026-09-03 | 148,193 |
| 2026-09-04 | 69,566 |
| 2026-09-05 | 20,577 |
| 2026-09-06 | 16,405 |
| 2026-09-07 | 13,141 |
| 2026-09-08 | 17,075 |
| 2026-09-09 | 8,889 |
| 2026-09-10 | 11,451 |
| 2026-09-11 | 12,034 |
| 2026-09-12 | 12,189 |
| 2026-09-13 | 13,023 |
| 2026-09-14 | 15,817 |
| 2026-09-15 | 6,323 |
| 2026-09-16 | 5,870 |
| 2026-09-17 | 8,916 |
| 2026-09-18 | 5,235 |
| 2026-09-19 | 5,132 |
| 2026-09-20 | 5,134 |
| 2026-09-21 | 11,346 |
| 2026-09-22 | 5,241 |
| 2026-09-23 | 11,547 |
| 2026-09-24 | 5,613 |
| 2026-09-25 | 624,992 |
| 2026-09-26 | 6,520 |
| 2026-09-27 | 802 |
| 2026-09-29 | 59,647 |

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-04 | 173,704 |
| 2026-09-07 | 664,158 |
| 2026-09-21 | 6,512 |
| 2026-09-22 | 13,227 |
| 2026-09-23 | 16,919 |
| 2026-09-24 | 21,217 |
| 2026-09-25 | 17,713 |
| 2026-09-26 | 15,287 |
| 2026-09-27 | 11,710 |
| 2026-09-28 | 9,471 |
| 2026-09-29 | 10,346 |
| 2026-09-30 | 16,790 |
| 2026-10-01 | 7,849 |
| 2026-10-02 | 7,436 |
| 2026-10-03 | 12,851 |
| 2026-10-04 | 17,767 |
| 2026-10-05 | 16,347 |
| 2026-10-06 | 15,266 |
| 2026-10-07 | 62,465 |
| 2026-10-08 | 226,984 |
| 2026-10-09 | 53,575 |
| 2026-10-10 | 16,142 |
| 2026-10-11 | 66,752 |
| 2026-10-12 | 1,592,973 |
| 2026-10-13 | 32,987 |
| 2026-10-14 | 41,490 |
| 2026-10-15 | 51,576 |
| 2026-10-16 | 24,546 |
| 2026-10-17 | 14,430 |
| 2026-10-18 | 22,937 |
| 2026-10-19 | 11,271 |
| 2026-10-20 | 11,261 |
| 2026-10-21 | 31,086 |
| 2026-10-22 | 50,733 |
| 2026-10-23 | 42,049 |
| 2026-10-24 | 21,905 |
| 2026-10-25 | 20,645 |
| 2026-10-26 | 20,986 |
| 2026-10-27 | 16,006 |
| 2026-10-28 | 9,881 |
| 2026-10-29 | 62,690 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
