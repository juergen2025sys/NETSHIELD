# Seen-DB Expiry Forecast

Lauf: 2026-08-26 23:03 CEST (Europe/Berlin)
Gesamt: 9,616,143 IPs in seen_db.json (8,253,834 aktiv/180-Tage-Pfad, 1,362,309 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 0 |
| 8-14 Tage | 838,964 |
| 15-30 Tage | 75,723 |
| 31-60 Tage | 2,538,773 |
| 61-90 Tage | 1,023,302 |
| 91-180 Tage | 3,777,072 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 0 |
| 0-3 Tage | 222,920 |
| 4-7 Tage | 83,574 |
| 8-14 Tage | 294,247 |
| 15-30 Tage | 761,568 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-08-26 | 8,583 |
| 2026-08-27 | 14,840 |
| 2026-08-28 | 184,452 |
| 2026-08-29 | 15,045 |
| 2026-08-30 | 10,105 |
| 2026-08-31 | 53,053 |
| 2026-09-01 | 9,380 |
| 2026-09-02 | 11,036 |
| 2026-09-03 | 148,259 |
| 2026-09-04 | 69,677 |
| 2026-09-05 | 20,619 |
| 2026-09-06 | 16,483 |
| 2026-09-07 | 13,179 |
| 2026-09-08 | 17,106 |
| 2026-09-09 | 8,924 |
| 2026-09-10 | 11,493 |
| 2026-09-11 | 12,068 |
| 2026-09-12 | 12,226 |
| 2026-09-13 | 13,089 |
| 2026-09-14 | 15,860 |
| 2026-09-15 | 6,350 |
| 2026-09-16 | 5,888 |
| 2026-09-17 | 8,948 |
| 2026-09-18 | 5,257 |
| 2026-09-19 | 5,155 |
| 2026-09-20 | 5,165 |
| 2026-09-21 | 11,390 |
| 2026-09-22 | 5,272 |
| 2026-09-23 | 11,646 |
| 2026-09-24 | 5,740 |
| 2026-09-25 | 626,021 |

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-04 | 173,737 |
| 2026-09-07 | 665,227 |
| 2026-09-21 | 6,526 |
| 2026-09-22 | 13,249 |
| 2026-09-23 | 16,956 |
| 2026-09-24 | 21,250 |
| 2026-09-25 | 17,742 |
| 2026-09-26 | 15,317 |
| 2026-09-27 | 11,722 |
| 2026-09-28 | 9,489 |
| 2026-09-29 | 10,369 |
| 2026-09-30 | 16,812 |
| 2026-10-01 | 7,863 |
| 2026-10-02 | 7,452 |
| 2026-10-03 | 12,880 |
| 2026-10-04 | 17,804 |
| 2026-10-05 | 16,372 |
| 2026-10-06 | 15,298 |
| 2026-10-07 | 62,648 |
| 2026-10-08 | 227,382 |
| 2026-10-09 | 53,595 |
| 2026-10-10 | 16,154 |
| 2026-10-11 | 66,780 |
| 2026-10-12 | 1,593,503 |
| 2026-10-13 | 32,995 |
| 2026-10-14 | 41,506 |
| 2026-10-15 | 51,602 |
| 2026-10-16 | 24,569 |
| 2026-10-17 | 14,461 |
| 2026-10-18 | 23,016 |
| 2026-10-19 | 11,287 |
| 2026-10-20 | 11,291 |
| 2026-10-21 | 31,119 |
| 2026-10-22 | 50,775 |
| 2026-10-23 | 42,083 |
| 2026-10-24 | 21,947 |
| 2026-10-25 | 20,682 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
