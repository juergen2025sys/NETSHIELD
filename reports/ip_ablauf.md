# Seen-DB Expiry Forecast

Lauf: 2026-08-24 05:12 CEST (Europe/Berlin)
Gesamt: 9,416,186 IPs in seen_db.json (8,024,409 aktiv/180-Tage-Pfad, 1,391,777 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 0 |
| 8-14 Tage | 839,687 |
| 15-30 Tage | 36,801 |
| 31-60 Tage | 2,536,955 |
| 61-90 Tage | 1,012,300 |
| 91-180 Tage | 3,598,666 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 657,382 |
| 0-3 Tage | 37,350 |
| 4-7 Tage | 262,992 |
| 8-14 Tage | 289,010 |
| 15-30 Tage | 145,043 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-08-24 | 8,120 |
| 2026-08-25 | 5,755 |
| 2026-08-26 | 8,602 |
| 2026-08-27 | 14,873 |
| 2026-08-28 | 184,616 |
| 2026-08-29 | 15,076 |
| 2026-08-30 | 10,144 |
| 2026-08-31 | 53,156 |
| 2026-09-01 | 9,403 |
| 2026-09-02 | 11,063 |
| 2026-09-03 | 148,318 |
| 2026-09-04 | 69,782 |
| 2026-09-05 | 20,666 |
| 2026-09-06 | 16,553 |
| 2026-09-07 | 13,225 |
| 2026-09-08 | 17,135 |
| 2026-09-09 | 8,967 |
| 2026-09-10 | 11,527 |
| 2026-09-11 | 12,087 |
| 2026-09-12 | 12,267 |
| 2026-09-13 | 13,156 |
| 2026-09-14 | 15,896 |
| 2026-09-15 | 6,372 |
| 2026-09-16 | 5,901 |
| 2026-09-17 | 8,975 |
| 2026-09-18 | 5,284 |
| 2026-09-19 | 5,174 |
| 2026-09-20 | 5,195 |
| 2026-09-21 | 11,498 |
| 2026-09-22 | 5,609 |

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-04 | 173,765 |
| 2026-09-07 | 665,922 |
| 2026-09-21 | 6,533 |
| 2026-09-22 | 13,274 |
| 2026-09-23 | 16,994 |
| 2026-09-24 | 21,283 |
| 2026-09-25 | 17,773 |
| 2026-09-26 | 15,353 |
| 2026-09-27 | 11,729 |
| 2026-09-28 | 9,507 |
| 2026-09-29 | 10,391 |
| 2026-09-30 | 16,837 |
| 2026-10-01 | 7,889 |
| 2026-10-02 | 7,475 |
| 2026-10-03 | 12,914 |
| 2026-10-04 | 17,844 |
| 2026-10-05 | 16,399 |
| 2026-10-06 | 15,315 |
| 2026-10-07 | 62,781 |
| 2026-10-08 | 227,741 |
| 2026-10-09 | 53,615 |
| 2026-10-10 | 16,167 |
| 2026-10-11 | 66,802 |
| 2026-10-12 | 1,594,123 |
| 2026-10-13 | 33,005 |
| 2026-10-14 | 41,523 |
| 2026-10-15 | 51,628 |
| 2026-10-16 | 24,595 |
| 2026-10-17 | 14,490 |
| 2026-10-18 | 23,071 |
| 2026-10-19 | 11,306 |
| 2026-10-20 | 11,310 |
| 2026-10-21 | 31,150 |
| 2026-10-22 | 50,821 |
| 2026-10-23 | 42,118 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
