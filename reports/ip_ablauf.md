# Seen-DB Expiry Forecast

Lauf: 2026-08-25 06:33 CEST (Europe/Berlin)
Gesamt: 8,936,798 IPs in seen_db.json (8,197,018 aktiv/180-Tage-Pfad, 739,780 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 0 |
| 8-14 Tage | 839,387 |
| 15-30 Tage | 58,028 |
| 31-60 Tage | 2,536,957 |
| 61-90 Tage | 1,016,700 |
| 91-180 Tage | 3,745,946 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 0 |
| 0-3 Tage | 213,760 |
| 4-7 Tage | 87,732 |
| 8-14 Tage | 296,573 |
| 15-30 Tage | 141,715 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-08-25 | 5,749 |
| 2026-08-26 | 8,597 |
| 2026-08-27 | 14,860 |
| 2026-08-28 | 184,554 |
| 2026-08-29 | 15,071 |
| 2026-08-30 | 10,133 |
| 2026-08-31 | 53,135 |
| 2026-09-01 | 9,393 |
| 2026-09-02 | 11,052 |
| 2026-09-03 | 148,295 |
| 2026-09-04 | 69,734 |
| 2026-09-05 | 20,643 |
| 2026-09-06 | 16,526 |
| 2026-09-07 | 13,201 |
| 2026-09-08 | 17,122 |
| 2026-09-09 | 8,944 |
| 2026-09-10 | 11,513 |
| 2026-09-11 | 12,084 |
| 2026-09-12 | 12,252 |
| 2026-09-13 | 13,129 |
| 2026-09-14 | 15,889 |
| 2026-09-15 | 6,361 |
| 2026-09-16 | 5,897 |
| 2026-09-17 | 8,963 |
| 2026-09-18 | 5,272 |
| 2026-09-19 | 5,165 |
| 2026-09-20 | 5,183 |
| 2026-09-21 | 11,430 |
| 2026-09-22 | 5,313 |
| 2026-09-23 | 11,793 |
| 2026-09-24 | 2,527 |

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-04 | 173,757 |
| 2026-09-07 | 665,630 |
| 2026-09-21 | 6,530 |
| 2026-09-22 | 13,262 |
| 2026-09-23 | 16,971 |
| 2026-09-24 | 21,265 |
| 2026-09-25 | 17,761 |
| 2026-09-26 | 15,341 |
| 2026-09-27 | 11,726 |
| 2026-09-28 | 9,501 |
| 2026-09-29 | 10,384 |
| 2026-09-30 | 16,829 |
| 2026-10-01 | 7,883 |
| 2026-10-02 | 7,463 |
| 2026-10-03 | 12,905 |
| 2026-10-04 | 17,829 |
| 2026-10-05 | 16,387 |
| 2026-10-06 | 15,310 |
| 2026-10-07 | 62,729 |
| 2026-10-08 | 227,577 |
| 2026-10-09 | 53,608 |
| 2026-10-10 | 16,164 |
| 2026-10-11 | 66,794 |
| 2026-10-12 | 1,593,894 |
| 2026-10-13 | 33,001 |
| 2026-10-14 | 41,517 |
| 2026-10-15 | 51,615 |
| 2026-10-16 | 24,585 |
| 2026-10-17 | 14,478 |
| 2026-10-18 | 23,050 |
| 2026-10-19 | 11,295 |
| 2026-10-20 | 11,303 |
| 2026-10-21 | 31,140 |
| 2026-10-22 | 50,808 |
| 2026-10-23 | 42,107 |
| 2026-10-24 | 21,973 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
