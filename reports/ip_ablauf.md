# Seen-DB Expiry Forecast

Lauf: 2026-08-24 12:48 CEST (Europe/Berlin)
Gesamt: 8,817,745 IPs in seen_db.json (8,072,954 aktiv/180-Tage-Pfad, 744,791 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 0 |
| 8-14 Tage | 839,571 |
| 15-30 Tage | 36,791 |
| 31-60 Tage | 2,536,663 |
| 61-90 Tage | 1,012,123 |
| 91-180 Tage | 3,647,806 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 0 |
| 0-3 Tage | 37,335 |
| 4-7 Tage | 262,964 |
| 8-14 Tage | 288,942 |
| 15-30 Tage | 155,550 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-08-24 | 8,116 |
| 2026-08-25 | 5,752 |
| 2026-08-26 | 8,600 |
| 2026-08-27 | 14,867 |
| 2026-08-28 | 184,602 |
| 2026-08-29 | 15,075 |
| 2026-08-30 | 10,139 |
| 2026-08-31 | 53,148 |
| 2026-09-01 | 9,398 |
| 2026-09-02 | 11,056 |
| 2026-09-03 | 148,306 |
| 2026-09-04 | 69,765 |
| 2026-09-05 | 20,655 |
| 2026-09-06 | 16,546 |
| 2026-09-07 | 13,216 |
| 2026-09-08 | 17,131 |
| 2026-09-09 | 8,961 |
| 2026-09-10 | 11,520 |
| 2026-09-11 | 12,087 |
| 2026-09-12 | 12,261 |
| 2026-09-13 | 13,143 |
| 2026-09-14 | 15,893 |
| 2026-09-15 | 6,369 |
| 2026-09-16 | 5,900 |
| 2026-09-17 | 8,974 |
| 2026-09-18 | 5,277 |
| 2026-09-19 | 5,168 |
| 2026-09-20 | 5,190 |
| 2026-09-21 | 11,453 |
| 2026-09-22 | 5,518 |
| 2026-09-23 | 10,705 |

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-04 | 173,763 |
| 2026-09-07 | 665,808 |
| 2026-09-21 | 6,533 |
| 2026-09-22 | 13,270 |
| 2026-09-23 | 16,988 |
| 2026-09-24 | 21,279 |
| 2026-09-25 | 17,768 |
| 2026-09-26 | 15,348 |
| 2026-09-27 | 11,727 |
| 2026-09-28 | 9,505 |
| 2026-09-29 | 10,387 |
| 2026-09-30 | 16,837 |
| 2026-10-01 | 7,884 |
| 2026-10-02 | 7,470 |
| 2026-10-03 | 12,911 |
| 2026-10-04 | 17,837 |
| 2026-10-05 | 16,395 |
| 2026-10-06 | 15,313 |
| 2026-10-07 | 62,766 |
| 2026-10-08 | 227,677 |
| 2026-10-09 | 53,612 |
| 2026-10-10 | 16,167 |
| 2026-10-11 | 66,799 |
| 2026-10-12 | 1,594,007 |
| 2026-10-13 | 33,002 |
| 2026-10-14 | 41,520 |
| 2026-10-15 | 51,625 |
| 2026-10-16 | 24,593 |
| 2026-10-17 | 14,486 |
| 2026-10-18 | 23,067 |
| 2026-10-19 | 11,300 |
| 2026-10-20 | 11,307 |
| 2026-10-21 | 31,147 |
| 2026-10-22 | 50,813 |
| 2026-10-23 | 42,114 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
