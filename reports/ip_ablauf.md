# Seen-DB Expiry Forecast

Lauf: 2026-08-25 09:27 CEST (Europe/Berlin)
Gesamt: 8,942,684 IPs in seen_db.json (8,200,068 aktiv/180-Tage-Pfad, 742,616 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 0 |
| 8-14 Tage | 839,356 |
| 15-30 Tage | 58,019 |
| 31-60 Tage | 2,536,886 |
| 61-90 Tage | 1,016,655 |
| 91-180 Tage | 3,749,152 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 0 |
| 0-3 Tage | 213,748 |
| 4-7 Tage | 87,721 |
| 8-14 Tage | 296,554 |
| 15-30 Tage | 144,593 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-08-25 | 5,747 |
| 2026-08-26 | 8,595 |
| 2026-08-27 | 14,858 |
| 2026-08-28 | 184,548 |
| 2026-08-29 | 15,070 |
| 2026-08-30 | 10,131 |
| 2026-08-31 | 53,128 |
| 2026-09-01 | 9,392 |
| 2026-09-02 | 11,051 |
| 2026-09-03 | 148,290 |
| 2026-09-04 | 69,727 |
| 2026-09-05 | 20,642 |
| 2026-09-06 | 16,523 |
| 2026-09-07 | 13,200 |
| 2026-09-08 | 17,121 |
| 2026-09-09 | 8,942 |
| 2026-09-10 | 11,511 |
| 2026-09-11 | 12,082 |
| 2026-09-12 | 12,252 |
| 2026-09-13 | 13,125 |
| 2026-09-14 | 15,886 |
| 2026-09-15 | 6,360 |
| 2026-09-16 | 5,897 |
| 2026-09-17 | 8,961 |
| 2026-09-18 | 5,268 |
| 2026-09-19 | 5,165 |
| 2026-09-20 | 5,180 |
| 2026-09-21 | 11,424 |
| 2026-09-22 | 5,293 |
| 2026-09-23 | 11,719 |
| 2026-09-24 | 5,528 |

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-04 | 173,755 |
| 2026-09-07 | 665,601 |
| 2026-09-21 | 6,528 |
| 2026-09-22 | 13,260 |
| 2026-09-23 | 16,969 |
| 2026-09-24 | 21,262 |
| 2026-09-25 | 17,760 |
| 2026-09-26 | 15,338 |
| 2026-09-27 | 11,726 |
| 2026-09-28 | 9,501 |
| 2026-09-29 | 10,380 |
| 2026-09-30 | 16,828 |
| 2026-10-01 | 7,881 |
| 2026-10-02 | 7,462 |
| 2026-10-03 | 12,903 |
| 2026-10-04 | 17,824 |
| 2026-10-05 | 16,387 |
| 2026-10-06 | 15,310 |
| 2026-10-07 | 62,724 |
| 2026-10-08 | 227,561 |
| 2026-10-09 | 53,606 |
| 2026-10-10 | 16,164 |
| 2026-10-11 | 66,793 |
| 2026-10-12 | 1,593,879 |
| 2026-10-13 | 33,001 |
| 2026-10-14 | 41,516 |
| 2026-10-15 | 51,613 |
| 2026-10-16 | 24,585 |
| 2026-10-17 | 14,477 |
| 2026-10-18 | 23,045 |
| 2026-10-19 | 11,295 |
| 2026-10-20 | 11,303 |
| 2026-10-21 | 31,139 |
| 2026-10-22 | 50,808 |
| 2026-10-23 | 42,105 |
| 2026-10-24 | 21,972 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
