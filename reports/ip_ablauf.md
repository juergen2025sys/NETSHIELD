# Seen-DB Expiry Forecast

Lauf: 2026-08-30 12:38 CEST (Europe/Berlin)
Gesamt: 9,541,268 IPs in seen_db.json (8,373,973 aktiv/180-Tage-Pfad, 1,167,295 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 173,702 |
| 8-14 Tage | 664,172 |
| 15-30 Tage | 122,393 |
| 31-60 Tage | 2,599,533 |
| 61-90 Tage | 1,107,881 |
| 91-180 Tage | 3,706,292 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 0 |
| 0-3 Tage | 83,394 |
| 4-7 Tage | 254,693 |
| 8-14 Tage | 87,778 |
| 15-30 Tage | 741,430 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-08-30 | 10,062 |
| 2026-08-31 | 52,990 |
| 2026-09-01 | 9,352 |
| 2026-09-02 | 10,990 |
| 2026-09-03 | 148,184 |
| 2026-09-04 | 69,550 |
| 2026-09-05 | 20,567 |
| 2026-09-06 | 16,392 |
| 2026-09-07 | 13,133 |
| 2026-09-08 | 17,069 |
| 2026-09-09 | 8,889 |
| 2026-09-10 | 11,446 |
| 2026-09-11 | 12,033 |
| 2026-09-12 | 12,187 |
| 2026-09-13 | 13,021 |
| 2026-09-14 | 15,815 |
| 2026-09-15 | 6,327 |
| 2026-09-16 | 5,867 |
| 2026-09-17 | 8,908 |
| 2026-09-18 | 5,235 |
| 2026-09-19 | 5,130 |
| 2026-09-20 | 5,130 |
| 2026-09-21 | 11,341 |
| 2026-09-22 | 5,236 |
| 2026-09-23 | 11,543 |
| 2026-09-24 | 5,596 |
| 2026-09-25 | 624,973 |
| 2026-09-26 | 5,954 |
| 2026-09-27 | 11,521 |
| 2026-09-28 | 8,601 |
| 2026-09-29 | 4,253 |

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-04 | 173,702 |
| 2026-09-07 | 664,172 |
| 2026-09-21 | 6,508 |
| 2026-09-22 | 13,230 |
| 2026-09-23 | 16,918 |
| 2026-09-24 | 21,210 |
| 2026-09-25 | 17,710 |
| 2026-09-26 | 15,290 |
| 2026-09-27 | 11,710 |
| 2026-09-28 | 9,472 |
| 2026-09-29 | 10,345 |
| 2026-09-30 | 16,788 |
| 2026-10-01 | 7,845 |
| 2026-10-02 | 7,438 |
| 2026-10-03 | 12,849 |
| 2026-10-04 | 17,770 |
| 2026-10-05 | 16,344 |
| 2026-10-06 | 15,260 |
| 2026-10-07 | 62,453 |
| 2026-10-08 | 226,953 |
| 2026-10-09 | 53,576 |
| 2026-10-10 | 16,141 |
| 2026-10-11 | 66,750 |
| 2026-10-12 | 1,592,959 |
| 2026-10-13 | 32,990 |
| 2026-10-14 | 41,488 |
| 2026-10-15 | 51,572 |
| 2026-10-16 | 24,544 |
| 2026-10-17 | 14,429 |
| 2026-10-18 | 22,933 |
| 2026-10-19 | 11,269 |
| 2026-10-20 | 11,255 |
| 2026-10-21 | 31,083 |
| 2026-10-22 | 50,725 |
| 2026-10-23 | 42,047 |
| 2026-10-24 | 21,897 |
| 2026-10-25 | 20,642 |
| 2026-10-26 | 20,984 |
| 2026-10-27 | 16,004 |
| 2026-10-28 | 9,876 |
| 2026-10-29 | 62,669 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
