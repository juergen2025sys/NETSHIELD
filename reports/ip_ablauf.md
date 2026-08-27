# Seen-DB Expiry Forecast

Lauf: 2026-08-27 23:08 CEST (Europe/Berlin)
Gesamt: 9,644,064 IPs in seen_db.json (8,285,619 aktiv/180-Tage-Pfad, 1,358,445 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 0 |
| 8-14 Tage | 838,716 |
| 15-30 Tage | 90,992 |
| 31-60 Tage | 2,543,944 |
| 61-90 Tage | 1,030,919 |
| 91-180 Tage | 3,781,048 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 0 |
| 0-3 Tage | 224,356 |
| 4-7 Tage | 221,664 |
| 8-14 Tage | 157,362 |
| 15-30 Tage | 755,063 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-08-27 | 14,830 |
| 2026-08-28 | 184,390 |
| 2026-08-29 | 15,041 |
| 2026-08-30 | 10,095 |
| 2026-08-31 | 53,026 |
| 2026-09-01 | 9,373 |
| 2026-09-02 | 11,023 |
| 2026-09-03 | 148,242 |
| 2026-09-04 | 69,649 |
| 2026-09-05 | 20,605 |
| 2026-09-06 | 16,456 |
| 2026-09-07 | 13,170 |
| 2026-09-08 | 17,093 |
| 2026-09-09 | 8,913 |
| 2026-09-10 | 11,476 |
| 2026-09-11 | 12,056 |
| 2026-09-12 | 12,213 |
| 2026-09-13 | 13,067 |
| 2026-09-14 | 15,849 |
| 2026-09-15 | 6,343 |
| 2026-09-16 | 5,884 |
| 2026-09-17 | 8,939 |
| 2026-09-18 | 5,252 |
| 2026-09-19 | 5,148 |
| 2026-09-20 | 5,152 |
| 2026-09-21 | 11,376 |
| 2026-09-22 | 5,263 |
| 2026-09-23 | 11,584 |
| 2026-09-24 | 5,658 |
| 2026-09-25 | 625,136 |
| 2026-09-26 | 6,143 |

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-04 | 173,727 |
| 2026-09-07 | 664,989 |
| 2026-09-21 | 6,522 |
| 2026-09-22 | 13,242 |
| 2026-09-23 | 16,942 |
| 2026-09-24 | 21,243 |
| 2026-09-25 | 17,737 |
| 2026-09-26 | 15,306 |
| 2026-09-27 | 11,717 |
| 2026-09-28 | 9,483 |
| 2026-09-29 | 10,360 |
| 2026-09-30 | 16,807 |
| 2026-10-01 | 7,858 |
| 2026-10-02 | 7,447 |
| 2026-10-03 | 12,871 |
| 2026-10-04 | 17,793 |
| 2026-10-05 | 16,365 |
| 2026-10-06 | 15,292 |
| 2026-10-07 | 62,599 |
| 2026-10-08 | 227,263 |
| 2026-10-09 | 53,590 |
| 2026-10-10 | 16,152 |
| 2026-10-11 | 66,769 |
| 2026-10-12 | 1,593,366 |
| 2026-10-13 | 32,992 |
| 2026-10-14 | 41,500 |
| 2026-10-15 | 51,593 |
| 2026-10-16 | 24,564 |
| 2026-10-17 | 14,448 |
| 2026-10-18 | 23,000 |
| 2026-10-19 | 11,282 |
| 2026-10-20 | 11,281 |
| 2026-10-21 | 31,110 |
| 2026-10-22 | 50,754 |
| 2026-10-23 | 42,070 |
| 2026-10-24 | 21,937 |
| 2026-10-25 | 20,669 |
| 2026-10-26 | 21,012 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
