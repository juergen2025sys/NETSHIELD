# Seen-DB Expiry Forecast

Lauf: 2026-08-24 08:06 CEST (Europe/Berlin)
Gesamt: 8,808,327 IPs in seen_db.json (8,064,228 aktiv/180-Tage-Pfad, 744,099 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 0 |
| 8-14 Tage | 839,619 |
| 15-30 Tage | 36,798 |
| 31-60 Tage | 2,536,829 |
| 61-90 Tage | 1,012,221 |
| 91-180 Tage | 3,638,761 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 0 |
| 0-3 Tage | 37,343 |
| 4-7 Tage | 262,976 |
| 8-14 Tage | 288,981 |
| 15-30 Tage | 154,799 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-08-24 | 8,117 |
| 2026-08-25 | 5,754 |
| 2026-08-26 | 8,600 |
| 2026-08-27 | 14,872 |
| 2026-08-28 | 184,608 |
| 2026-08-29 | 15,076 |
| 2026-08-30 | 10,141 |
| 2026-08-31 | 53,151 |
| 2026-09-01 | 9,402 |
| 2026-09-02 | 11,060 |
| 2026-09-03 | 148,312 |
| 2026-09-04 | 69,776 |
| 2026-09-05 | 20,660 |
| 2026-09-06 | 16,550 |
| 2026-09-07 | 13,221 |
| 2026-09-08 | 17,133 |
| 2026-09-09 | 8,963 |
| 2026-09-10 | 11,524 |
| 2026-09-11 | 12,087 |
| 2026-09-12 | 12,264 |
| 2026-09-13 | 13,151 |
| 2026-09-14 | 15,894 |
| 2026-09-15 | 6,369 |
| 2026-09-16 | 5,900 |
| 2026-09-17 | 8,974 |
| 2026-09-18 | 5,281 |
| 2026-09-19 | 5,172 |
| 2026-09-20 | 5,192 |
| 2026-09-21 | 11,466 |
| 2026-09-22 | 5,540 |
| 2026-09-23 | 9,889 |

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-04 | 173,763 |
| 2026-09-07 | 665,856 |
| 2026-09-21 | 6,533 |
| 2026-09-22 | 13,271 |
| 2026-09-23 | 16,994 |
| 2026-09-24 | 21,281 |
| 2026-09-25 | 17,769 |
| 2026-09-26 | 15,349 |
| 2026-09-27 | 11,728 |
| 2026-09-28 | 9,505 |
| 2026-09-29 | 10,388 |
| 2026-09-30 | 16,837 |
| 2026-10-01 | 7,886 |
| 2026-10-02 | 7,473 |
| 2026-10-03 | 12,912 |
| 2026-10-04 | 17,838 |
| 2026-10-05 | 16,396 |
| 2026-10-06 | 15,314 |
| 2026-10-07 | 62,773 |
| 2026-10-08 | 227,696 |
| 2026-10-09 | 53,613 |
| 2026-10-10 | 16,167 |
| 2026-10-11 | 66,801 |
| 2026-10-12 | 1,594,103 |
| 2026-10-13 | 33,003 |
| 2026-10-14 | 41,522 |
| 2026-10-15 | 51,626 |
| 2026-10-16 | 24,595 |
| 2026-10-17 | 14,488 |
| 2026-10-18 | 23,070 |
| 2026-10-19 | 11,305 |
| 2026-10-20 | 11,310 |
| 2026-10-21 | 31,149 |
| 2026-10-22 | 50,817 |
| 2026-10-23 | 42,115 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
