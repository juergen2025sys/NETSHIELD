# Seen-DB Expiry Forecast

Lauf: 2026-08-28 07:35 CEST (Europe/Berlin)
Gesamt: 9,658,059 IPs in seen_db.json (8,304,785 aktiv/180-Tage-Pfad, 1,353,274 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 173,721 |
| 8-14 Tage | 664,887 |
| 15-30 Tage | 102,690 |
| 31-60 Tage | 2,548,036 |
| 61-90 Tage | 1,042,947 |
| 91-180 Tage | 3,772,504 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 0 |
| 0-3 Tage | 262,519 |
| 4-7 Tage | 238,262 |
| 8-14 Tage | 99,735 |
| 15-30 Tage | 752,758 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-08-28 | 184,369 |
| 2026-08-29 | 15,039 |
| 2026-08-30 | 10,088 |
| 2026-08-31 | 53,023 |
| 2026-09-01 | 9,371 |
| 2026-09-02 | 11,021 |
| 2026-09-03 | 148,239 |
| 2026-09-04 | 69,631 |
| 2026-09-05 | 20,601 |
| 2026-09-06 | 16,448 |
| 2026-09-07 | 13,165 |
| 2026-09-08 | 17,091 |
| 2026-09-09 | 8,907 |
| 2026-09-10 | 11,474 |
| 2026-09-11 | 12,049 |
| 2026-09-12 | 12,211 |
| 2026-09-13 | 13,058 |
| 2026-09-14 | 15,836 |
| 2026-09-15 | 6,341 |
| 2026-09-16 | 5,880 |
| 2026-09-17 | 8,937 |
| 2026-09-18 | 5,248 |
| 2026-09-19 | 5,144 |
| 2026-09-20 | 5,148 |
| 2026-09-21 | 11,370 |
| 2026-09-22 | 5,255 |
| 2026-09-23 | 11,573 |
| 2026-09-24 | 5,636 |
| 2026-09-25 | 625,096 |
| 2026-09-26 | 6,616 |
| 2026-09-27 | 9,409 |

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-04 | 173,721 |
| 2026-09-07 | 664,887 |
| 2026-09-21 | 6,519 |
| 2026-09-22 | 13,240 |
| 2026-09-23 | 16,939 |
| 2026-09-24 | 21,241 |
| 2026-09-25 | 17,735 |
| 2026-09-26 | 15,303 |
| 2026-09-27 | 11,713 |
| 2026-09-28 | 9,483 |
| 2026-09-29 | 10,357 |
| 2026-09-30 | 16,805 |
| 2026-10-01 | 7,857 |
| 2026-10-02 | 7,447 |
| 2026-10-03 | 12,869 |
| 2026-10-04 | 17,791 |
| 2026-10-05 | 16,363 |
| 2026-10-06 | 15,285 |
| 2026-10-07 | 62,585 |
| 2026-10-08 | 227,214 |
| 2026-10-09 | 53,589 |
| 2026-10-10 | 16,148 |
| 2026-10-11 | 66,767 |
| 2026-10-12 | 1,593,291 |
| 2026-10-13 | 32,992 |
| 2026-10-14 | 41,499 |
| 2026-10-15 | 51,591 |
| 2026-10-16 | 24,560 |
| 2026-10-17 | 14,444 |
| 2026-10-18 | 22,995 |
| 2026-10-19 | 11,281 |
| 2026-10-20 | 11,279 |
| 2026-10-21 | 31,105 |
| 2026-10-22 | 50,749 |
| 2026-10-23 | 42,065 |
| 2026-10-24 | 21,933 |
| 2026-10-25 | 20,668 |
| 2026-10-26 | 21,006 |
| 2026-10-27 | 16,018 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
