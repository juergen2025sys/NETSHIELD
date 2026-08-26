# Seen-DB Expiry Forecast

Lauf: 2026-08-26 09:29 CEST (Europe/Berlin)
Gesamt: 9,591,725 IPs in seen_db.json (8,229,880 aktiv/180-Tage-Pfad, 1,361,845 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 0 |
| 8-14 Tage | 839,145 |
| 15-30 Tage | 75,748 |
| 31-60 Tage | 2,539,282 |
| 61-90 Tage | 1,023,572 |
| 91-180 Tage | 3,752,133 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 0 |
| 0-3 Tage | 223,009 |
| 4-7 Tage | 83,613 |
| 8-14 Tage | 294,333 |
| 15-30 Tage | 760,890 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-08-26 | 8,586 |
| 2026-08-27 | 14,846 |
| 2026-08-28 | 184,518 |
| 2026-08-29 | 15,059 |
| 2026-08-30 | 10,112 |
| 2026-08-31 | 53,074 |
| 2026-09-01 | 9,382 |
| 2026-09-02 | 11,045 |
| 2026-09-03 | 148,266 |
| 2026-09-04 | 69,700 |
| 2026-09-05 | 20,635 |
| 2026-09-06 | 16,500 |
| 2026-09-07 | 13,190 |
| 2026-09-08 | 17,111 |
| 2026-09-09 | 8,931 |
| 2026-09-10 | 11,502 |
| 2026-09-11 | 12,074 |
| 2026-09-12 | 12,230 |
| 2026-09-13 | 13,099 |
| 2026-09-14 | 15,871 |
| 2026-09-15 | 6,354 |
| 2026-09-16 | 5,892 |
| 2026-09-17 | 8,954 |
| 2026-09-18 | 5,259 |
| 2026-09-19 | 5,161 |
| 2026-09-20 | 5,170 |
| 2026-09-21 | 11,397 |
| 2026-09-22 | 5,279 |
| 2026-09-23 | 11,678 |
| 2026-09-24 | 6,657 |
| 2026-09-25 | 624,313 |

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-04 | 173,748 |
| 2026-09-07 | 665,397 |
| 2026-09-21 | 6,527 |
| 2026-09-22 | 13,254 |
| 2026-09-23 | 16,962 |
| 2026-09-24 | 21,251 |
| 2026-09-25 | 17,754 |
| 2026-09-26 | 15,326 |
| 2026-09-27 | 11,723 |
| 2026-09-28 | 9,494 |
| 2026-09-29 | 10,375 |
| 2026-09-30 | 16,816 |
| 2026-10-01 | 7,868 |
| 2026-10-02 | 7,456 |
| 2026-10-03 | 12,888 |
| 2026-10-04 | 17,813 |
| 2026-10-05 | 16,378 |
| 2026-10-06 | 15,302 |
| 2026-10-07 | 62,698 |
| 2026-10-08 | 227,493 |
| 2026-10-09 | 53,600 |
| 2026-10-10 | 16,157 |
| 2026-10-11 | 66,781 |
| 2026-10-12 | 1,593,695 |
| 2026-10-13 | 32,996 |
| 2026-10-14 | 41,509 |
| 2026-10-15 | 51,606 |
| 2026-10-16 | 24,571 |
| 2026-10-17 | 14,471 |
| 2026-10-18 | 23,029 |
| 2026-10-19 | 11,287 |
| 2026-10-20 | 11,294 |
| 2026-10-21 | 31,124 |
| 2026-10-22 | 50,791 |
| 2026-10-23 | 42,094 |
| 2026-10-24 | 21,957 |
| 2026-10-25 | 20,690 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
