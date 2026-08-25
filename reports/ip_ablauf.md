# Seen-DB Expiry Forecast

Lauf: 2026-08-25 05:07 CEST (Europe/Berlin)
Gesamt: 8,927,629 IPs in seen_db.json (8,190,098 aktiv/180-Tage-Pfad, 737,531 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 0 |
| 8-14 Tage | 839,429 |
| 15-30 Tage | 58,034 |
| 31-60 Tage | 2,537,058 |
| 61-90 Tage | 1,016,759 |
| 91-180 Tage | 3,738,818 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 0 |
| 0-3 Tage | 213,764 |
| 4-7 Tage | 87,737 |
| 8-14 Tage | 296,590 |
| 15-30 Tage | 139,440 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-08-25 | 5,749 |
| 2026-08-26 | 8,598 |
| 2026-08-27 | 14,861 |
| 2026-08-28 | 184,556 |
| 2026-08-29 | 15,072 |
| 2026-08-30 | 10,134 |
| 2026-08-31 | 53,138 |
| 2026-09-01 | 9,393 |
| 2026-09-02 | 11,053 |
| 2026-09-03 | 148,300 |
| 2026-09-04 | 69,738 |
| 2026-09-05 | 20,644 |
| 2026-09-06 | 16,527 |
| 2026-09-07 | 13,205 |
| 2026-09-08 | 17,123 |
| 2026-09-09 | 8,945 |
| 2026-09-10 | 11,514 |
| 2026-09-11 | 12,086 |
| 2026-09-12 | 12,253 |
| 2026-09-13 | 13,132 |
| 2026-09-14 | 15,889 |
| 2026-09-15 | 6,362 |
| 2026-09-16 | 5,898 |
| 2026-09-17 | 8,966 |
| 2026-09-18 | 5,273 |
| 2026-09-19 | 5,166 |
| 2026-09-20 | 5,185 |
| 2026-09-21 | 11,433 |
| 2026-09-22 | 5,314 |
| 2026-09-23 | 11,801 |
| 2026-09-24 | 223 |

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-04 | 173,757 |
| 2026-09-07 | 665,672 |
| 2026-09-21 | 6,530 |
| 2026-09-22 | 13,263 |
| 2026-09-23 | 16,975 |
| 2026-09-24 | 21,266 |
| 2026-09-25 | 17,762 |
| 2026-09-26 | 15,341 |
| 2026-09-27 | 11,727 |
| 2026-09-28 | 9,501 |
| 2026-09-29 | 10,384 |
| 2026-09-30 | 16,831 |
| 2026-10-01 | 7,884 |
| 2026-10-02 | 7,465 |
| 2026-10-03 | 12,907 |
| 2026-10-04 | 17,830 |
| 2026-10-05 | 16,388 |
| 2026-10-06 | 15,311 |
| 2026-10-07 | 62,744 |
| 2026-10-08 | 227,609 |
| 2026-10-09 | 53,610 |
| 2026-10-10 | 16,164 |
| 2026-10-11 | 66,795 |
| 2026-10-12 | 1,593,917 |
| 2026-10-13 | 33,001 |
| 2026-10-14 | 41,519 |
| 2026-10-15 | 51,616 |
| 2026-10-16 | 24,587 |
| 2026-10-17 | 14,480 |
| 2026-10-18 | 23,054 |
| 2026-10-19 | 11,295 |
| 2026-10-20 | 11,304 |
| 2026-10-21 | 31,141 |
| 2026-10-22 | 50,809 |
| 2026-10-23 | 42,109 |
| 2026-10-24 | 21,973 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
