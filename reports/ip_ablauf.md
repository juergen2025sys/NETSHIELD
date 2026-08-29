# Seen-DB Expiry Forecast

Lauf: 2026-08-29 04:03 CEST (Europe/Berlin)
Gesamt: 9,513,964 IPs in seen_db.json (8,341,749 aktiv/180-Tage-Pfad, 1,172,215 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 173,710 |
| 8-14 Tage | 664,649 |
| 15-30 Tage | 112,124 |
| 31-60 Tage | 2,547,948 |
| 61-90 Tage | 1,142,469 |
| 91-180 Tage | 3,700,849 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 0 |
| 0-3 Tage | 87,480 |
| 4-7 Tage | 249,409 |
| 8-14 Tage | 91,250 |
| 15-30 Tage | 744,076 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-08-29 | 15,032 |
| 2026-08-30 | 10,075 |
| 2026-08-31 | 53,009 |
| 2026-09-01 | 9,364 |
| 2026-09-02 | 11,010 |
| 2026-09-03 | 148,220 |
| 2026-09-04 | 69,592 |
| 2026-09-05 | 20,587 |
| 2026-09-06 | 16,424 |
| 2026-09-07 | 13,149 |
| 2026-09-08 | 17,078 |
| 2026-09-09 | 8,898 |
| 2026-09-10 | 11,459 |
| 2026-09-11 | 12,042 |
| 2026-09-12 | 12,200 |
| 2026-09-13 | 13,045 |
| 2026-09-14 | 15,824 |
| 2026-09-15 | 6,334 |
| 2026-09-16 | 5,873 |
| 2026-09-17 | 8,922 |
| 2026-09-18 | 5,244 |
| 2026-09-19 | 5,140 |
| 2026-09-20 | 5,138 |
| 2026-09-21 | 11,359 |
| 2026-09-22 | 5,247 |
| 2026-09-23 | 11,555 |
| 2026-09-24 | 5,618 |
| 2026-09-25 | 625,036 |
| 2026-09-26 | 5,990 |
| 2026-09-27 | 11,926 |
| 2026-09-28 | 1,825 |

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-04 | 173,710 |
| 2026-09-07 | 664,649 |
| 2026-09-21 | 6,517 |
| 2026-09-22 | 13,237 |
| 2026-09-23 | 16,932 |
| 2026-09-24 | 21,228 |
| 2026-09-25 | 17,723 |
| 2026-09-26 | 15,295 |
| 2026-09-27 | 11,712 |
| 2026-09-28 | 9,480 |
| 2026-09-29 | 10,353 |
| 2026-09-30 | 16,798 |
| 2026-10-01 | 7,853 |
| 2026-10-02 | 7,445 |
| 2026-10-03 | 12,864 |
| 2026-10-04 | 17,784 |
| 2026-10-05 | 16,356 |
| 2026-10-06 | 15,277 |
| 2026-10-07 | 62,539 |
| 2026-10-08 | 227,106 |
| 2026-10-09 | 53,586 |
| 2026-10-10 | 16,145 |
| 2026-10-11 | 66,757 |
| 2026-10-12 | 1,593,143 |
| 2026-10-13 | 32,991 |
| 2026-10-14 | 41,497 |
| 2026-10-15 | 51,582 |
| 2026-10-16 | 24,553 |
| 2026-10-17 | 14,440 |
| 2026-10-18 | 22,971 |
| 2026-10-19 | 11,276 |
| 2026-10-20 | 11,269 |
| 2026-10-21 | 31,097 |
| 2026-10-22 | 50,735 |
| 2026-10-23 | 42,054 |
| 2026-10-24 | 21,920 |
| 2026-10-25 | 20,657 |
| 2026-10-26 | 20,998 |
| 2026-10-27 | 16,016 |
| 2026-10-28 | 9,886 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
