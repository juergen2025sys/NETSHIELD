# Seen-DB Expiry Forecast

Lauf: 2026-08-27 02:58 CEST (Europe/Berlin)
Gesamt: 9,611,073 IPs in seen_db.json (8,256,928 aktiv/180-Tage-Pfad, 1,354,145 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 0 |
| 8-14 Tage | 838,918 |
| 15-30 Tage | 91,035 |
| 31-60 Tage | 2,544,439 |
| 61-90 Tage | 1,031,243 |
| 91-180 Tage | 3,751,293 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 0 |
| 0-3 Tage | 224,438 |
| 4-7 Tage | 221,725 |
| 8-14 Tage | 157,465 |
| 15-30 Tage | 750,517 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-08-27 | 14,839 |
| 2026-08-28 | 184,450 |
| 2026-08-29 | 15,045 |
| 2026-08-30 | 10,104 |
| 2026-08-31 | 53,051 |
| 2026-09-01 | 9,380 |
| 2026-09-02 | 11,036 |
| 2026-09-03 | 148,258 |
| 2026-09-04 | 69,676 |
| 2026-09-05 | 20,616 |
| 2026-09-06 | 16,479 |
| 2026-09-07 | 13,178 |
| 2026-09-08 | 17,104 |
| 2026-09-09 | 8,923 |
| 2026-09-10 | 11,489 |
| 2026-09-11 | 12,067 |
| 2026-09-12 | 12,225 |
| 2026-09-13 | 13,087 |
| 2026-09-14 | 15,860 |
| 2026-09-15 | 6,348 |
| 2026-09-16 | 5,887 |
| 2026-09-17 | 8,948 |
| 2026-09-18 | 5,256 |
| 2026-09-19 | 5,155 |
| 2026-09-20 | 5,163 |
| 2026-09-21 | 11,389 |
| 2026-09-22 | 5,268 |
| 2026-09-23 | 11,643 |
| 2026-09-24 | 5,736 |
| 2026-09-25 | 626,042 |
| 2026-09-26 | 443 |

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-04 | 173,736 |
| 2026-09-07 | 665,182 |
| 2026-09-21 | 6,526 |
| 2026-09-22 | 13,248 |
| 2026-09-23 | 16,955 |
| 2026-09-24 | 21,249 |
| 2026-09-25 | 17,741 |
| 2026-09-26 | 15,316 |
| 2026-09-27 | 11,722 |
| 2026-09-28 | 9,489 |
| 2026-09-29 | 10,369 |
| 2026-09-30 | 16,811 |
| 2026-10-01 | 7,863 |
| 2026-10-02 | 7,452 |
| 2026-10-03 | 12,880 |
| 2026-10-04 | 17,802 |
| 2026-10-05 | 16,372 |
| 2026-10-06 | 15,298 |
| 2026-10-07 | 62,646 |
| 2026-10-08 | 227,367 |
| 2026-10-09 | 53,594 |
| 2026-10-10 | 16,154 |
| 2026-10-11 | 66,778 |
| 2026-10-12 | 1,593,499 |
| 2026-10-13 | 32,992 |
| 2026-10-14 | 41,506 |
| 2026-10-15 | 51,601 |
| 2026-10-16 | 24,569 |
| 2026-10-17 | 14,461 |
| 2026-10-18 | 23,016 |
| 2026-10-19 | 11,287 |
| 2026-10-20 | 11,290 |
| 2026-10-21 | 31,117 |
| 2026-10-22 | 50,771 |
| 2026-10-23 | 42,083 |
| 2026-10-24 | 21,946 |
| 2026-10-25 | 20,681 |
| 2026-10-26 | 21,023 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
