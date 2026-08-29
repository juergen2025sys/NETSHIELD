# Seen-DB Expiry Forecast

Lauf: 2026-08-29 20:19 CEST (Europe/Berlin)
Gesamt: 9,535,319 IPs in seen_db.json (8,358,266 aktiv/180-Tage-Pfad, 1,177,053 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 173,706 |
| 8-14 Tage | 664,521 |
| 15-30 Tage | 112,095 |
| 31-60 Tage | 2,547,680 |
| 61-90 Tage | 1,142,262 |
| 91-180 Tage | 3,718,002 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 0 |
| 0-3 Tage | 87,458 |
| 4-7 Tage | 249,366 |
| 8-14 Tage | 91,211 |
| 15-30 Tage | 749,018 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-08-29 | 15,022 |
| 2026-08-30 | 10,071 |
| 2026-08-31 | 53,003 |
| 2026-09-01 | 9,362 |
| 2026-09-02 | 11,004 |
| 2026-09-03 | 148,206 |
| 2026-09-04 | 69,577 |
| 2026-09-05 | 20,579 |
| 2026-09-06 | 16,407 |
| 2026-09-07 | 13,140 |
| 2026-09-08 | 17,076 |
| 2026-09-09 | 8,896 |
| 2026-09-10 | 11,455 |
| 2026-09-11 | 12,038 |
| 2026-09-12 | 12,199 |
| 2026-09-13 | 13,038 |
| 2026-09-14 | 15,821 |
| 2026-09-15 | 6,332 |
| 2026-09-16 | 5,871 |
| 2026-09-17 | 8,914 |
| 2026-09-18 | 5,238 |
| 2026-09-19 | 5,136 |
| 2026-09-20 | 5,137 |
| 2026-09-21 | 11,353 |
| 2026-09-22 | 5,244 |
| 2026-09-23 | 11,548 |
| 2026-09-24 | 5,611 |
| 2026-09-25 | 625,005 |
| 2026-09-26 | 5,975 |
| 2026-09-27 | 11,612 |
| 2026-09-28 | 7,183 |

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-04 | 173,706 |
| 2026-09-07 | 664,521 |
| 2026-09-21 | 6,516 |
| 2026-09-22 | 13,234 |
| 2026-09-23 | 16,926 |
| 2026-09-24 | 21,221 |
| 2026-09-25 | 17,717 |
| 2026-09-26 | 15,291 |
| 2026-09-27 | 11,711 |
| 2026-09-28 | 9,479 |
| 2026-09-29 | 10,352 |
| 2026-09-30 | 16,796 |
| 2026-10-01 | 7,850 |
| 2026-10-02 | 7,445 |
| 2026-10-03 | 12,857 |
| 2026-10-04 | 17,782 |
| 2026-10-05 | 16,356 |
| 2026-10-06 | 15,273 |
| 2026-10-07 | 62,519 |
| 2026-10-08 | 227,040 |
| 2026-10-09 | 53,582 |
| 2026-10-10 | 16,144 |
| 2026-10-11 | 66,754 |
| 2026-10-12 | 1,593,061 |
| 2026-10-13 | 32,991 |
| 2026-10-14 | 41,494 |
| 2026-10-15 | 51,582 |
| 2026-10-16 | 24,551 |
| 2026-10-17 | 14,434 |
| 2026-10-18 | 22,964 |
| 2026-10-19 | 11,273 |
| 2026-10-20 | 11,261 |
| 2026-10-21 | 31,092 |
| 2026-10-22 | 50,730 |
| 2026-10-23 | 42,051 |
| 2026-10-24 | 21,910 |
| 2026-10-25 | 20,651 |
| 2026-10-26 | 20,991 |
| 2026-10-27 | 16,011 |
| 2026-10-28 | 9,883 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
