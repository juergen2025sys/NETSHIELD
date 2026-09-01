# Seen-DB Expiry Forecast

Lauf: 2026-09-01 06:03 CEST (Europe/Berlin)
Gesamt: 9,796,731 IPs in seen_db.json (8,417,811 aktiv/180-Tage-Pfad, 1,378,920 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 837,617 |
| 8-14 Tage | 0 |
| 15-30 Tage | 139,115 |
| 31-60 Tage | 2,670,933 |
| 61-90 Tage | 1,044,963 |
| 91-180 Tage | 3,725,183 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 174,598 |
| 0-3 Tage | 221,470 |
| 4-7 Tage | 119,598 |
| 8-14 Tage | 90,397 |
| 15-30 Tage | 772,857 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-01 | 52,971 |
| 2026-09-02 | 9,342 |
| 2026-09-03 | 10,983 |
| 2026-09-04 | 148,174 |
| 2026-09-05 | 69,528 |
| 2026-09-06 | 20,562 |
| 2026-09-07 | 16,376 |
| 2026-09-08 | 13,132 |
| 2026-09-09 | 17,066 |
| 2026-09-10 | 8,874 |
| 2026-09-11 | 11,439 |
| 2026-09-12 | 12,024 |
| 2026-09-13 | 12,179 |
| 2026-09-14 | 13,015 |
| 2026-09-15 | 15,800 |
| 2026-09-16 | 6,319 |
| 2026-09-17 | 5,867 |
| 2026-09-18 | 8,909 |
| 2026-09-19 | 5,225 |
| 2026-09-20 | 5,128 |
| 2026-09-21 | 5,126 |
| 2026-09-22 | 11,338 |
| 2026-09-23 | 5,232 |
| 2026-09-24 | 11,534 |
| 2026-09-25 | 5,607 |
| 2026-09-26 | 624,939 |
| 2026-09-27 | 6,488 |
| 2026-09-28 | 797 |
| 2026-09-30 | 60,383 |
| 2026-10-01 | 8,598 |

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-05 | 173,699 |
| 2026-09-08 | 663,918 |
| 2026-09-22 | 6,508 |
| 2026-09-23 | 13,224 |
| 2026-09-24 | 16,911 |
| 2026-09-25 | 21,206 |
| 2026-09-26 | 17,704 |
| 2026-09-27 | 15,276 |
| 2026-09-28 | 11,704 |
| 2026-09-29 | 9,463 |
| 2026-09-30 | 10,340 |
| 2026-10-01 | 16,779 |
| 2026-10-02 | 7,841 |
| 2026-10-03 | 7,433 |
| 2026-10-04 | 12,842 |
| 2026-10-05 | 17,760 |
| 2026-10-06 | 16,338 |
| 2026-10-07 | 15,257 |
| 2026-10-08 | 62,423 |
| 2026-10-09 | 226,906 |
| 2026-10-10 | 53,572 |
| 2026-10-11 | 16,140 |
| 2026-10-12 | 66,746 |
| 2026-10-13 | 1,592,827 |
| 2026-10-14 | 32,985 |
| 2026-10-15 | 41,485 |
| 2026-10-16 | 51,568 |
| 2026-10-17 | 24,538 |
| 2026-10-18 | 14,423 |
| 2026-10-19 | 22,915 |
| 2026-10-20 | 11,267 |
| 2026-10-21 | 11,254 |
| 2026-10-22 | 31,075 |
| 2026-10-23 | 50,719 |
| 2026-10-24 | 42,036 |
| 2026-10-25 | 21,891 |
| 2026-10-26 | 20,632 |
| 2026-10-27 | 20,975 |
| 2026-10-28 | 15,993 |
| 2026-10-29 | 9,868 |
| 2026-10-30 | 62,653 |
| 2026-10-31 | 88,571 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
