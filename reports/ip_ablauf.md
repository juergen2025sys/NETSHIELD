# Seen-DB Expiry Forecast

Lauf: 2026-08-29 13:27 CEST (Europe/Berlin)
Gesamt: 9,525,863 IPs in seen_db.json (8,348,211 aktiv/180-Tage-Pfad, 1,177,652 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 173,708 |
| 8-14 Tage | 664,584 |
| 15-30 Tage | 112,117 |
| 31-60 Tage | 2,547,835 |
| 61-90 Tage | 1,142,369 |
| 91-180 Tage | 3,707,598 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 0 |
| 0-3 Tage | 87,475 |
| 4-7 Tage | 249,392 |
| 8-14 Tage | 91,236 |
| 15-30 Tage | 749,549 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-08-29 | 15,031 |
| 2026-08-30 | 10,074 |
| 2026-08-31 | 53,007 |
| 2026-09-01 | 9,363 |
| 2026-09-02 | 11,009 |
| 2026-09-03 | 148,215 |
| 2026-09-04 | 69,583 |
| 2026-09-05 | 20,585 |
| 2026-09-06 | 16,419 |
| 2026-09-07 | 13,146 |
| 2026-09-08 | 17,076 |
| 2026-09-09 | 8,897 |
| 2026-09-10 | 11,458 |
| 2026-09-11 | 12,040 |
| 2026-09-12 | 12,200 |
| 2026-09-13 | 13,040 |
| 2026-09-14 | 15,823 |
| 2026-09-15 | 6,333 |
| 2026-09-16 | 5,872 |
| 2026-09-17 | 8,921 |
| 2026-09-18 | 5,242 |
| 2026-09-19 | 5,138 |
| 2026-09-20 | 5,137 |
| 2026-09-21 | 11,354 |
| 2026-09-22 | 5,245 |
| 2026-09-23 | 11,554 |
| 2026-09-24 | 5,616 |
| 2026-09-25 | 625,016 |
| 2026-09-26 | 5,980 |
| 2026-09-27 | 11,870 |
| 2026-09-28 | 7,408 |

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-04 | 173,708 |
| 2026-09-07 | 664,584 |
| 2026-09-21 | 6,517 |
| 2026-09-22 | 13,237 |
| 2026-09-23 | 16,930 |
| 2026-09-24 | 21,226 |
| 2026-09-25 | 17,721 |
| 2026-09-26 | 15,295 |
| 2026-09-27 | 11,712 |
| 2026-09-28 | 9,479 |
| 2026-09-29 | 10,353 |
| 2026-09-30 | 16,797 |
| 2026-10-01 | 7,851 |
| 2026-10-02 | 7,445 |
| 2026-10-03 | 12,860 |
| 2026-10-04 | 17,782 |
| 2026-10-05 | 16,356 |
| 2026-10-06 | 15,276 |
| 2026-10-07 | 62,534 |
| 2026-10-08 | 227,081 |
| 2026-10-09 | 53,584 |
| 2026-10-10 | 16,144 |
| 2026-10-11 | 66,756 |
| 2026-10-12 | 1,593,105 |
| 2026-10-13 | 32,991 |
| 2026-10-14 | 41,495 |
| 2026-10-15 | 51,582 |
| 2026-10-16 | 24,551 |
| 2026-10-17 | 14,439 |
| 2026-10-18 | 22,968 |
| 2026-10-19 | 11,274 |
| 2026-10-20 | 11,267 |
| 2026-10-21 | 31,095 |
| 2026-10-22 | 50,732 |
| 2026-10-23 | 42,053 |
| 2026-10-24 | 21,914 |
| 2026-10-25 | 20,653 |
| 2026-10-26 | 20,997 |
| 2026-10-27 | 16,015 |
| 2026-10-28 | 9,885 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
