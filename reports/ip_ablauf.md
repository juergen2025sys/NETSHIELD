# Seen-DB Expiry Forecast

Lauf: 2026-08-31 02:22 CEST (Europe/Berlin)
Gesamt: 9,589,730 IPs in seen_db.json (8,384,257 aktiv/180-Tage-Pfad, 1,205,473 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 837,840 |
| 8-14 Tage | 0 |
| 15-30 Tage | 139,186 |
| 31-60 Tage | 2,671,400 |
| 61-90 Tage | 1,045,295 |
| 91-180 Tage | 3,690,536 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 10,064 |
| 0-3 Tage | 221,535 |
| 4-7 Tage | 119,673 |
| 8-14 Tage | 90,469 |
| 15-30 Tage | 763,732 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-08-31 | 52,994 |
| 2026-09-01 | 9,354 |
| 2026-09-02 | 10,995 |
| 2026-09-03 | 148,192 |
| 2026-09-04 | 69,557 |
| 2026-09-05 | 20,575 |
| 2026-09-06 | 16,401 |
| 2026-09-07 | 13,140 |
| 2026-09-08 | 17,073 |
| 2026-09-09 | 8,889 |
| 2026-09-10 | 11,450 |
| 2026-09-11 | 12,032 |
| 2026-09-12 | 12,187 |
| 2026-09-13 | 13,023 |
| 2026-09-14 | 15,815 |
| 2026-09-15 | 6,323 |
| 2026-09-16 | 5,868 |
| 2026-09-17 | 8,915 |
| 2026-09-18 | 5,235 |
| 2026-09-19 | 5,132 |
| 2026-09-20 | 5,132 |
| 2026-09-21 | 11,345 |
| 2026-09-22 | 5,241 |
| 2026-09-23 | 11,547 |
| 2026-09-24 | 5,613 |
| 2026-09-25 | 624,984 |
| 2026-09-26 | 6,517 |
| 2026-09-27 | 801 |
| 2026-09-29 | 61,079 |

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-04 | 173,704 |
| 2026-09-07 | 664,136 |
| 2026-09-21 | 6,512 |
| 2026-09-22 | 13,227 |
| 2026-09-23 | 16,919 |
| 2026-09-24 | 21,215 |
| 2026-09-25 | 17,712 |
| 2026-09-26 | 15,286 |
| 2026-09-27 | 11,710 |
| 2026-09-28 | 9,471 |
| 2026-09-29 | 10,346 |
| 2026-09-30 | 16,788 |
| 2026-10-01 | 7,848 |
| 2026-10-02 | 7,435 |
| 2026-10-03 | 12,851 |
| 2026-10-04 | 17,767 |
| 2026-10-05 | 16,346 |
| 2026-10-06 | 15,264 |
| 2026-10-07 | 62,460 |
| 2026-10-08 | 226,977 |
| 2026-10-09 | 53,574 |
| 2026-10-10 | 16,142 |
| 2026-10-11 | 66,751 |
| 2026-10-12 | 1,592,961 |
| 2026-10-13 | 32,986 |
| 2026-10-14 | 41,490 |
| 2026-10-15 | 51,576 |
| 2026-10-16 | 24,544 |
| 2026-10-17 | 14,429 |
| 2026-10-18 | 22,933 |
| 2026-10-19 | 11,270 |
| 2026-10-20 | 11,260 |
| 2026-10-21 | 31,082 |
| 2026-10-22 | 50,730 |
| 2026-10-23 | 42,047 |
| 2026-10-24 | 21,904 |
| 2026-10-25 | 20,641 |
| 2026-10-26 | 20,985 |
| 2026-10-27 | 16,004 |
| 2026-10-28 | 9,879 |
| 2026-10-29 | 62,681 |
| 2026-10-30 | 88,583 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
