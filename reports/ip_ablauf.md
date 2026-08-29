# Seen-DB Expiry Forecast

Lauf: 2026-08-30 01:35 CEST (Europe/Berlin)
Gesamt: 9,546,199 IPs in seen_db.json (8,365,592 aktiv/180-Tage-Pfad, 1,180,607 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 173,706 |
| 8-14 Tage | 664,485 |
| 15-30 Tage | 112,086 |
| 31-60 Tage | 2,547,580 |
| 61-90 Tage | 1,142,170 |
| 91-180 Tage | 3,725,565 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 0 |
| 0-3 Tage | 87,455 |
| 4-7 Tage | 249,355 |
| 8-14 Tage | 91,198 |
| 15-30 Tage | 752,599 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-08-29 | 15,021 |
| 2026-08-30 | 10,071 |
| 2026-08-31 | 53,001 |
| 2026-09-01 | 9,362 |
| 2026-09-02 | 11,001 |
| 2026-09-03 | 148,205 |
| 2026-09-04 | 69,571 |
| 2026-09-05 | 20,578 |
| 2026-09-06 | 16,404 |
| 2026-09-07 | 13,138 |
| 2026-09-08 | 17,075 |
| 2026-09-09 | 8,895 |
| 2026-09-10 | 11,453 |
| 2026-09-11 | 12,037 |
| 2026-09-12 | 12,196 |
| 2026-09-13 | 13,035 |
| 2026-09-14 | 15,821 |
| 2026-09-15 | 6,331 |
| 2026-09-16 | 5,870 |
| 2026-09-17 | 8,914 |
| 2026-09-18 | 5,238 |
| 2026-09-19 | 5,133 |
| 2026-09-20 | 5,137 |
| 2026-09-21 | 11,350 |
| 2026-09-22 | 5,240 |
| 2026-09-23 | 11,546 |
| 2026-09-24 | 5,606 |
| 2026-09-25 | 624,994 |
| 2026-09-26 | 5,969 |
| 2026-09-27 | 11,594 |
| 2026-09-28 | 10,821 |

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-04 | 173,706 |
| 2026-09-07 | 664,485 |
| 2026-09-21 | 6,515 |
| 2026-09-22 | 13,232 |
| 2026-09-23 | 16,925 |
| 2026-09-24 | 21,220 |
| 2026-09-25 | 17,715 |
| 2026-09-26 | 15,290 |
| 2026-09-27 | 11,711 |
| 2026-09-28 | 9,478 |
| 2026-09-29 | 10,352 |
| 2026-09-30 | 16,794 |
| 2026-10-01 | 7,848 |
| 2026-10-02 | 7,444 |
| 2026-10-03 | 12,857 |
| 2026-10-04 | 17,781 |
| 2026-10-05 | 16,355 |
| 2026-10-06 | 15,270 |
| 2026-10-07 | 62,517 |
| 2026-10-08 | 227,027 |
| 2026-10-09 | 53,582 |
| 2026-10-10 | 16,143 |
| 2026-10-11 | 66,753 |
| 2026-10-12 | 1,593,016 |
| 2026-10-13 | 32,991 |
| 2026-10-14 | 41,494 |
| 2026-10-15 | 51,581 |
| 2026-10-16 | 24,551 |
| 2026-10-17 | 14,433 |
| 2026-10-18 | 22,957 |
| 2026-10-19 | 11,273 |
| 2026-10-20 | 11,260 |
| 2026-10-21 | 31,090 |
| 2026-10-22 | 50,728 |
| 2026-10-23 | 42,049 |
| 2026-10-24 | 21,906 |
| 2026-10-25 | 20,648 |
| 2026-10-26 | 20,990 |
| 2026-10-27 | 16,008 |
| 2026-10-28 | 9,882 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
