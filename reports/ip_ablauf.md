# Seen-DB Expiry Forecast

Lauf: 2026-08-24 21:36 CEST (Europe/Berlin)
Gesamt: 8,926,822 IPs in seen_db.json (8,180,720 aktiv/180-Tage-Pfad, 746,102 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 0 |
| 8-14 Tage | 839,500 |
| 15-30 Tage | 36,776 |
| 31-60 Tage | 2,536,474 |
| 61-90 Tage | 1,011,998 |
| 91-180 Tage | 3,755,972 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 0 |
| 0-3 Tage | 37,323 |
| 4-7 Tage | 262,914 |
| 8-14 Tage | 288,881 |
| 15-30 Tage | 156,984 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-08-24 | 8,113 |
| 2026-08-25 | 5,750 |
| 2026-08-26 | 8,598 |
| 2026-08-27 | 14,862 |
| 2026-08-28 | 184,564 |
| 2026-08-29 | 15,073 |
| 2026-08-30 | 10,136 |
| 2026-08-31 | 53,141 |
| 2026-09-01 | 9,395 |
| 2026-09-02 | 11,053 |
| 2026-09-03 | 148,301 |
| 2026-09-04 | 69,747 |
| 2026-09-05 | 20,644 |
| 2026-09-06 | 16,533 |
| 2026-09-07 | 13,208 |
| 2026-09-08 | 17,126 |
| 2026-09-09 | 8,949 |
| 2026-09-10 | 11,516 |
| 2026-09-11 | 12,086 |
| 2026-09-12 | 12,255 |
| 2026-09-13 | 13,136 |
| 2026-09-14 | 15,893 |
| 2026-09-15 | 6,363 |
| 2026-09-16 | 5,898 |
| 2026-09-17 | 8,968 |
| 2026-09-18 | 5,276 |
| 2026-09-19 | 5,167 |
| 2026-09-20 | 5,190 |
| 2026-09-21 | 11,444 |
| 2026-09-22 | 5,319 |
| 2026-09-23 | 12,398 |

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-04 | 173,760 |
| 2026-09-07 | 665,740 |
| 2026-09-21 | 6,530 |
| 2026-09-22 | 13,263 |
| 2026-09-23 | 16,983 |
| 2026-09-24 | 21,270 |
| 2026-09-25 | 17,766 |
| 2026-09-26 | 15,342 |
| 2026-09-27 | 11,727 |
| 2026-09-28 | 9,503 |
| 2026-09-29 | 10,386 |
| 2026-09-30 | 16,834 |
| 2026-10-01 | 7,884 |
| 2026-10-02 | 7,466 |
| 2026-10-03 | 12,909 |
| 2026-10-04 | 17,834 |
| 2026-10-05 | 16,390 |
| 2026-10-06 | 15,312 |
| 2026-10-07 | 62,748 |
| 2026-10-08 | 227,633 |
| 2026-10-09 | 53,611 |
| 2026-10-10 | 16,166 |
| 2026-10-11 | 66,796 |
| 2026-10-12 | 1,593,957 |
| 2026-10-13 | 33,002 |
| 2026-10-14 | 41,520 |
| 2026-10-15 | 51,621 |
| 2026-10-16 | 24,591 |
| 2026-10-17 | 14,484 |
| 2026-10-18 | 23,055 |
| 2026-10-19 | 11,298 |
| 2026-10-20 | 11,306 |
| 2026-10-21 | 31,143 |
| 2026-10-22 | 50,810 |
| 2026-10-23 | 42,110 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
