# Seen-DB Expiry Forecast

Lauf: 2026-08-24 09:59 CEST (Europe/Berlin)
Gesamt: 8,812,353 IPs in seen_db.json (8,067,731 aktiv/180-Tage-Pfad, 744,622 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 0 |
| 8-14 Tage | 839,591 |
| 15-30 Tage | 36,795 |
| 31-60 Tage | 2,536,725 |
| 61-90 Tage | 1,012,171 |
| 91-180 Tage | 3,642,449 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 0 |
| 0-3 Tage | 37,340 |
| 4-7 Tage | 262,968 |
| 8-14 Tage | 288,961 |
| 15-30 Tage | 155,353 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-08-24 | 8,117 |
| 2026-08-25 | 5,753 |
| 2026-08-26 | 8,600 |
| 2026-08-27 | 14,870 |
| 2026-08-28 | 184,604 |
| 2026-08-29 | 15,075 |
| 2026-08-30 | 10,139 |
| 2026-08-31 | 53,150 |
| 2026-09-01 | 9,398 |
| 2026-09-02 | 11,058 |
| 2026-09-03 | 148,311 |
| 2026-09-04 | 69,771 |
| 2026-09-05 | 20,656 |
| 2026-09-06 | 16,547 |
| 2026-09-07 | 13,220 |
| 2026-09-08 | 17,132 |
| 2026-09-09 | 8,962 |
| 2026-09-10 | 11,521 |
| 2026-09-11 | 12,087 |
| 2026-09-12 | 12,262 |
| 2026-09-13 | 13,148 |
| 2026-09-14 | 15,893 |
| 2026-09-15 | 6,369 |
| 2026-09-16 | 5,900 |
| 2026-09-17 | 8,974 |
| 2026-09-18 | 5,278 |
| 2026-09-19 | 5,169 |
| 2026-09-20 | 5,190 |
| 2026-09-21 | 11,454 |
| 2026-09-22 | 5,524 |
| 2026-09-23 | 10,490 |

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-04 | 173,763 |
| 2026-09-07 | 665,828 |
| 2026-09-21 | 6,533 |
| 2026-09-22 | 13,270 |
| 2026-09-23 | 16,992 |
| 2026-09-24 | 21,280 |
| 2026-09-25 | 17,769 |
| 2026-09-26 | 15,348 |
| 2026-09-27 | 11,727 |
| 2026-09-28 | 9,505 |
| 2026-09-29 | 10,387 |
| 2026-09-30 | 16,837 |
| 2026-10-01 | 7,885 |
| 2026-10-02 | 7,472 |
| 2026-10-03 | 12,911 |
| 2026-10-04 | 17,838 |
| 2026-10-05 | 16,396 |
| 2026-10-06 | 15,314 |
| 2026-10-07 | 62,770 |
| 2026-10-08 | 227,687 |
| 2026-10-09 | 53,612 |
| 2026-10-10 | 16,167 |
| 2026-10-11 | 66,800 |
| 2026-10-12 | 1,594,031 |
| 2026-10-13 | 33,002 |
| 2026-10-14 | 41,521 |
| 2026-10-15 | 51,626 |
| 2026-10-16 | 24,594 |
| 2026-10-17 | 14,488 |
| 2026-10-18 | 23,069 |
| 2026-10-19 | 11,302 |
| 2026-10-20 | 11,309 |
| 2026-10-21 | 31,147 |
| 2026-10-22 | 50,816 |
| 2026-10-23 | 42,115 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
