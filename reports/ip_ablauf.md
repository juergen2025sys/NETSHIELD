# Seen-DB Expiry Forecast

Lauf: 2026-08-30 07:09 CEST (Europe/Berlin)
Gesamt: 9,540,902 IPs in seen_db.json (8,370,831 aktiv/180-Tage-Pfad, 1,170,071 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 173,703 |
| 8-14 Tage | 664,435 |
| 15-30 Tage | 122,425 |
| 31-60 Tage | 2,599,825 |
| 61-90 Tage | 1,107,961 |
| 91-180 Tage | 3,702,482 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 0 |
| 0-3 Tage | 83,426 |
| 4-7 Tage | 254,744 |
| 8-14 Tage | 87,817 |
| 15-30 Tage | 744,084 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-08-30 | 10,070 |
| 2026-08-31 | 52,997 |
| 2026-09-01 | 9,359 |
| 2026-09-02 | 11,000 |
| 2026-09-03 | 148,201 |
| 2026-09-04 | 69,564 |
| 2026-09-05 | 20,577 |
| 2026-09-06 | 16,402 |
| 2026-09-07 | 13,137 |
| 2026-09-08 | 17,073 |
| 2026-09-09 | 8,894 |
| 2026-09-10 | 11,453 |
| 2026-09-11 | 12,037 |
| 2026-09-12 | 12,193 |
| 2026-09-13 | 13,030 |
| 2026-09-14 | 15,818 |
| 2026-09-15 | 6,330 |
| 2026-09-16 | 5,869 |
| 2026-09-17 | 8,912 |
| 2026-09-18 | 5,236 |
| 2026-09-19 | 5,133 |
| 2026-09-20 | 5,134 |
| 2026-09-21 | 11,349 |
| 2026-09-22 | 5,240 |
| 2026-09-23 | 11,545 |
| 2026-09-24 | 5,603 |
| 2026-09-25 | 624,987 |
| 2026-09-26 | 5,964 |
| 2026-09-27 | 11,542 |
| 2026-09-28 | 8,665 |
| 2026-09-29 | 6,757 |

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-04 | 173,703 |
| 2026-09-07 | 664,435 |
| 2026-09-21 | 6,513 |
| 2026-09-22 | 13,232 |
| 2026-09-23 | 16,924 |
| 2026-09-24 | 21,217 |
| 2026-09-25 | 17,713 |
| 2026-09-26 | 15,290 |
| 2026-09-27 | 11,711 |
| 2026-09-28 | 9,476 |
| 2026-09-29 | 10,349 |
| 2026-09-30 | 16,794 |
| 2026-10-01 | 7,847 |
| 2026-10-02 | 7,444 |
| 2026-10-03 | 12,856 |
| 2026-10-04 | 17,779 |
| 2026-10-05 | 16,355 |
| 2026-10-06 | 15,267 |
| 2026-10-07 | 62,512 |
| 2026-10-08 | 227,015 |
| 2026-10-09 | 53,580 |
| 2026-10-10 | 16,143 |
| 2026-10-11 | 66,750 |
| 2026-10-12 | 1,592,991 |
| 2026-10-13 | 32,991 |
| 2026-10-14 | 41,494 |
| 2026-10-15 | 51,580 |
| 2026-10-16 | 24,548 |
| 2026-10-17 | 14,431 |
| 2026-10-18 | 22,953 |
| 2026-10-19 | 11,272 |
| 2026-10-20 | 11,259 |
| 2026-10-21 | 31,088 |
| 2026-10-22 | 50,726 |
| 2026-10-23 | 42,047 |
| 2026-10-24 | 21,904 |
| 2026-10-25 | 20,646 |
| 2026-10-26 | 20,989 |
| 2026-10-27 | 16,008 |
| 2026-10-28 | 9,879 |
| 2026-10-29 | 62,677 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
