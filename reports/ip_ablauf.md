# Seen-DB Expiry Forecast

Lauf: 2026-08-30 17:18 CEST (Europe/Berlin)
Gesamt: 9,597,703 IPs in seen_db.json (8,386,710 aktiv/180-Tage-Pfad, 1,210,993 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 173,698 |
| 8-14 Tage | 664,077 |
| 15-30 Tage | 122,368 |
| 31-60 Tage | 2,599,349 |
| 61-90 Tage | 1,107,766 |
| 91-180 Tage | 3,719,452 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 0 |
| 0-3 Tage | 83,367 |
| 4-7 Tage | 254,654 |
| 8-14 Tage | 87,742 |
| 15-30 Tage | 785,230 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-08-30 | 10,056 |
| 2026-08-31 | 52,982 |
| 2026-09-01 | 9,347 |
| 2026-09-02 | 10,982 |
| 2026-09-03 | 148,177 |
| 2026-09-04 | 69,536 |
| 2026-09-05 | 20,563 |
| 2026-09-06 | 16,378 |
| 2026-09-07 | 13,127 |
| 2026-09-08 | 17,065 |
| 2026-09-09 | 8,886 |
| 2026-09-10 | 11,440 |
| 2026-09-11 | 12,030 |
| 2026-09-12 | 12,180 |
| 2026-09-13 | 13,014 |
| 2026-09-14 | 15,812 |
| 2026-09-15 | 6,321 |
| 2026-09-16 | 5,864 |
| 2026-09-17 | 8,903 |
| 2026-09-18 | 5,231 |
| 2026-09-19 | 5,126 |
| 2026-09-20 | 5,127 |
| 2026-09-21 | 11,340 |
| 2026-09-22 | 5,233 |
| 2026-09-23 | 11,537 |
| 2026-09-24 | 5,595 |
| 2026-09-25 | 624,955 |
| 2026-09-26 | 5,950 |
| 2026-09-27 | 11,501 |
| 2026-09-28 | 7,995 |
| 2026-09-29 | 48,740 |

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-04 | 173,698 |
| 2026-09-07 | 664,077 |
| 2026-09-21 | 6,508 |
| 2026-09-22 | 13,224 |
| 2026-09-23 | 16,911 |
| 2026-09-24 | 21,209 |
| 2026-09-25 | 17,706 |
| 2026-09-26 | 15,284 |
| 2026-09-27 | 11,709 |
| 2026-09-28 | 9,472 |
| 2026-09-29 | 10,345 |
| 2026-09-30 | 16,787 |
| 2026-10-01 | 7,844 |
| 2026-10-02 | 7,437 |
| 2026-10-03 | 12,847 |
| 2026-10-04 | 17,767 |
| 2026-10-05 | 16,343 |
| 2026-10-06 | 15,257 |
| 2026-10-07 | 62,434 |
| 2026-10-08 | 226,906 |
| 2026-10-09 | 53,572 |
| 2026-10-10 | 16,141 |
| 2026-10-11 | 66,749 |
| 2026-10-12 | 1,592,910 |
| 2026-10-13 | 32,987 |
| 2026-10-14 | 41,488 |
| 2026-10-15 | 51,570 |
| 2026-10-16 | 24,542 |
| 2026-10-17 | 14,425 |
| 2026-10-18 | 22,922 |
| 2026-10-19 | 11,266 |
| 2026-10-20 | 11,253 |
| 2026-10-21 | 31,080 |
| 2026-10-22 | 50,719 |
| 2026-10-23 | 42,045 |
| 2026-10-24 | 21,895 |
| 2026-10-25 | 20,641 |
| 2026-10-26 | 20,983 |
| 2026-10-27 | 16,001 |
| 2026-10-28 | 9,875 |
| 2026-10-29 | 62,663 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
