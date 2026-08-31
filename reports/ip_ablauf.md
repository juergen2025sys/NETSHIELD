# Seen-DB Expiry Forecast

Lauf: 2026-08-31 16:19 CEST (Europe/Berlin)
Gesamt: 9,607,940 IPs in seen_db.json (8,406,365 aktiv/180-Tage-Pfad, 1,201,575 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 837,681 |
| 8-14 Tage | 0 |
| 15-30 Tage | 139,145 |
| 31-60 Tage | 2,671,120 |
| 61-90 Tage | 1,045,093 |
| 91-180 Tage | 3,713,326 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 0 |
| 0-3 Tage | 221,493 |
| 4-7 Tage | 119,625 |
| 8-14 Tage | 90,426 |
| 15-30 Tage | 770,031 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-08-31 | 52,975 |
| 2026-09-01 | 9,350 |
| 2026-09-02 | 10,986 |
| 2026-09-03 | 148,182 |
| 2026-09-04 | 69,540 |
| 2026-09-05 | 20,567 |
| 2026-09-06 | 16,382 |
| 2026-09-07 | 13,136 |
| 2026-09-08 | 17,070 |
| 2026-09-09 | 8,876 |
| 2026-09-10 | 11,445 |
| 2026-09-11 | 12,028 |
| 2026-09-12 | 12,181 |
| 2026-09-13 | 13,018 |
| 2026-09-14 | 15,808 |
| 2026-09-15 | 6,321 |
| 2026-09-16 | 5,867 |
| 2026-09-17 | 8,911 |
| 2026-09-18 | 5,228 |
| 2026-09-19 | 5,130 |
| 2026-09-20 | 5,127 |
| 2026-09-21 | 11,343 |
| 2026-09-22 | 5,234 |
| 2026-09-23 | 11,538 |
| 2026-09-24 | 5,608 |
| 2026-09-25 | 624,952 |
| 2026-09-26 | 6,494 |
| 2026-09-27 | 798 |
| 2026-09-29 | 60,458 |
| 2026-09-30 | 7,022 |

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-04 | 173,700 |
| 2026-09-07 | 663,981 |
| 2026-09-21 | 6,509 |
| 2026-09-22 | 13,226 |
| 2026-09-23 | 16,915 |
| 2026-09-24 | 21,212 |
| 2026-09-25 | 17,707 |
| 2026-09-26 | 15,281 |
| 2026-09-27 | 11,708 |
| 2026-09-28 | 9,463 |
| 2026-09-29 | 10,343 |
| 2026-09-30 | 16,781 |
| 2026-10-01 | 7,843 |
| 2026-10-02 | 7,435 |
| 2026-10-03 | 12,845 |
| 2026-10-04 | 17,763 |
| 2026-10-05 | 16,340 |
| 2026-10-06 | 15,258 |
| 2026-10-07 | 62,441 |
| 2026-10-08 | 226,929 |
| 2026-10-09 | 53,573 |
| 2026-10-10 | 16,142 |
| 2026-10-11 | 66,748 |
| 2026-10-12 | 1,592,872 |
| 2026-10-13 | 32,985 |
| 2026-10-14 | 41,489 |
| 2026-10-15 | 51,572 |
| 2026-10-16 | 24,541 |
| 2026-10-17 | 14,425 |
| 2026-10-18 | 22,927 |
| 2026-10-19 | 11,270 |
| 2026-10-20 | 11,256 |
| 2026-10-21 | 31,077 |
| 2026-10-22 | 50,724 |
| 2026-10-23 | 42,042 |
| 2026-10-24 | 21,898 |
| 2026-10-25 | 20,635 |
| 2026-10-26 | 20,978 |
| 2026-10-27 | 15,998 |
| 2026-10-28 | 9,871 |
| 2026-10-29 | 62,667 |
| 2026-10-30 | 88,576 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
