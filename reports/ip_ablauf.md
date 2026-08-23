# Seen-DB Expiry Forecast

Lauf: 2026-08-23 13:25 CEST (Europe/Berlin)
Gesamt: 9,396,039 IPs in seen_db.json (8,004,616 aktiv/180-Tage-Pfad, 1,391,423 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 0 |
| 8-14 Tage | 173,773 |
| 15-30 Tage | 685,875 |
| 31-60 Tage | 2,512,221 |
| 61-90 Tage | 1,028,563 |
| 91-180 Tage | 3,604,184 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 0 |
| 0-3 Tage | 679,888 |
| 4-7 Tage | 224,774 |
| 8-14 Tage | 329,035 |
| 15-30 Tage | 157,726 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-08-23 | 657,401 |
| 2026-08-24 | 8,123 |
| 2026-08-25 | 5,758 |
| 2026-08-26 | 8,606 |
| 2026-08-27 | 14,881 |
| 2026-08-28 | 184,660 |
| 2026-08-29 | 15,081 |
| 2026-08-30 | 10,152 |
| 2026-08-31 | 53,166 |
| 2026-09-01 | 9,409 |
| 2026-09-02 | 11,073 |
| 2026-09-03 | 148,338 |
| 2026-09-04 | 69,804 |
| 2026-09-05 | 20,672 |
| 2026-09-06 | 16,573 |
| 2026-09-07 | 13,234 |
| 2026-09-08 | 17,147 |
| 2026-09-09 | 8,978 |
| 2026-09-10 | 11,535 |
| 2026-09-11 | 12,094 |
| 2026-09-12 | 12,277 |
| 2026-09-13 | 13,169 |
| 2026-09-14 | 15,904 |
| 2026-09-15 | 6,375 |
| 2026-09-16 | 5,907 |
| 2026-09-17 | 8,981 |
| 2026-09-18 | 5,287 |
| 2026-09-19 | 5,180 |
| 2026-09-20 | 5,203 |
| 2026-09-21 | 11,948 |
| 2026-09-22 | 4,507 |

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-04 | 173,773 |
| 2026-09-07 | 666,062 |
| 2026-09-21 | 6,538 |
| 2026-09-22 | 13,275 |
| 2026-09-23 | 17,006 |
| 2026-09-24 | 21,291 |
| 2026-09-25 | 17,778 |
| 2026-09-26 | 15,358 |
| 2026-09-27 | 11,733 |
| 2026-09-28 | 9,509 |
| 2026-09-29 | 10,395 |
| 2026-09-30 | 16,845 |
| 2026-10-01 | 7,894 |
| 2026-10-02 | 7,479 |
| 2026-10-03 | 12,921 |
| 2026-10-04 | 17,847 |
| 2026-10-05 | 16,403 |
| 2026-10-06 | 15,322 |
| 2026-10-07 | 62,812 |
| 2026-10-08 | 227,830 |
| 2026-10-09 | 53,620 |
| 2026-10-10 | 16,169 |
| 2026-10-11 | 66,805 |
| 2026-10-12 | 1,594,249 |
| 2026-10-13 | 33,007 |
| 2026-10-14 | 41,527 |
| 2026-10-15 | 51,634 |
| 2026-10-16 | 24,602 |
| 2026-10-17 | 14,492 |
| 2026-10-18 | 23,086 |
| 2026-10-19 | 11,312 |
| 2026-10-20 | 11,313 |
| 2026-10-21 | 31,154 |
| 2026-10-22 | 50,828 |
