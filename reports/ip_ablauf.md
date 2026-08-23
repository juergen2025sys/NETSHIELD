# Seen-DB Expiry Forecast

Lauf: 2026-08-23 21:43 CEST (Europe/Berlin)
Gesamt: 9,411,701 IPs in seen_db.json (8,019,697 aktiv/180-Tage-Pfad, 1,392,004 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 0 |
| 8-14 Tage | 173,769 |
| 15-30 Tage | 685,769 |
| 31-60 Tage | 2,511,940 |
| 61-90 Tage | 1,028,392 |
| 91-180 Tage | 3,619,827 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 0 |
| 0-3 Tage | 679,867 |
| 4-7 Tage | 224,724 |
| 8-14 Tage | 328,962 |
| 15-30 Tage | 158,451 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-08-23 | 657,388 |
| 2026-08-24 | 8,120 |
| 2026-08-25 | 5,757 |
| 2026-08-26 | 8,602 |
| 2026-08-27 | 14,875 |
| 2026-08-28 | 184,629 |
| 2026-08-29 | 15,076 |
| 2026-08-30 | 10,144 |
| 2026-08-31 | 53,157 |
| 2026-09-01 | 9,404 |
| 2026-09-02 | 11,063 |
| 2026-09-03 | 148,325 |
| 2026-09-04 | 69,785 |
| 2026-09-05 | 20,669 |
| 2026-09-06 | 16,559 |
| 2026-09-07 | 13,229 |
| 2026-09-08 | 17,137 |
| 2026-09-09 | 8,969 |
| 2026-09-10 | 11,532 |
| 2026-09-11 | 12,088 |
| 2026-09-12 | 12,267 |
| 2026-09-13 | 13,159 |
| 2026-09-14 | 15,898 |
| 2026-09-15 | 6,372 |
| 2026-09-16 | 5,903 |
| 2026-09-17 | 8,977 |
| 2026-09-18 | 5,285 |
| 2026-09-19 | 5,178 |
| 2026-09-20 | 5,196 |
| 2026-09-21 | 11,573 |
| 2026-09-22 | 5,688 |

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-04 | 173,769 |
| 2026-09-07 | 665,961 |
| 2026-09-21 | 6,534 |
| 2026-09-22 | 13,274 |
| 2026-09-23 | 16,999 |
| 2026-09-24 | 21,286 |
| 2026-09-25 | 17,774 |
| 2026-09-26 | 15,354 |
| 2026-09-27 | 11,732 |
| 2026-09-28 | 9,508 |
| 2026-09-29 | 10,393 |
| 2026-09-30 | 16,838 |
| 2026-10-01 | 7,891 |
| 2026-10-02 | 7,475 |
| 2026-10-03 | 12,914 |
| 2026-10-04 | 17,844 |
| 2026-10-05 | 16,400 |
| 2026-10-06 | 15,317 |
| 2026-10-07 | 62,787 |
| 2026-10-08 | 227,766 |
| 2026-10-09 | 53,615 |
| 2026-10-10 | 16,167 |
| 2026-10-11 | 66,802 |
| 2026-10-12 | 1,594,156 |
| 2026-10-13 | 33,006 |
| 2026-10-14 | 41,526 |
| 2026-10-15 | 51,630 |
| 2026-10-16 | 24,596 |
| 2026-10-17 | 14,491 |
| 2026-10-18 | 23,076 |
| 2026-10-19 | 11,308 |
| 2026-10-20 | 11,312 |
| 2026-10-21 | 31,151 |
| 2026-10-22 | 50,826 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
