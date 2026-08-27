# Seen-DB Expiry Forecast

Lauf: 2026-08-27 13:07 CEST (Europe/Berlin)
Gesamt: 9,621,174 IPs in seen_db.json (8,262,753 aktiv/180-Tage-Pfad, 1,358,421 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 0 |
| 8-14 Tage | 838,890 |
| 15-30 Tage | 91,028 |
| 31-60 Tage | 2,544,360 |
| 61-90 Tage | 1,031,184 |
| 91-180 Tage | 3,757,291 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 0 |
| 0-3 Tage | 224,423 |
| 4-7 Tage | 221,714 |
| 8-14 Tage | 157,447 |
| 15-30 Tage | 754,837 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-08-27 | 14,835 |
| 2026-08-28 | 184,439 |
| 2026-08-29 | 15,045 |
| 2026-08-30 | 10,104 |
| 2026-08-31 | 53,049 |
| 2026-09-01 | 9,377 |
| 2026-09-02 | 11,034 |
| 2026-09-03 | 148,254 |
| 2026-09-04 | 69,671 |
| 2026-09-05 | 20,615 |
| 2026-09-06 | 16,477 |
| 2026-09-07 | 13,174 |
| 2026-09-08 | 17,102 |
| 2026-09-09 | 8,921 |
| 2026-09-10 | 11,487 |
| 2026-09-11 | 12,067 |
| 2026-09-12 | 12,222 |
| 2026-09-13 | 13,081 |
| 2026-09-14 | 15,859 |
| 2026-09-15 | 6,347 |
| 2026-09-16 | 5,886 |
| 2026-09-17 | 8,946 |
| 2026-09-18 | 5,255 |
| 2026-09-19 | 5,153 |
| 2026-09-20 | 5,158 |
| 2026-09-21 | 11,388 |
| 2026-09-22 | 5,268 |
| 2026-09-23 | 11,642 |
| 2026-09-24 | 5,731 |
| 2026-09-25 | 625,724 |
| 2026-09-26 | 5,110 |

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-04 | 173,735 |
| 2026-09-07 | 665,155 |
| 2026-09-21 | 6,526 |
| 2026-09-22 | 13,247 |
| 2026-09-23 | 16,953 |
| 2026-09-24 | 21,249 |
| 2026-09-25 | 17,739 |
| 2026-09-26 | 15,314 |
| 2026-09-27 | 11,722 |
| 2026-09-28 | 9,489 |
| 2026-09-29 | 10,367 |
| 2026-09-30 | 16,810 |
| 2026-10-01 | 7,863 |
| 2026-10-02 | 7,452 |
| 2026-10-03 | 12,879 |
| 2026-10-04 | 17,800 |
| 2026-10-05 | 16,371 |
| 2026-10-06 | 15,297 |
| 2026-10-07 | 62,644 |
| 2026-10-08 | 227,353 |
| 2026-10-09 | 53,594 |
| 2026-10-10 | 16,154 |
| 2026-10-11 | 66,777 |
| 2026-10-12 | 1,593,476 |
| 2026-10-13 | 32,992 |
| 2026-10-14 | 41,506 |
| 2026-10-15 | 51,599 |
| 2026-10-16 | 24,566 |
| 2026-10-17 | 14,454 |
| 2026-10-18 | 23,014 |
| 2026-10-19 | 11,287 |
| 2026-10-20 | 11,288 |
| 2026-10-21 | 31,115 |
| 2026-10-22 | 50,768 |
| 2026-10-23 | 42,083 |
| 2026-10-24 | 21,943 |
| 2026-10-25 | 20,679 |
| 2026-10-26 | 21,018 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
