# Seen-DB Expiry Forecast

Lauf: 2026-09-01 20:21 CEST (Europe/Berlin)
Gesamt: 9,824,674 IPs in seen_db.json (8,440,262 aktiv/180-Tage-Pfad, 1,384,412 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 837,423 |
| 8-14 Tage | 0 |
| 15-30 Tage | 139,051 |
| 31-60 Tage | 2,670,414 |
| 61-90 Tage | 1,044,621 |
| 91-180 Tage | 3,748,753 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 176,906 |
| 0-3 Tage | 221,404 |
| 4-7 Tage | 119,502 |
| 8-14 Tage | 90,317 |
| 15-30 Tage | 776,283 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-01 | 52,949 |
| 2026-09-02 | 9,332 |
| 2026-09-03 | 10,975 |
| 2026-09-04 | 148,148 |
| 2026-09-05 | 69,485 |
| 2026-09-06 | 20,550 |
| 2026-09-07 | 16,347 |
| 2026-09-08 | 13,120 |
| 2026-09-09 | 17,060 |
| 2026-09-10 | 8,864 |
| 2026-09-11 | 11,429 |
| 2026-09-12 | 12,016 |
| 2026-09-13 | 12,164 |
| 2026-09-14 | 13,002 |
| 2026-09-15 | 15,782 |
| 2026-09-16 | 6,313 |
| 2026-09-17 | 5,863 |
| 2026-09-18 | 8,903 |
| 2026-09-19 | 5,221 |
| 2026-09-20 | 5,126 |
| 2026-09-21 | 5,119 |
| 2026-09-22 | 11,326 |
| 2026-09-23 | 5,228 |
| 2026-09-24 | 11,522 |
| 2026-09-25 | 5,593 |
| 2026-09-26 | 624,913 |
| 2026-09-27 | 6,469 |
| 2026-09-28 | 797 |
| 2026-09-30 | 60,306 |
| 2026-10-01 | 7,894 |

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-05 | 173,692 |
| 2026-09-08 | 663,731 |
| 2026-09-22 | 6,506 |
| 2026-09-23 | 13,216 |
| 2026-09-24 | 16,905 |
| 2026-09-25 | 21,197 |
| 2026-09-26 | 17,696 |
| 2026-09-27 | 15,271 |
| 2026-09-28 | 11,700 |
| 2026-09-29 | 9,458 |
| 2026-09-30 | 10,332 |
| 2026-10-01 | 16,770 |
| 2026-10-02 | 7,838 |
| 2026-10-03 | 7,429 |
| 2026-10-04 | 12,837 |
| 2026-10-05 | 17,755 |
| 2026-10-06 | 16,319 |
| 2026-10-07 | 15,250 |
| 2026-10-08 | 62,387 |
| 2026-10-09 | 226,820 |
| 2026-10-10 | 53,567 |
| 2026-10-11 | 16,135 |
| 2026-10-12 | 66,740 |
| 2026-10-13 | 1,592,691 |
| 2026-10-14 | 32,980 |
| 2026-10-15 | 41,482 |
| 2026-10-16 | 51,561 |
| 2026-10-17 | 24,530 |
| 2026-10-18 | 14,418 |
| 2026-10-19 | 22,880 |
| 2026-10-20 | 11,263 |
| 2026-10-21 | 11,247 |
| 2026-10-22 | 31,065 |
| 2026-10-23 | 50,707 |
| 2026-10-24 | 42,015 |
| 2026-10-25 | 21,881 |
| 2026-10-26 | 20,621 |
| 2026-10-27 | 20,968 |
| 2026-10-28 | 15,990 |
| 2026-10-29 | 9,861 |
| 2026-10-30 | 62,623 |
| 2026-10-31 | 88,554 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
