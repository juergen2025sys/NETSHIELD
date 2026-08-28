# Seen-DB Expiry Forecast

Lauf: 2026-08-28 20:45 CEST (Europe/Berlin)
Gesamt: 9,688,982 IPs in seen_db.json (8,334,162 aktiv/180-Tage-Pfad, 1,354,820 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 173,714 |
| 8-14 Tage | 664,713 |
| 15-30 Tage | 102,654 |
| 31-60 Tage | 2,547,658 |
| 61-90 Tage | 1,042,746 |
| 91-180 Tage | 3,802,677 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 0 |
| 0-3 Tage | 262,440 |
| 4-7 Tage | 238,204 |
| 8-14 Tage | 99,670 |
| 15-30 Tage | 754,506 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-08-28 | 184,319 |
| 2026-08-29 | 15,032 |
| 2026-08-30 | 10,077 |
| 2026-08-31 | 53,012 |
| 2026-09-01 | 9,365 |
| 2026-09-02 | 11,012 |
| 2026-09-03 | 148,226 |
| 2026-09-04 | 69,601 |
| 2026-09-05 | 20,591 |
| 2026-09-06 | 16,431 |
| 2026-09-07 | 13,152 |
| 2026-09-08 | 17,083 |
| 2026-09-09 | 8,903 |
| 2026-09-10 | 11,464 |
| 2026-09-11 | 12,046 |
| 2026-09-12 | 12,203 |
| 2026-09-13 | 13,050 |
| 2026-09-14 | 15,828 |
| 2026-09-15 | 6,335 |
| 2026-09-16 | 5,875 |
| 2026-09-17 | 8,927 |
| 2026-09-18 | 5,245 |
| 2026-09-19 | 5,143 |
| 2026-09-20 | 5,143 |
| 2026-09-21 | 11,360 |
| 2026-09-22 | 5,248 |
| 2026-09-23 | 11,560 |
| 2026-09-24 | 5,620 |
| 2026-09-25 | 625,049 |
| 2026-09-26 | 6,040 |
| 2026-09-27 | 11,880 |

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-04 | 173,714 |
| 2026-09-07 | 664,713 |
| 2026-09-21 | 6,517 |
| 2026-09-22 | 13,239 |
| 2026-09-23 | 16,933 |
| 2026-09-24 | 21,231 |
| 2026-09-25 | 17,725 |
| 2026-09-26 | 15,297 |
| 2026-09-27 | 11,712 |
| 2026-09-28 | 9,480 |
| 2026-09-29 | 10,355 |
| 2026-09-30 | 16,801 |
| 2026-10-01 | 7,854 |
| 2026-10-02 | 7,445 |
| 2026-10-03 | 12,866 |
| 2026-10-04 | 17,785 |
| 2026-10-05 | 16,358 |
| 2026-10-06 | 15,278 |
| 2026-10-07 | 62,550 |
| 2026-10-08 | 227,125 |
| 2026-10-09 | 53,586 |
| 2026-10-10 | 16,145 |
| 2026-10-11 | 66,758 |
| 2026-10-12 | 1,593,178 |
| 2026-10-13 | 32,991 |
| 2026-10-14 | 41,497 |
| 2026-10-15 | 51,586 |
| 2026-10-16 | 24,557 |
| 2026-10-17 | 14,441 |
| 2026-10-18 | 22,976 |
| 2026-10-19 | 11,277 |
| 2026-10-20 | 11,271 |
| 2026-10-21 | 31,099 |
| 2026-10-22 | 50,740 |
| 2026-10-23 | 42,058 |
| 2026-10-24 | 21,926 |
| 2026-10-25 | 20,659 |
| 2026-10-26 | 21,000 |
| 2026-10-27 | 16,016 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
