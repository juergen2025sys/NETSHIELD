# Seen-DB Expiry Forecast

Lauf: 2026-08-26 03:49 CEST (Europe/Berlin)
Gesamt: 9,577,670 IPs in seen_db.json (8,220,778 aktiv/180-Tage-Pfad, 1,356,892 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 0 |
| 8-14 Tage | 839,209 |
| 15-30 Tage | 75,758 |
| 31-60 Tage | 2,539,415 |
| 61-90 Tage | 1,023,655 |
| 91-180 Tage | 3,742,741 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 0 |
| 0-3 Tage | 223,020 |
| 4-7 Tage | 83,644 |
| 8-14 Tage | 294,356 |
| 15-30 Tage | 755,872 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-08-26 | 8,587 |
| 2026-08-27 | 14,847 |
| 2026-08-28 | 184,525 |
| 2026-08-29 | 15,061 |
| 2026-08-30 | 10,115 |
| 2026-08-31 | 53,102 |
| 2026-09-01 | 9,382 |
| 2026-09-02 | 11,045 |
| 2026-09-03 | 148,274 |
| 2026-09-04 | 69,704 |
| 2026-09-05 | 20,636 |
| 2026-09-06 | 16,503 |
| 2026-09-07 | 13,193 |
| 2026-09-08 | 17,113 |
| 2026-09-09 | 8,933 |
| 2026-09-10 | 11,503 |
| 2026-09-11 | 12,077 |
| 2026-09-12 | 12,237 |
| 2026-09-13 | 13,103 |
| 2026-09-14 | 15,871 |
| 2026-09-15 | 6,354 |
| 2026-09-16 | 5,894 |
| 2026-09-17 | 8,955 |
| 2026-09-18 | 5,263 |
| 2026-09-19 | 5,161 |
| 2026-09-20 | 5,175 |
| 2026-09-21 | 11,401 |
| 2026-09-22 | 5,282 |
| 2026-09-23 | 11,683 |
| 2026-09-24 | 6,858 |
| 2026-09-25 | 619,055 |

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-04 | 173,749 |
| 2026-09-07 | 665,460 |
| 2026-09-21 | 6,528 |
| 2026-09-22 | 13,256 |
| 2026-09-23 | 16,965 |
| 2026-09-24 | 21,254 |
| 2026-09-25 | 17,755 |
| 2026-09-26 | 15,330 |
| 2026-09-27 | 11,725 |
| 2026-09-28 | 9,496 |
| 2026-09-29 | 10,376 |
| 2026-09-30 | 16,818 |
| 2026-10-01 | 7,868 |
| 2026-10-02 | 7,458 |
| 2026-10-03 | 12,894 |
| 2026-10-04 | 17,818 |
| 2026-10-05 | 16,380 |
| 2026-10-06 | 15,304 |
| 2026-10-07 | 62,705 |
| 2026-10-08 | 227,510 |
| 2026-10-09 | 53,603 |
| 2026-10-10 | 16,161 |
| 2026-10-11 | 66,786 |
| 2026-10-12 | 1,593,738 |
| 2026-10-13 | 32,996 |
| 2026-10-14 | 41,511 |
| 2026-10-15 | 51,607 |
| 2026-10-16 | 24,574 |
| 2026-10-17 | 14,471 |
| 2026-10-18 | 23,032 |
| 2026-10-19 | 11,290 |
| 2026-10-20 | 11,295 |
| 2026-10-21 | 31,127 |
| 2026-10-22 | 50,793 |
| 2026-10-23 | 42,098 |
| 2026-10-24 | 21,958 |
| 2026-10-25 | 20,693 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
