# Seen-DB Expiry Forecast

Lauf: 2026-09-21 03:31 CEST (Europe/Berlin)
Gesamt: 11,627,828 IPs in seen_db.json (8,663,491 aktiv/180-Tage-Pfad, 2,964,337 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 101,203 |
| 8-14 Tage | 81,385 |
| 15-30 Tage | 2,246,655 |
| 31-60 Tage | 1,006,142 |
| 61-90 Tage | 932,522 |
| 91-180 Tage | 4,295,584 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 577,813 |
| 0-3 Tage | 32,641 |
| 4-7 Tage | 636,365 |
| 8-14 Tage | 1,387,583 |
| 15-30 Tage | 329,935 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-21 | 5,005 |
| 2026-09-22 | 11,134 |
| 2026-09-23 | 5,113 |
| 2026-09-24 | 11,389 |
| 2026-09-25 | 5,463 |
| 2026-09-26 | 623,841 |
| 2026-09-27 | 6,287 |
| 2026-09-28 | 774 |
| 2026-09-30 | 59,699 |
| 2026-10-01 | 7,659 |
| 2026-10-02 | 1,307,419 |
| 2026-10-03 | 2,973 |
| 2026-10-04 | 6,927 |
| 2026-10-05 | 2,906 |
| 2026-10-06 | 8,281 |
| 2026-10-07 | 7,999 |
| 2026-10-08 | 7,321 |
| 2026-10-09 | 151,929 |
| 2026-10-10 | 8,210 |
| 2026-10-11 | 23,138 |
| 2026-10-12 | 33,295 |
| 2026-10-13 | 9,022 |
| 2026-10-14 | 8,089 |
| 2026-10-15 | 8,842 |
| 2026-10-16 | 16,241 |
| 2026-10-17 | 10,641 |
| 2026-10-18 | 9,390 |
| 2026-10-19 | 5,723 |
| 2026-10-20 | 10,431 |
| 2026-10-21 | 10,896 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **577,813** IPs. Brutto faellig in den naechsten 30 Tagen: **2,386,037**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,903,850**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-21 | 5,005 | 2,000 |
| 2026-09-22 | 11,134 | 2,000 |
| 2026-09-23 | 5,113 | 2,000 |
| 2026-09-24 | 11,389 | 2,000 |
| 2026-09-25 | 5,463 | 2,000 |
| 2026-09-26 | 623,841 | 2,000 |
| 2026-09-27 | 6,287 | 2,000 |
| 2026-09-28 | 774 | 2,000 |
| 2026-09-30 | 59,699 | 2,000 |
| 2026-10-01 | 7,659 | 2,000 |
| 2026-10-02 | 1,307,419 | 2,000 |
| 2026-10-03 | 2,973 | 2,000 |
| 2026-10-04 | 6,927 | 2,000 |
| 2026-10-05 | 2,906 | 2,000 |
| 2026-10-06 | 8,281 | 2,000 |
| 2026-10-07 | 7,999 | 2,000 |
| 2026-10-08 | 7,321 | 2,000 |
| 2026-10-09 | 151,929 | 2,000 |
| 2026-10-10 | 8,210 | 2,000 |
| 2026-10-11 | 23,138 | 2,000 |
| 2026-10-12 | 33,295 | 2,000 |
| 2026-10-13 | 9,022 | 2,000 |
| 2026-10-14 | 8,089 | 2,000 |
| 2026-10-15 | 8,842 | 2,000 |
| 2026-10-16 | 16,241 | 2,000 |
| 2026-10-17 | 10,641 | 2,000 |
| 2026-10-18 | 9,390 | 2,000 |
| 2026-10-19 | 5,723 | 2,000 |
| 2026-10-20 | 10,431 | 2,000 |
| 2026-10-21 | 10,896 | 2,000 |

> Hinweis: Der Rueckstau von 2,903,850 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,434 |
| 2026-09-23 | 13,059 |
| 2026-09-24 | 16,669 |
| 2026-09-25 | 20,935 |
| 2026-09-26 | 17,454 |
| 2026-09-27 | 15,041 |
| 2026-09-28 | 11,611 |
| 2026-09-29 | 9,360 |
| 2026-09-30 | 10,179 |
| 2026-10-01 | 16,607 |
| 2026-10-02 | 7,722 |
| 2026-10-03 | 7,336 |
| 2026-10-04 | 12,633 |
| 2026-10-05 | 17,548 |
| 2026-10-06 | 16,137 |
| 2026-10-07 | 15,073 |
| 2026-10-08 | 61,444 |
| 2026-10-09 | 223,206 |
| 2026-10-10 | 53,391 |
| 2026-10-11 | 16,061 |
| 2026-10-12 | 66,594 |
| 2026-10-13 | 1,585,838 |
| 2026-10-14 | 32,924 |
| 2026-10-15 | 41,354 |
| 2026-10-16 | 51,330 |
| 2026-10-17 | 24,331 |
| 2026-10-18 | 14,291 |
| 2026-10-19 | 22,394 |
| 2026-10-20 | 11,156 |
| 2026-10-21 | 11,131 |
| 2026-10-22 | 30,783 |
| 2026-10-23 | 50,457 |
| 2026-10-24 | 41,773 |
| 2026-10-25 | 21,654 |
| 2026-10-26 | 20,372 |
| 2026-10-27 | 20,743 |
| 2026-10-28 | 15,834 |
| 2026-10-29 | 9,707 |
| 2026-10-30 | 62,046 |
| 2026-10-31 | 88,280 |
| 2026-11-01 | 27,919 |
| 2026-11-02 | 28,883 |
| 2026-11-03 | 29,900 |
| 2026-11-04 | 29,718 |
| 2026-11-05 | 25,345 |
| 2026-11-06 | 36,759 |
| 2026-11-07 | 24,548 |
| 2026-11-08 | 26,194 |
| 2026-11-09 | 25,626 |
| 2026-11-10 | 32,823 |
| 2026-11-11 | 22,449 |
| 2026-11-12 | 20,558 |
| 2026-11-13 | 19,707 |
| 2026-11-14 | 23,040 |
| 2026-11-15 | 17,516 |
| 2026-11-16 | 18,030 |
| 2026-11-17 | 15,288 |
| 2026-11-18 | 19,562 |
| 2026-11-19 | 174,346 |
| 2026-11-20 | 26,282 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 194469 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
