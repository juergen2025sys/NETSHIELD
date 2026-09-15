# Seen-DB Expiry Forecast

Lauf: 2026-09-15 15:26 CEST (Europe/Berlin)
Gesamt: 11,251,284 IPs in seen_db.json (8,330,081 aktiv/180-Tage-Pfad, 2,921,203 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 6,444 |
| 8-14 Tage | 104,433 |
| 15-30 Tage | 2,187,342 |
| 31-60 Tage | 871,639 |
| 61-90 Tage | 1,073,914 |
| 91-180 Tage | 4,086,309 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 534,650 |
| 0-3 Tage | 36,348 |
| 4-7 Tage | 26,400 |
| 8-14 Tage | 653,288 |
| 15-30 Tage | 1,670,517 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-15 | 15,572 |
| 2026-09-16 | 6,236 |
| 2026-09-17 | 5,761 |
| 2026-09-18 | 8,779 |
| 2026-09-19 | 5,137 |
| 2026-09-20 | 5,056 |
| 2026-09-21 | 5,032 |
| 2026-09-22 | 11,175 |
| 2026-09-23 | 5,136 |
| 2026-09-24 | 11,420 |
| 2026-09-25 | 5,489 |
| 2026-09-26 | 624,143 |
| 2026-09-27 | 6,320 |
| 2026-09-28 | 780 |
| 2026-09-30 | 59,805 |
| 2026-10-01 | 7,691 |
| 2026-10-02 | 1,308,666 |
| 2026-10-03 | 2,985 |
| 2026-10-04 | 6,956 |
| 2026-10-05 | 2,920 |
| 2026-10-06 | 8,315 |
| 2026-10-07 | 8,053 |
| 2026-10-08 | 7,366 |
| 2026-10-09 | 152,318 |
| 2026-10-10 | 8,265 |
| 2026-10-11 | 23,313 |
| 2026-10-12 | 33,430 |
| 2026-10-13 | 9,138 |
| 2026-10-14 | 8,170 |
| 2026-10-15 | 9,319 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **534,650** IPs. Brutto faellig in den naechsten 30 Tagen: **2,372,746**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,847,396**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-15 | 15,572 | 2,000 |
| 2026-09-16 | 6,236 | 2,000 |
| 2026-09-17 | 5,761 | 2,000 |
| 2026-09-18 | 8,779 | 2,000 |
| 2026-09-19 | 5,137 | 2,000 |
| 2026-09-20 | 5,056 | 2,000 |
| 2026-09-21 | 5,032 | 2,000 |
| 2026-09-22 | 11,175 | 2,000 |
| 2026-09-23 | 5,136 | 2,000 |
| 2026-09-24 | 11,420 | 2,000 |
| 2026-09-25 | 5,489 | 2,000 |
| 2026-09-26 | 624,143 | 2,000 |
| 2026-09-27 | 6,320 | 2,000 |
| 2026-09-28 | 780 | 2,000 |
| 2026-09-30 | 59,805 | 2,000 |
| 2026-10-01 | 7,691 | 2,000 |
| 2026-10-02 | 1,308,666 | 2,000 |
| 2026-10-03 | 2,985 | 2,000 |
| 2026-10-04 | 6,956 | 2,000 |
| 2026-10-05 | 2,920 | 2,000 |
| 2026-10-06 | 8,315 | 2,000 |
| 2026-10-07 | 8,053 | 2,000 |
| 2026-10-08 | 7,366 | 2,000 |
| 2026-10-09 | 152,318 | 2,000 |
| 2026-10-10 | 8,265 | 2,000 |
| 2026-10-11 | 23,313 | 2,000 |
| 2026-10-12 | 33,430 | 2,000 |
| 2026-10-13 | 9,138 | 2,000 |
| 2026-10-14 | 8,170 | 2,000 |
| 2026-10-15 | 9,319 | 2,000 |

> Hinweis: Der Rueckstau von 2,847,396 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,444 |
| 2026-09-23 | 13,092 |
| 2026-09-24 | 16,727 |
| 2026-09-25 | 20,996 |
| 2026-09-26 | 17,507 |
| 2026-09-27 | 15,094 |
| 2026-09-28 | 11,628 |
| 2026-09-29 | 9,389 |
| 2026-09-30 | 10,227 |
| 2026-10-01 | 16,643 |
| 2026-10-02 | 7,754 |
| 2026-10-03 | 7,359 |
| 2026-10-04 | 12,682 |
| 2026-10-05 | 17,608 |
| 2026-10-06 | 16,177 |
| 2026-10-07 | 15,113 |
| 2026-10-08 | 61,683 |
| 2026-10-09 | 224,079 |
| 2026-10-10 | 53,448 |
| 2026-10-11 | 16,081 |
| 2026-10-12 | 66,635 |
| 2026-10-13 | 1,587,523 |
| 2026-10-14 | 32,938 |
| 2026-10-15 | 41,392 |
| 2026-10-16 | 51,426 |
| 2026-10-17 | 24,392 |
| 2026-10-18 | 14,328 |
| 2026-10-19 | 22,512 |
| 2026-10-20 | 11,183 |
| 2026-10-21 | 11,157 |
| 2026-10-22 | 30,857 |
| 2026-10-23 | 50,527 |
| 2026-10-24 | 41,831 |
| 2026-10-25 | 21,696 |
| 2026-10-26 | 20,438 |
| 2026-10-27 | 20,796 |
| 2026-10-28 | 15,870 |
| 2026-10-29 | 9,754 |
| 2026-10-30 | 62,186 |
| 2026-10-31 | 88,333 |
| 2026-11-01 | 27,974 |
| 2026-11-02 | 28,959 |
| 2026-11-03 | 30,005 |
| 2026-11-04 | 29,793 |
| 2026-11-05 | 25,402 |
| 2026-11-06 | 36,836 |
| 2026-11-07 | 24,590 |
| 2026-11-08 | 26,261 |
| 2026-11-09 | 25,701 |
| 2026-11-10 | 32,892 |
| 2026-11-11 | 22,502 |
| 2026-11-12 | 20,595 |
| 2026-11-13 | 19,747 |
| 2026-11-14 | 23,096 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 191725 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
