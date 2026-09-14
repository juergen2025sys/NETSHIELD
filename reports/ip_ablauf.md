# Seen-DB Expiry Forecast

Lauf: 2026-09-15 01:03 CEST (Europe/Berlin)
Gesamt: 11,183,419 IPs in seen_db.json (8,275,307 aktiv/180-Tage-Pfad, 2,908,112 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 0 |
| 8-14 Tage | 101,546 |
| 15-30 Tage | 2,156,012 |
| 31-60 Tage | 890,259 |
| 61-90 Tage | 1,073,754 |
| 91-180 Tage | 4,053,736 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 522,084 |
| 0-3 Tage | 40,429 |
| 4-7 Tage | 24,028 |
| 8-14 Tage | 664,540 |
| 15-30 Tage | 1,657,031 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-14 | 12,839 |
| 2026-09-15 | 15,579 |
| 2026-09-16 | 6,243 |
| 2026-09-17 | 5,768 |
| 2026-09-18 | 8,788 |
| 2026-09-19 | 5,145 |
| 2026-09-20 | 5,058 |
| 2026-09-21 | 5,037 |
| 2026-09-22 | 11,179 |
| 2026-09-23 | 5,144 |
| 2026-09-24 | 11,424 |
| 2026-09-25 | 5,496 |
| 2026-09-26 | 624,190 |
| 2026-09-27 | 6,325 |
| 2026-09-28 | 782 |
| 2026-09-30 | 59,834 |
| 2026-10-01 | 7,699 |
| 2026-10-02 | 1,308,880 |
| 2026-10-03 | 2,987 |
| 2026-10-04 | 6,964 |
| 2026-10-05 | 2,924 |
| 2026-10-06 | 8,320 |
| 2026-10-07 | 8,059 |
| 2026-10-08 | 7,370 |
| 2026-10-09 | 152,376 |
| 2026-10-10 | 8,273 |
| 2026-10-11 | 23,345 |
| 2026-10-12 | 33,439 |
| 2026-10-13 | 9,160 |
| 2026-10-14 | 8,225 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **522,084** IPs. Brutto faellig in den naechsten 30 Tagen: **2,376,852**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,838,936**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-14 | 12,839 | 2,000 |
| 2026-09-15 | 15,579 | 2,000 |
| 2026-09-16 | 6,243 | 2,000 |
| 2026-09-17 | 5,768 | 2,000 |
| 2026-09-18 | 8,788 | 2,000 |
| 2026-09-19 | 5,145 | 2,000 |
| 2026-09-20 | 5,058 | 2,000 |
| 2026-09-21 | 5,037 | 2,000 |
| 2026-09-22 | 11,179 | 2,000 |
| 2026-09-23 | 5,144 | 2,000 |
| 2026-09-24 | 11,424 | 2,000 |
| 2026-09-25 | 5,496 | 2,000 |
| 2026-09-26 | 624,190 | 2,000 |
| 2026-09-27 | 6,325 | 2,000 |
| 2026-09-28 | 782 | 2,000 |
| 2026-09-30 | 59,834 | 2,000 |
| 2026-10-01 | 7,699 | 2,000 |
| 2026-10-02 | 1,308,880 | 2,000 |
| 2026-10-03 | 2,987 | 2,000 |
| 2026-10-04 | 6,964 | 2,000 |
| 2026-10-05 | 2,924 | 2,000 |
| 2026-10-06 | 8,320 | 2,000 |
| 2026-10-07 | 8,059 | 2,000 |
| 2026-10-08 | 7,370 | 2,000 |
| 2026-10-09 | 152,376 | 2,000 |
| 2026-10-10 | 8,273 | 2,000 |
| 2026-10-11 | 23,345 | 2,000 |
| 2026-10-12 | 33,439 | 2,000 |
| 2026-10-13 | 9,160 | 2,000 |
| 2026-10-14 | 8,225 | 2,000 |

> Hinweis: Der Rueckstau von 2,838,936 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,447 |
| 2026-09-23 | 13,098 |
| 2026-09-24 | 16,739 |
| 2026-09-25 | 21,009 |
| 2026-09-26 | 17,515 |
| 2026-09-27 | 15,107 |
| 2026-09-28 | 11,631 |
| 2026-09-29 | 9,392 |
| 2026-09-30 | 10,236 |
| 2026-10-01 | 16,652 |
| 2026-10-02 | 7,755 |
| 2026-10-03 | 7,365 |
| 2026-10-04 | 12,699 |
| 2026-10-05 | 17,621 |
| 2026-10-06 | 16,189 |
| 2026-10-07 | 15,123 |
| 2026-10-08 | 61,737 |
| 2026-10-09 | 224,264 |
| 2026-10-10 | 53,454 |
| 2026-10-11 | 16,083 |
| 2026-10-12 | 66,640 |
| 2026-10-13 | 1,587,862 |
| 2026-10-14 | 32,940 |
| 2026-10-15 | 41,415 |
| 2026-10-16 | 51,440 |
| 2026-10-17 | 24,405 |
| 2026-10-18 | 14,335 |
| 2026-10-19 | 22,532 |
| 2026-10-20 | 11,186 |
| 2026-10-21 | 11,161 |
| 2026-10-22 | 30,864 |
| 2026-10-23 | 50,539 |
| 2026-10-24 | 41,843 |
| 2026-10-25 | 21,706 |
| 2026-10-26 | 20,451 |
| 2026-10-27 | 20,806 |
| 2026-10-28 | 15,874 |
| 2026-10-29 | 9,763 |
| 2026-10-30 | 62,207 |
| 2026-10-31 | 88,344 |
| 2026-11-01 | 27,988 |
| 2026-11-02 | 28,972 |
| 2026-11-03 | 30,012 |
| 2026-11-04 | 29,804 |
| 2026-11-05 | 25,415 |
| 2026-11-06 | 36,844 |
| 2026-11-07 | 24,600 |
| 2026-11-08 | 26,270 |
| 2026-11-09 | 25,710 |
| 2026-11-10 | 32,907 |
| 2026-11-11 | 22,511 |
| 2026-11-12 | 20,601 |
| 2026-11-13 | 19,754 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 191213 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
