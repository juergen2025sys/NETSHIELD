# Seen-DB Expiry Forecast

Lauf: 2026-09-10 17:07 CEST (Europe/Berlin)
Gesamt: 10,867,293 IPs in seen_db.json (8,032,294 aktiv/180-Tage-Pfad, 2,834,999 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 0 |
| 8-14 Tage | 36,396 |
| 15-30 Tage | 519,653 |
| 31-60 Tage | 2,501,542 |
| 61-90 Tage | 1,069,215 |
| 91-180 Tage | 3,905,488 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 479,850 |
| 0-3 Tage | 44,072 |
| 4-7 Tage | 40,586 |
| 8-14 Tage | 51,973 |
| 15-30 Tage | 2,218,518 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-10 | 8,750 |
| 2026-09-11 | 11,322 |
| 2026-09-12 | 11,926 |
| 2026-09-13 | 12,074 |
| 2026-09-14 | 12,886 |
| 2026-09-15 | 15,641 |
| 2026-09-16 | 6,258 |
| 2026-09-17 | 5,801 |
| 2026-09-18 | 8,815 |
| 2026-09-19 | 5,165 |
| 2026-09-20 | 5,082 |
| 2026-09-21 | 5,068 |
| 2026-09-22 | 11,220 |
| 2026-09-23 | 5,175 |
| 2026-09-24 | 11,448 |
| 2026-09-25 | 5,522 |
| 2026-09-26 | 624,447 |
| 2026-09-27 | 6,357 |
| 2026-09-28 | 784 |
| 2026-09-30 | 59,973 |
| 2026-10-01 | 7,742 |
| 2026-10-02 | 1,309,856 |
| 2026-10-03 | 3,005 |
| 2026-10-04 | 7,004 |
| 2026-10-05 | 2,953 |
| 2026-10-06 | 8,370 |
| 2026-10-07 | 8,143 |
| 2026-10-08 | 7,415 |
| 2026-10-09 | 152,721 |
| 2026-10-10 | 8,747 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **479,850** IPs. Brutto faellig in den naechsten 30 Tagen: **2,349,670**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,769,520**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-10 | 8,750 | 2,000 |
| 2026-09-11 | 11,322 | 2,000 |
| 2026-09-12 | 11,926 | 2,000 |
| 2026-09-13 | 12,074 | 2,000 |
| 2026-09-14 | 12,886 | 2,000 |
| 2026-09-15 | 15,641 | 2,000 |
| 2026-09-16 | 6,258 | 2,000 |
| 2026-09-17 | 5,801 | 2,000 |
| 2026-09-18 | 8,815 | 2,000 |
| 2026-09-19 | 5,165 | 2,000 |
| 2026-09-20 | 5,082 | 2,000 |
| 2026-09-21 | 5,068 | 2,000 |
| 2026-09-22 | 11,220 | 2,000 |
| 2026-09-23 | 5,175 | 2,000 |
| 2026-09-24 | 11,448 | 2,000 |
| 2026-09-25 | 5,522 | 2,000 |
| 2026-09-26 | 624,447 | 2,000 |
| 2026-09-27 | 6,357 | 2,000 |
| 2026-09-28 | 784 | 2,000 |
| 2026-09-30 | 59,973 | 2,000 |
| 2026-10-01 | 7,742 | 2,000 |
| 2026-10-02 | 1,309,856 | 2,000 |
| 2026-10-03 | 3,005 | 2,000 |
| 2026-10-04 | 7,004 | 2,000 |
| 2026-10-05 | 2,953 | 2,000 |
| 2026-10-06 | 8,370 | 2,000 |
| 2026-10-07 | 8,143 | 2,000 |
| 2026-10-08 | 7,415 | 2,000 |
| 2026-10-09 | 152,721 | 2,000 |
| 2026-10-10 | 8,747 | 2,000 |

> Hinweis: Der Rueckstau von 2,769,520 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,466 |
| 2026-09-23 | 13,133 |
| 2026-09-24 | 16,797 |
| 2026-09-25 | 21,083 |
| 2026-09-26 | 17,585 |
| 2026-09-27 | 15,181 |
| 2026-09-28 | 11,651 |
| 2026-09-29 | 9,411 |
| 2026-09-30 | 10,271 |
| 2026-10-01 | 16,691 |
| 2026-10-02 | 7,784 |
| 2026-10-03 | 7,386 |
| 2026-10-04 | 12,745 |
| 2026-10-05 | 17,667 |
| 2026-10-06 | 16,240 |
| 2026-10-07 | 15,160 |
| 2026-10-08 | 61,936 |
| 2026-10-09 | 225,358 |
| 2026-10-10 | 53,504 |
| 2026-10-11 | 16,098 |
| 2026-10-12 | 66,678 |
| 2026-10-13 | 1,589,877 |
| 2026-10-14 | 32,953 |
| 2026-10-15 | 41,442 |
| 2026-10-16 | 51,482 |
| 2026-10-17 | 24,443 |
| 2026-10-18 | 14,367 |
| 2026-10-19 | 22,630 |
| 2026-10-20 | 11,209 |
| 2026-10-21 | 11,188 |
| 2026-10-22 | 30,934 |
| 2026-10-23 | 50,590 |
| 2026-10-24 | 41,894 |
| 2026-10-25 | 21,747 |
| 2026-10-26 | 20,498 |
| 2026-10-27 | 20,861 |
| 2026-10-28 | 15,924 |
| 2026-10-29 | 9,797 |
| 2026-10-30 | 62,337 |
| 2026-10-31 | 88,417 |
| 2026-11-01 | 28,038 |
| 2026-11-02 | 29,037 |
| 2026-11-03 | 30,098 |
| 2026-11-04 | 29,889 |
| 2026-11-05 | 25,470 |
| 2026-11-06 | 36,912 |
| 2026-11-07 | 24,641 |
| 2026-11-08 | 26,319 |
| 2026-11-09 | 25,772 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 143663 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
