# Seen-DB Expiry Forecast

Lauf: 2026-09-07 06:17 CEST (Europe/Berlin)
Gesamt: 11,163,016 IPs in seen_db.json (8,500,303 aktiv/180-Tage-Pfad, 2,662,713 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 662,528 |
| 8-14 Tage | 0 |
| 15-30 Tage | 215,785 |
| 31-60 Tage | 2,769,334 |
| 61-90 Tage | 1,027,583 |
| 91-180 Tage | 3,825,073 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 432,509 |
| 0-3 Tage | 55,112 |
| 4-7 Tage | 48,376 |
| 8-14 Tage | 52,046 |
| 15-30 Tage | 2,074,670 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-07 | 16,227 |
| 2026-09-08 | 13,076 |
| 2026-09-09 | 17,011 |
| 2026-09-10 | 8,798 |
| 2026-09-11 | 11,372 |
| 2026-09-12 | 11,964 |
| 2026-09-13 | 12,106 |
| 2026-09-14 | 12,934 |
| 2026-09-15 | 15,700 |
| 2026-09-16 | 6,287 |
| 2026-09-17 | 5,828 |
| 2026-09-18 | 8,862 |
| 2026-09-19 | 5,187 |
| 2026-09-20 | 5,098 |
| 2026-09-21 | 5,084 |
| 2026-09-22 | 11,263 |
| 2026-09-23 | 5,195 |
| 2026-09-24 | 11,474 |
| 2026-09-25 | 5,550 |
| 2026-09-26 | 624,666 |
| 2026-09-27 | 6,391 |
| 2026-09-28 | 788 |
| 2026-09-30 | 60,075 |
| 2026-10-01 | 7,772 |
| 2026-10-02 | 1,310,839 |
| 2026-10-03 | 3,026 |
| 2026-10-04 | 7,042 |
| 2026-10-05 | 3,008 |
| 2026-10-06 | 8,530 |
| 2026-10-07 | 8,660 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **432,509** IPs. Brutto faellig in den naechsten 30 Tagen: **2,229,813**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,602,322**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-07 | 16,227 | 2,000 |
| 2026-09-08 | 13,076 | 2,000 |
| 2026-09-09 | 17,011 | 2,000 |
| 2026-09-10 | 8,798 | 2,000 |
| 2026-09-11 | 11,372 | 2,000 |
| 2026-09-12 | 11,964 | 2,000 |
| 2026-09-13 | 12,106 | 2,000 |
| 2026-09-14 | 12,934 | 2,000 |
| 2026-09-15 | 15,700 | 2,000 |
| 2026-09-16 | 6,287 | 2,000 |
| 2026-09-17 | 5,828 | 2,000 |
| 2026-09-18 | 8,862 | 2,000 |
| 2026-09-19 | 5,187 | 2,000 |
| 2026-09-20 | 5,098 | 2,000 |
| 2026-09-21 | 5,084 | 2,000 |
| 2026-09-22 | 11,263 | 2,000 |
| 2026-09-23 | 5,195 | 2,000 |
| 2026-09-24 | 11,474 | 2,000 |
| 2026-09-25 | 5,550 | 2,000 |
| 2026-09-26 | 624,666 | 2,000 |
| 2026-09-27 | 6,391 | 2,000 |
| 2026-09-28 | 788 | 2,000 |
| 2026-09-30 | 60,075 | 2,000 |
| 2026-10-01 | 7,772 | 2,000 |
| 2026-10-02 | 1,310,839 | 2,000 |
| 2026-10-03 | 3,026 | 2,000 |
| 2026-10-04 | 7,042 | 2,000 |
| 2026-10-05 | 3,008 | 2,000 |
| 2026-10-06 | 8,530 | 2,000 |
| 2026-10-07 | 8,660 | 2,000 |

> Hinweis: Der Rueckstau von 2,602,322 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-08 | 662,528 |
| 2026-09-22 | 6,479 |
| 2026-09-23 | 13,177 |
| 2026-09-24 | 16,859 |
| 2026-09-25 | 21,125 |
| 2026-09-26 | 17,641 |
| 2026-09-27 | 15,221 |
| 2026-09-28 | 11,678 |
| 2026-09-29 | 9,434 |
| 2026-09-30 | 10,295 |
| 2026-10-01 | 16,723 |
| 2026-10-02 | 7,806 |
| 2026-10-03 | 7,400 |
| 2026-10-04 | 12,782 |
| 2026-10-05 | 17,701 |
| 2026-10-06 | 16,267 |
| 2026-10-07 | 15,197 |
| 2026-10-08 | 62,119 |
| 2026-10-09 | 226,154 |
| 2026-10-10 | 53,528 |
| 2026-10-11 | 16,115 |
| 2026-10-12 | 66,706 |
| 2026-10-13 | 1,591,460 |
| 2026-10-14 | 32,963 |
| 2026-10-15 | 41,450 |
| 2026-10-16 | 51,516 |
| 2026-10-17 | 24,486 |
| 2026-10-18 | 14,394 |
| 2026-10-19 | 22,718 |
| 2026-10-20 | 11,233 |
| 2026-10-21 | 11,211 |
| 2026-10-22 | 30,995 |
| 2026-10-23 | 50,629 |
| 2026-10-24 | 41,939 |
| 2026-10-25 | 21,784 |
| 2026-10-26 | 20,544 |
| 2026-10-27 | 20,897 |
| 2026-10-28 | 15,949 |
| 2026-10-29 | 9,825 |
| 2026-10-30 | 62,447 |
| 2026-10-31 | 88,477 |
| 2026-11-01 | 28,082 |
| 2026-11-02 | 29,094 |
| 2026-11-03 | 30,167 |
| 2026-11-04 | 29,958 |
| 2026-11-05 | 25,518 |
| 2026-11-06 | 36,976 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 247 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
