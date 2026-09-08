# Seen-DB Expiry Forecast

Lauf: 2026-09-08 13:42 CEST (Europe/Berlin)
Gesamt: 10,746,548 IPs in seen_db.json (7,929,646 aktiv/180-Tage-Pfad, 2,816,902 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 0 |
| 8-14 Tage | 6,472 |
| 15-30 Tage | 271,206 |
| 31-60 Tage | 2,730,751 |
| 61-90 Tage | 1,026,371 |
| 91-180 Tage | 3,894,846 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 450,689 |
| 0-3 Tage | 50,216 |
| 4-7 Tage | 52,635 |
| 8-14 Tage | 47,556 |
| 15-30 Tage | 2,215,806 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-08 | 13,062 |
| 2026-09-09 | 17,007 |
| 2026-09-10 | 8,783 |
| 2026-09-11 | 11,364 |
| 2026-09-12 | 11,945 |
| 2026-09-13 | 12,095 |
| 2026-09-14 | 12,921 |
| 2026-09-15 | 15,674 |
| 2026-09-16 | 6,277 |
| 2026-09-17 | 5,824 |
| 2026-09-18 | 8,851 |
| 2026-09-19 | 5,181 |
| 2026-09-20 | 5,094 |
| 2026-09-21 | 5,079 |
| 2026-09-22 | 11,250 |
| 2026-09-23 | 5,191 |
| 2026-09-24 | 11,466 |
| 2026-09-25 | 5,539 |
| 2026-09-26 | 624,588 |
| 2026-09-27 | 6,378 |
| 2026-09-28 | 787 |
| 2026-09-30 | 60,042 |
| 2026-10-01 | 7,761 |
| 2026-10-02 | 1,310,559 |
| 2026-10-03 | 3,019 |
| 2026-10-04 | 7,022 |
| 2026-10-05 | 2,987 |
| 2026-10-06 | 8,489 |
| 2026-10-07 | 8,221 |
| 2026-10-08 | 7,843 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **450,689** IPs. Brutto faellig in den naechsten 30 Tagen: **2,220,299**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,610,988**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-08 | 13,062 | 2,000 |
| 2026-09-09 | 17,007 | 2,000 |
| 2026-09-10 | 8,783 | 2,000 |
| 2026-09-11 | 11,364 | 2,000 |
| 2026-09-12 | 11,945 | 2,000 |
| 2026-09-13 | 12,095 | 2,000 |
| 2026-09-14 | 12,921 | 2,000 |
| 2026-09-15 | 15,674 | 2,000 |
| 2026-09-16 | 6,277 | 2,000 |
| 2026-09-17 | 5,824 | 2,000 |
| 2026-09-18 | 8,851 | 2,000 |
| 2026-09-19 | 5,181 | 2,000 |
| 2026-09-20 | 5,094 | 2,000 |
| 2026-09-21 | 5,079 | 2,000 |
| 2026-09-22 | 11,250 | 2,000 |
| 2026-09-23 | 5,191 | 2,000 |
| 2026-09-24 | 11,466 | 2,000 |
| 2026-09-25 | 5,539 | 2,000 |
| 2026-09-26 | 624,588 | 2,000 |
| 2026-09-27 | 6,378 | 2,000 |
| 2026-09-28 | 787 | 2,000 |
| 2026-09-30 | 60,042 | 2,000 |
| 2026-10-01 | 7,761 | 2,000 |
| 2026-10-02 | 1,310,559 | 2,000 |
| 2026-10-03 | 3,019 | 2,000 |
| 2026-10-04 | 7,022 | 2,000 |
| 2026-10-05 | 2,987 | 2,000 |
| 2026-10-06 | 8,489 | 2,000 |
| 2026-10-07 | 8,221 | 2,000 |
| 2026-10-08 | 7,843 | 2,000 |

> Hinweis: Der Rueckstau von 2,610,988 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,472 |
| 2026-09-23 | 13,167 |
| 2026-09-24 | 16,839 |
| 2026-09-25 | 21,113 |
| 2026-09-26 | 17,617 |
| 2026-09-27 | 15,211 |
| 2026-09-28 | 11,673 |
| 2026-09-29 | 9,427 |
| 2026-09-30 | 10,286 |
| 2026-10-01 | 16,713 |
| 2026-10-02 | 7,801 |
| 2026-10-03 | 7,393 |
| 2026-10-04 | 12,775 |
| 2026-10-05 | 17,689 |
| 2026-10-06 | 16,262 |
| 2026-10-07 | 15,179 |
| 2026-10-08 | 62,061 |
| 2026-10-09 | 225,942 |
| 2026-10-10 | 53,519 |
| 2026-10-11 | 16,112 |
| 2026-10-12 | 66,698 |
| 2026-10-13 | 1,590,957 |
| 2026-10-14 | 32,962 |
| 2026-10-15 | 41,445 |
| 2026-10-16 | 51,503 |
| 2026-10-17 | 24,468 |
| 2026-10-18 | 14,385 |
| 2026-10-19 | 22,679 |
| 2026-10-20 | 11,219 |
| 2026-10-21 | 11,202 |
| 2026-10-22 | 30,971 |
| 2026-10-23 | 50,615 |
| 2026-10-24 | 41,918 |
| 2026-10-25 | 21,768 |
| 2026-10-26 | 20,530 |
| 2026-10-27 | 20,887 |
| 2026-10-28 | 15,944 |
| 2026-10-29 | 9,817 |
| 2026-10-30 | 62,409 |
| 2026-10-31 | 88,453 |
| 2026-11-01 | 28,063 |
| 2026-11-02 | 29,073 |
| 2026-11-03 | 30,143 |
| 2026-11-04 | 29,932 |
| 2026-11-05 | 25,499 |
| 2026-11-06 | 36,957 |
| 2026-11-07 | 24,681 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 142334 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
