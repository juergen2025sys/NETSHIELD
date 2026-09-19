# Seen-DB Expiry Forecast

Lauf: 2026-09-19 06:57 CEST (Europe/Berlin)
Gesamt: 11,508,382 IPs in seen_db.json (8,555,054 aktiv/180-Tage-Pfad, 2,953,328 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 74,613 |
| 8-14 Tage | 77,926 |
| 15-30 Tage | 2,255,783 |
| 31-60 Tage | 828,382 |
| 61-90 Tage | 1,093,400 |
| 91-180 Tage | 4,224,950 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 570,099 |
| 0-3 Tage | 26,333 |
| 4-7 Tage | 645,954 |
| 8-14 Tage | 1,385,233 |
| 15-30 Tage | 325,709 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-19 | 5,126 |
| 2026-09-20 | 5,038 |
| 2026-09-21 | 5,017 |
| 2026-09-22 | 11,152 |
| 2026-09-23 | 5,120 |
| 2026-09-24 | 11,407 |
| 2026-09-25 | 5,474 |
| 2026-09-26 | 623,953 |
| 2026-09-27 | 6,295 |
| 2026-09-28 | 777 |
| 2026-09-30 | 59,732 |
| 2026-10-01 | 7,673 |
| 2026-10-02 | 1,307,782 |
| 2026-10-03 | 2,974 |
| 2026-10-04 | 6,931 |
| 2026-10-05 | 2,913 |
| 2026-10-06 | 8,297 |
| 2026-10-07 | 8,016 |
| 2026-10-08 | 7,340 |
| 2026-10-09 | 152,031 |
| 2026-10-10 | 8,225 |
| 2026-10-11 | 23,196 |
| 2026-10-12 | 33,332 |
| 2026-10-13 | 9,058 |
| 2026-10-14 | 8,114 |
| 2026-10-15 | 8,893 |
| 2026-10-16 | 16,292 |
| 2026-10-17 | 10,668 |
| 2026-10-18 | 9,443 |
| 2026-10-19 | 6,166 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **570,099** IPs. Brutto faellig in den naechsten 30 Tagen: **2,376,435**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,886,534**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-19 | 5,126 | 2,000 |
| 2026-09-20 | 5,038 | 2,000 |
| 2026-09-21 | 5,017 | 2,000 |
| 2026-09-22 | 11,152 | 2,000 |
| 2026-09-23 | 5,120 | 2,000 |
| 2026-09-24 | 11,407 | 2,000 |
| 2026-09-25 | 5,474 | 2,000 |
| 2026-09-26 | 623,953 | 2,000 |
| 2026-09-27 | 6,295 | 2,000 |
| 2026-09-28 | 777 | 2,000 |
| 2026-09-30 | 59,732 | 2,000 |
| 2026-10-01 | 7,673 | 2,000 |
| 2026-10-02 | 1,307,782 | 2,000 |
| 2026-10-03 | 2,974 | 2,000 |
| 2026-10-04 | 6,931 | 2,000 |
| 2026-10-05 | 2,913 | 2,000 |
| 2026-10-06 | 8,297 | 2,000 |
| 2026-10-07 | 8,016 | 2,000 |
| 2026-10-08 | 7,340 | 2,000 |
| 2026-10-09 | 152,031 | 2,000 |
| 2026-10-10 | 8,225 | 2,000 |
| 2026-10-11 | 23,196 | 2,000 |
| 2026-10-12 | 33,332 | 2,000 |
| 2026-10-13 | 9,058 | 2,000 |
| 2026-10-14 | 8,114 | 2,000 |
| 2026-10-15 | 8,893 | 2,000 |
| 2026-10-16 | 16,292 | 2,000 |
| 2026-10-17 | 10,668 | 2,000 |
| 2026-10-18 | 9,443 | 2,000 |
| 2026-10-19 | 6,166 | 2,000 |

> Hinweis: Der Rueckstau von 2,886,534 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,436 |
| 2026-09-23 | 13,066 |
| 2026-09-24 | 16,686 |
| 2026-09-25 | 20,953 |
| 2026-09-26 | 17,472 |
| 2026-09-27 | 15,056 |
| 2026-09-28 | 11,620 |
| 2026-09-29 | 9,368 |
| 2026-09-30 | 10,193 |
| 2026-10-01 | 16,617 |
| 2026-10-02 | 7,731 |
| 2026-10-03 | 7,341 |
| 2026-10-04 | 12,643 |
| 2026-10-05 | 17,564 |
| 2026-10-06 | 16,151 |
| 2026-10-07 | 15,090 |
| 2026-10-08 | 61,502 |
| 2026-10-09 | 223,567 |
| 2026-10-10 | 53,414 |
| 2026-10-11 | 16,068 |
| 2026-10-12 | 66,605 |
| 2026-10-13 | 1,586,416 |
| 2026-10-14 | 32,927 |
| 2026-10-15 | 41,366 |
| 2026-10-16 | 51,388 |
| 2026-10-17 | 24,350 |
| 2026-10-18 | 14,302 |
| 2026-10-19 | 22,430 |
| 2026-10-20 | 11,164 |
| 2026-10-21 | 11,140 |
| 2026-10-22 | 30,811 |
| 2026-10-23 | 50,479 |
| 2026-10-24 | 41,794 |
| 2026-10-25 | 21,673 |
| 2026-10-26 | 20,398 |
| 2026-10-27 | 20,759 |
| 2026-10-28 | 15,841 |
| 2026-10-29 | 9,721 |
| 2026-10-30 | 62,095 |
| 2026-10-31 | 88,292 |
| 2026-11-01 | 27,937 |
| 2026-11-02 | 28,909 |
| 2026-11-03 | 29,939 |
| 2026-11-04 | 29,751 |
| 2026-11-05 | 25,367 |
| 2026-11-06 | 36,786 |
| 2026-11-07 | 24,556 |
| 2026-11-08 | 26,216 |
| 2026-11-09 | 25,649 |
| 2026-11-10 | 32,843 |
| 2026-11-11 | 22,467 |
| 2026-11-12 | 20,574 |
| 2026-11-13 | 19,722 |
| 2026-11-14 | 23,054 |
| 2026-11-15 | 17,523 |
| 2026-11-16 | 18,046 |
| 2026-11-17 | 15,297 |
| 2026-11-18 | 19,579 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 193590 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
