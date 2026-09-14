# Seen-DB Expiry Forecast

Lauf: 2026-09-14 21:50 CEST (Europe/Berlin)
Gesamt: 11,166,289 IPs in seen_db.json (8,258,844 aktiv/180-Tage-Pfad, 2,907,445 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 0 |
| 8-14 Tage | 101,562 |
| 15-30 Tage | 2,156,159 |
| 31-60 Tage | 890,318 |
| 61-90 Tage | 1,073,838 |
| 91-180 Tage | 4,036,967 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 522,167 |
| 0-3 Tage | 40,435 |
| 4-7 Tage | 24,032 |
| 8-14 Tage | 664,556 |
| 15-30 Tage | 1,656,255 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-14 | 12,841 |
| 2026-09-15 | 15,582 |
| 2026-09-16 | 6,243 |
| 2026-09-17 | 5,769 |
| 2026-09-18 | 8,790 |
| 2026-09-19 | 5,146 |
| 2026-09-20 | 5,058 |
| 2026-09-21 | 5,038 |
| 2026-09-22 | 11,182 |
| 2026-09-23 | 5,146 |
| 2026-09-24 | 11,427 |
| 2026-09-25 | 5,496 |
| 2026-09-26 | 624,197 |
| 2026-09-27 | 6,326 |
| 2026-09-28 | 782 |
| 2026-09-30 | 59,839 |
| 2026-10-01 | 7,701 |
| 2026-10-02 | 1,308,939 |
| 2026-10-03 | 2,988 |
| 2026-10-04 | 6,967 |
| 2026-10-05 | 2,925 |
| 2026-10-06 | 8,326 |
| 2026-10-07 | 8,061 |
| 2026-10-08 | 7,372 |
| 2026-10-09 | 152,388 |
| 2026-10-10 | 8,276 |
| 2026-10-11 | 23,350 |
| 2026-10-12 | 33,447 |
| 2026-10-13 | 9,170 |
| 2026-10-14 | 8,350 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **522,167** IPs. Brutto faellig in den naechsten 30 Tagen: **2,377,122**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,839,289**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-14 | 12,841 | 2,000 |
| 2026-09-15 | 15,582 | 2,000 |
| 2026-09-16 | 6,243 | 2,000 |
| 2026-09-17 | 5,769 | 2,000 |
| 2026-09-18 | 8,790 | 2,000 |
| 2026-09-19 | 5,146 | 2,000 |
| 2026-09-20 | 5,058 | 2,000 |
| 2026-09-21 | 5,038 | 2,000 |
| 2026-09-22 | 11,182 | 2,000 |
| 2026-09-23 | 5,146 | 2,000 |
| 2026-09-24 | 11,427 | 2,000 |
| 2026-09-25 | 5,496 | 2,000 |
| 2026-09-26 | 624,197 | 2,000 |
| 2026-09-27 | 6,326 | 2,000 |
| 2026-09-28 | 782 | 2,000 |
| 2026-09-30 | 59,839 | 2,000 |
| 2026-10-01 | 7,701 | 2,000 |
| 2026-10-02 | 1,308,939 | 2,000 |
| 2026-10-03 | 2,988 | 2,000 |
| 2026-10-04 | 6,967 | 2,000 |
| 2026-10-05 | 2,925 | 2,000 |
| 2026-10-06 | 8,326 | 2,000 |
| 2026-10-07 | 8,061 | 2,000 |
| 2026-10-08 | 7,372 | 2,000 |
| 2026-10-09 | 152,388 | 2,000 |
| 2026-10-10 | 8,276 | 2,000 |
| 2026-10-11 | 23,350 | 2,000 |
| 2026-10-12 | 33,447 | 2,000 |
| 2026-10-13 | 9,170 | 2,000 |
| 2026-10-14 | 8,350 | 2,000 |

> Hinweis: Der Rueckstau von 2,839,289 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,447 |
| 2026-09-23 | 13,099 |
| 2026-09-24 | 16,741 |
| 2026-09-25 | 21,010 |
| 2026-09-26 | 17,519 |
| 2026-09-27 | 15,114 |
| 2026-09-28 | 11,632 |
| 2026-09-29 | 9,392 |
| 2026-09-30 | 10,236 |
| 2026-10-01 | 16,653 |
| 2026-10-02 | 7,755 |
| 2026-10-03 | 7,366 |
| 2026-10-04 | 12,699 |
| 2026-10-05 | 17,621 |
| 2026-10-06 | 16,192 |
| 2026-10-07 | 15,127 |
| 2026-10-08 | 61,747 |
| 2026-10-09 | 224,289 |
| 2026-10-10 | 53,456 |
| 2026-10-11 | 16,083 |
| 2026-10-12 | 66,640 |
| 2026-10-13 | 1,587,962 |
| 2026-10-14 | 32,941 |
| 2026-10-15 | 41,415 |
| 2026-10-16 | 51,441 |
| 2026-10-17 | 24,407 |
| 2026-10-18 | 14,335 |
| 2026-10-19 | 22,537 |
| 2026-10-20 | 11,186 |
| 2026-10-21 | 11,162 |
| 2026-10-22 | 30,869 |
| 2026-10-23 | 50,541 |
| 2026-10-24 | 41,843 |
| 2026-10-25 | 21,707 |
| 2026-10-26 | 20,452 |
| 2026-10-27 | 20,808 |
| 2026-10-28 | 15,874 |
| 2026-10-29 | 9,763 |
| 2026-10-30 | 62,212 |
| 2026-10-31 | 88,348 |
| 2026-11-01 | 27,989 |
| 2026-11-02 | 28,977 |
| 2026-11-03 | 30,016 |
| 2026-11-04 | 29,808 |
| 2026-11-05 | 25,417 |
| 2026-11-06 | 36,847 |
| 2026-11-07 | 24,603 |
| 2026-11-08 | 26,270 |
| 2026-11-09 | 25,712 |
| 2026-11-10 | 32,909 |
| 2026-11-11 | 22,512 |
| 2026-11-12 | 20,602 |
| 2026-11-13 | 19,756 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 191218 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
