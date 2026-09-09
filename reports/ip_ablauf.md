# Seen-DB Expiry Forecast

Lauf: 2026-09-09 21:40 CEST (Europe/Berlin)
Gesamt: 10,835,343 IPs in seen_db.json (8,004,989 aktiv/180-Tage-Pfad, 2,830,354 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 0 |
| 8-14 Tage | 19,614 |
| 15-30 Tage | 483,351 |
| 31-60 Tage | 2,529,924 |
| 61-90 Tage | 1,039,141 |
| 91-180 Tage | 3,932,959 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 463,480 |
| 0-3 Tage | 48,931 |
| 4-7 Tage | 46,887 |
| 8-14 Tage | 46,354 |
| 15-30 Tage | 2,224,702 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-09 | 16,910 |
| 2026-09-10 | 8,757 |
| 2026-09-11 | 11,334 |
| 2026-09-12 | 11,930 |
| 2026-09-13 | 12,077 |
| 2026-09-14 | 12,894 |
| 2026-09-15 | 15,651 |
| 2026-09-16 | 6,265 |
| 2026-09-17 | 5,804 |
| 2026-09-18 | 8,822 |
| 2026-09-19 | 5,169 |
| 2026-09-20 | 5,086 |
| 2026-09-21 | 5,069 |
| 2026-09-22 | 11,223 |
| 2026-09-23 | 5,181 |
| 2026-09-24 | 11,451 |
| 2026-09-25 | 5,524 |
| 2026-09-26 | 624,492 |
| 2026-09-27 | 6,359 |
| 2026-09-28 | 784 |
| 2026-09-30 | 59,992 |
| 2026-10-01 | 7,748 |
| 2026-10-02 | 1,310,038 |
| 2026-10-03 | 3,009 |
| 2026-10-04 | 7,007 |
| 2026-10-05 | 2,959 |
| 2026-10-06 | 8,376 |
| 2026-10-07 | 8,156 |
| 2026-10-08 | 7,429 |
| 2026-10-09 | 152,820 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **463,480** IPs. Brutto faellig in den naechsten 30 Tagen: **2,358,316**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,761,796**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-09 | 16,910 | 2,000 |
| 2026-09-10 | 8,757 | 2,000 |
| 2026-09-11 | 11,334 | 2,000 |
| 2026-09-12 | 11,930 | 2,000 |
| 2026-09-13 | 12,077 | 2,000 |
| 2026-09-14 | 12,894 | 2,000 |
| 2026-09-15 | 15,651 | 2,000 |
| 2026-09-16 | 6,265 | 2,000 |
| 2026-09-17 | 5,804 | 2,000 |
| 2026-09-18 | 8,822 | 2,000 |
| 2026-09-19 | 5,169 | 2,000 |
| 2026-09-20 | 5,086 | 2,000 |
| 2026-09-21 | 5,069 | 2,000 |
| 2026-09-22 | 11,223 | 2,000 |
| 2026-09-23 | 5,181 | 2,000 |
| 2026-09-24 | 11,451 | 2,000 |
| 2026-09-25 | 5,524 | 2,000 |
| 2026-09-26 | 624,492 | 2,000 |
| 2026-09-27 | 6,359 | 2,000 |
| 2026-09-28 | 784 | 2,000 |
| 2026-09-30 | 59,992 | 2,000 |
| 2026-10-01 | 7,748 | 2,000 |
| 2026-10-02 | 1,310,038 | 2,000 |
| 2026-10-03 | 3,009 | 2,000 |
| 2026-10-04 | 7,007 | 2,000 |
| 2026-10-05 | 2,959 | 2,000 |
| 2026-10-06 | 8,376 | 2,000 |
| 2026-10-07 | 8,156 | 2,000 |
| 2026-10-08 | 7,429 | 2,000 |
| 2026-10-09 | 152,820 | 2,000 |

> Hinweis: Der Rueckstau von 2,761,796 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,469 |
| 2026-09-23 | 13,145 |
| 2026-09-24 | 16,816 |
| 2026-09-25 | 21,096 |
| 2026-09-26 | 17,593 |
| 2026-09-27 | 15,198 |
| 2026-09-28 | 11,659 |
| 2026-09-29 | 9,418 |
| 2026-09-30 | 10,280 |
| 2026-10-01 | 16,697 |
| 2026-10-02 | 7,788 |
| 2026-10-03 | 7,389 |
| 2026-10-04 | 12,761 |
| 2026-10-05 | 17,673 |
| 2026-10-06 | 16,247 |
| 2026-10-07 | 15,166 |
| 2026-10-08 | 61,979 |
| 2026-10-09 | 225,591 |
| 2026-10-10 | 53,511 |
| 2026-10-11 | 16,103 |
| 2026-10-12 | 66,686 |
| 2026-10-13 | 1,590,255 |
| 2026-10-14 | 32,959 |
| 2026-10-15 | 41,443 |
| 2026-10-16 | 51,492 |
| 2026-10-17 | 24,455 |
| 2026-10-18 | 14,372 |
| 2026-10-19 | 22,646 |
| 2026-10-20 | 11,212 |
| 2026-10-21 | 11,191 |
| 2026-10-22 | 30,949 |
| 2026-10-23 | 50,598 |
| 2026-10-24 | 41,899 |
| 2026-10-25 | 21,754 |
| 2026-10-26 | 20,509 |
| 2026-10-27 | 20,872 |
| 2026-10-28 | 15,929 |
| 2026-10-29 | 9,803 |
| 2026-10-30 | 62,360 |
| 2026-10-31 | 88,426 |
| 2026-11-01 | 28,046 |
| 2026-11-02 | 29,049 |
| 2026-11-03 | 30,115 |
| 2026-11-04 | 29,903 |
| 2026-11-05 | 25,482 |
| 2026-11-06 | 36,926 |
| 2026-11-07 | 24,653 |
| 2026-11-08 | 26,326 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 143170 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
