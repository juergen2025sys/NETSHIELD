# Seen-DB Expiry Forecast

Lauf: 2026-09-09 18:52 CEST (Europe/Berlin)
Gesamt: 10,829,715 IPs in seen_db.json (8,000,549 aktiv/180-Tage-Pfad, 2,829,166 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 0 |
| 8-14 Tage | 19,615 |
| 15-30 Tage | 483,418 |
| 31-60 Tage | 2,530,011 |
| 61-90 Tage | 1,039,200 |
| 91-180 Tage | 3,928,305 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 463,495 |
| 0-3 Tage | 48,936 |
| 4-7 Tage | 46,891 |
| 8-14 Tage | 46,364 |
| 15-30 Tage | 2,223,480 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-09 | 16,911 |
| 2026-09-10 | 8,760 |
| 2026-09-11 | 11,335 |
| 2026-09-12 | 11,930 |
| 2026-09-13 | 12,080 |
| 2026-09-14 | 12,894 |
| 2026-09-15 | 15,651 |
| 2026-09-16 | 6,266 |
| 2026-09-17 | 5,806 |
| 2026-09-18 | 8,824 |
| 2026-09-19 | 5,170 |
| 2026-09-20 | 5,087 |
| 2026-09-21 | 5,071 |
| 2026-09-22 | 11,224 |
| 2026-09-23 | 5,182 |
| 2026-09-24 | 11,453 |
| 2026-09-25 | 5,524 |
| 2026-09-26 | 624,500 |
| 2026-09-27 | 6,363 |
| 2026-09-28 | 784 |
| 2026-09-30 | 59,994 |
| 2026-10-01 | 7,748 |
| 2026-10-02 | 1,310,078 |
| 2026-10-03 | 3,009 |
| 2026-10-04 | 7,008 |
| 2026-10-05 | 2,960 |
| 2026-10-06 | 8,377 |
| 2026-10-07 | 8,159 |
| 2026-10-08 | 7,432 |
| 2026-10-09 | 152,842 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **463,495** IPs. Brutto faellig in den naechsten 30 Tagen: **2,358,422**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,761,917**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-09 | 16,911 | 2,000 |
| 2026-09-10 | 8,760 | 2,000 |
| 2026-09-11 | 11,335 | 2,000 |
| 2026-09-12 | 11,930 | 2,000 |
| 2026-09-13 | 12,080 | 2,000 |
| 2026-09-14 | 12,894 | 2,000 |
| 2026-09-15 | 15,651 | 2,000 |
| 2026-09-16 | 6,266 | 2,000 |
| 2026-09-17 | 5,806 | 2,000 |
| 2026-09-18 | 8,824 | 2,000 |
| 2026-09-19 | 5,170 | 2,000 |
| 2026-09-20 | 5,087 | 2,000 |
| 2026-09-21 | 5,071 | 2,000 |
| 2026-09-22 | 11,224 | 2,000 |
| 2026-09-23 | 5,182 | 2,000 |
| 2026-09-24 | 11,453 | 2,000 |
| 2026-09-25 | 5,524 | 2,000 |
| 2026-09-26 | 624,500 | 2,000 |
| 2026-09-27 | 6,363 | 2,000 |
| 2026-09-28 | 784 | 2,000 |
| 2026-09-30 | 59,994 | 2,000 |
| 2026-10-01 | 7,748 | 2,000 |
| 2026-10-02 | 1,310,078 | 2,000 |
| 2026-10-03 | 3,009 | 2,000 |
| 2026-10-04 | 7,008 | 2,000 |
| 2026-10-05 | 2,960 | 2,000 |
| 2026-10-06 | 8,377 | 2,000 |
| 2026-10-07 | 8,159 | 2,000 |
| 2026-10-08 | 7,432 | 2,000 |
| 2026-10-09 | 152,842 | 2,000 |

> Hinweis: Der Rueckstau von 2,761,917 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,469 |
| 2026-09-23 | 13,146 |
| 2026-09-24 | 16,818 |
| 2026-09-25 | 21,098 |
| 2026-09-26 | 17,596 |
| 2026-09-27 | 15,199 |
| 2026-09-28 | 11,660 |
| 2026-09-29 | 9,419 |
| 2026-09-30 | 10,281 |
| 2026-10-01 | 16,698 |
| 2026-10-02 | 7,788 |
| 2026-10-03 | 7,390 |
| 2026-10-04 | 12,764 |
| 2026-10-05 | 17,676 |
| 2026-10-06 | 16,247 |
| 2026-10-07 | 15,168 |
| 2026-10-08 | 61,986 |
| 2026-10-09 | 225,630 |
| 2026-10-10 | 53,511 |
| 2026-10-11 | 16,103 |
| 2026-10-12 | 66,688 |
| 2026-10-13 | 1,590,292 |
| 2026-10-14 | 32,960 |
| 2026-10-15 | 41,444 |
| 2026-10-16 | 51,493 |
| 2026-10-17 | 24,457 |
| 2026-10-18 | 14,374 |
| 2026-10-19 | 22,648 |
| 2026-10-20 | 11,212 |
| 2026-10-21 | 11,192 |
| 2026-10-22 | 30,952 |
| 2026-10-23 | 50,599 |
| 2026-10-24 | 41,901 |
| 2026-10-25 | 21,754 |
| 2026-10-26 | 20,510 |
| 2026-10-27 | 20,874 |
| 2026-10-28 | 15,930 |
| 2026-10-29 | 9,804 |
| 2026-10-30 | 62,365 |
| 2026-10-31 | 88,430 |
| 2026-11-01 | 28,050 |
| 2026-11-02 | 29,052 |
| 2026-11-03 | 30,116 |
| 2026-11-04 | 29,906 |
| 2026-11-05 | 25,483 |
| 2026-11-06 | 36,929 |
| 2026-11-07 | 24,654 |
| 2026-11-08 | 26,328 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 143159 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
