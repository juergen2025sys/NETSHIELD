# Seen-DB Expiry Forecast

Lauf: 2026-09-14 03:31 CEST (Europe/Berlin)
Gesamt: 11,106,866 IPs in seen_db.json (8,208,750 aktiv/180-Tage-Pfad, 2,898,116 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 0 |
| 8-14 Tage | 101,599 |
| 15-30 Tage | 2,156,660 |
| 31-60 Tage | 890,537 |
| 61-90 Tage | 1,074,168 |
| 91-180 Tage | 3,985,786 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 520,363 |
| 0-3 Tage | 40,457 |
| 4-7 Tage | 24,047 |
| 8-14 Tage | 664,607 |
| 15-30 Tage | 1,648,642 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-14 | 12,843 |
| 2026-09-15 | 15,597 |
| 2026-09-16 | 6,244 |
| 2026-09-17 | 5,773 |
| 2026-09-18 | 8,795 |
| 2026-09-19 | 5,151 |
| 2026-09-20 | 5,060 |
| 2026-09-21 | 5,041 |
| 2026-09-22 | 11,186 |
| 2026-09-23 | 5,151 |
| 2026-09-24 | 11,432 |
| 2026-09-25 | 5,503 |
| 2026-09-26 | 624,224 |
| 2026-09-27 | 6,328 |
| 2026-09-28 | 783 |
| 2026-09-30 | 59,864 |
| 2026-10-01 | 7,713 |
| 2026-10-02 | 1,309,062 |
| 2026-10-03 | 2,992 |
| 2026-10-04 | 6,975 |
| 2026-10-05 | 2,929 |
| 2026-10-06 | 8,332 |
| 2026-10-07 | 8,079 |
| 2026-10-08 | 7,378 |
| 2026-10-09 | 152,434 |
| 2026-10-10 | 8,292 |
| 2026-10-11 | 23,367 |
| 2026-10-12 | 33,470 |
| 2026-10-13 | 9,236 |
| 2026-10-14 | 8,494 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **520,363** IPs. Brutto faellig in den naechsten 30 Tagen: **2,377,728**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,838,091**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-14 | 12,843 | 2,000 |
| 2026-09-15 | 15,597 | 2,000 |
| 2026-09-16 | 6,244 | 2,000 |
| 2026-09-17 | 5,773 | 2,000 |
| 2026-09-18 | 8,795 | 2,000 |
| 2026-09-19 | 5,151 | 2,000 |
| 2026-09-20 | 5,060 | 2,000 |
| 2026-09-21 | 5,041 | 2,000 |
| 2026-09-22 | 11,186 | 2,000 |
| 2026-09-23 | 5,151 | 2,000 |
| 2026-09-24 | 11,432 | 2,000 |
| 2026-09-25 | 5,503 | 2,000 |
| 2026-09-26 | 624,224 | 2,000 |
| 2026-09-27 | 6,328 | 2,000 |
| 2026-09-28 | 783 | 2,000 |
| 2026-09-30 | 59,864 | 2,000 |
| 2026-10-01 | 7,713 | 2,000 |
| 2026-10-02 | 1,309,062 | 2,000 |
| 2026-10-03 | 2,992 | 2,000 |
| 2026-10-04 | 6,975 | 2,000 |
| 2026-10-05 | 2,929 | 2,000 |
| 2026-10-06 | 8,332 | 2,000 |
| 2026-10-07 | 8,079 | 2,000 |
| 2026-10-08 | 7,378 | 2,000 |
| 2026-10-09 | 152,434 | 2,000 |
| 2026-10-10 | 8,292 | 2,000 |
| 2026-10-11 | 23,367 | 2,000 |
| 2026-10-12 | 33,470 | 2,000 |
| 2026-10-13 | 9,236 | 2,000 |
| 2026-10-14 | 8,494 | 2,000 |

> Hinweis: Der Rueckstau von 2,838,091 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,449 |
| 2026-09-23 | 13,104 |
| 2026-09-24 | 16,745 |
| 2026-09-25 | 21,018 |
| 2026-09-26 | 17,524 |
| 2026-09-27 | 15,125 |
| 2026-09-28 | 11,634 |
| 2026-09-29 | 9,393 |
| 2026-09-30 | 10,243 |
| 2026-10-01 | 16,657 |
| 2026-10-02 | 7,760 |
| 2026-10-03 | 7,371 |
| 2026-10-04 | 12,702 |
| 2026-10-05 | 17,627 |
| 2026-10-06 | 16,200 |
| 2026-10-07 | 15,132 |
| 2026-10-08 | 61,768 |
| 2026-10-09 | 224,413 |
| 2026-10-10 | 53,463 |
| 2026-10-11 | 16,084 |
| 2026-10-12 | 66,647 |
| 2026-10-13 | 1,588,257 |
| 2026-10-14 | 32,943 |
| 2026-10-15 | 41,420 |
| 2026-10-16 | 51,447 |
| 2026-10-17 | 24,413 |
| 2026-10-18 | 14,339 |
| 2026-10-19 | 22,546 |
| 2026-10-20 | 11,188 |
| 2026-10-21 | 11,163 |
| 2026-10-22 | 30,876 |
| 2026-10-23 | 50,551 |
| 2026-10-24 | 41,851 |
| 2026-10-25 | 21,713 |
| 2026-10-26 | 20,463 |
| 2026-10-27 | 20,814 |
| 2026-10-28 | 15,877 |
| 2026-10-29 | 9,763 |
| 2026-10-30 | 62,226 |
| 2026-10-31 | 88,356 |
| 2026-11-01 | 28,000 |
| 2026-11-02 | 28,987 |
| 2026-11-03 | 30,027 |
| 2026-11-04 | 29,822 |
| 2026-11-05 | 25,422 |
| 2026-11-06 | 36,860 |
| 2026-11-07 | 24,609 |
| 2026-11-08 | 26,276 |
| 2026-11-09 | 25,723 |
| 2026-11-10 | 32,922 |
| 2026-11-11 | 22,520 |
| 2026-11-12 | 20,603 |
| 2026-11-13 | 19,760 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 190837 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
