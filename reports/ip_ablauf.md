# Seen-DB Expiry Forecast

Lauf: 2026-09-10 00:27 CEST (Europe/Berlin)
Gesamt: 10,836,691 IPs in seen_db.json (8,006,249 aktiv/180-Tage-Pfad, 2,830,442 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 0 |
| 8-14 Tage | 19,613 |
| 15-30 Tage | 483,324 |
| 31-60 Tage | 2,529,891 |
| 61-90 Tage | 1,039,115 |
| 91-180 Tage | 3,934,306 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 463,146 |
| 0-3 Tage | 48,927 |
| 4-7 Tage | 46,885 |
| 8-14 Tage | 46,353 |
| 15-30 Tage | 2,225,131 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-09 | 16,909 |
| 2026-09-10 | 8,757 |
| 2026-09-11 | 11,333 |
| 2026-09-12 | 11,928 |
| 2026-09-13 | 12,077 |
| 2026-09-14 | 12,893 |
| 2026-09-15 | 15,651 |
| 2026-09-16 | 6,264 |
| 2026-09-17 | 5,804 |
| 2026-09-18 | 8,822 |
| 2026-09-19 | 5,169 |
| 2026-09-20 | 5,086 |
| 2026-09-21 | 5,069 |
| 2026-09-22 | 11,223 |
| 2026-09-23 | 5,180 |
| 2026-09-24 | 11,451 |
| 2026-09-25 | 5,524 |
| 2026-09-26 | 624,489 |
| 2026-09-27 | 6,358 |
| 2026-09-28 | 784 |
| 2026-09-30 | 59,989 |
| 2026-10-01 | 7,748 |
| 2026-10-02 | 1,310,033 |
| 2026-10-03 | 3,009 |
| 2026-10-04 | 7,007 |
| 2026-10-05 | 2,959 |
| 2026-10-06 | 8,376 |
| 2026-10-07 | 8,154 |
| 2026-10-08 | 7,428 |
| 2026-10-09 | 152,812 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **463,146** IPs. Brutto faellig in den naechsten 30 Tagen: **2,358,286**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,761,432**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-09 | 16,909 | 2,000 |
| 2026-09-10 | 8,757 | 2,000 |
| 2026-09-11 | 11,333 | 2,000 |
| 2026-09-12 | 11,928 | 2,000 |
| 2026-09-13 | 12,077 | 2,000 |
| 2026-09-14 | 12,893 | 2,000 |
| 2026-09-15 | 15,651 | 2,000 |
| 2026-09-16 | 6,264 | 2,000 |
| 2026-09-17 | 5,804 | 2,000 |
| 2026-09-18 | 8,822 | 2,000 |
| 2026-09-19 | 5,169 | 2,000 |
| 2026-09-20 | 5,086 | 2,000 |
| 2026-09-21 | 5,069 | 2,000 |
| 2026-09-22 | 11,223 | 2,000 |
| 2026-09-23 | 5,180 | 2,000 |
| 2026-09-24 | 11,451 | 2,000 |
| 2026-09-25 | 5,524 | 2,000 |
| 2026-09-26 | 624,489 | 2,000 |
| 2026-09-27 | 6,358 | 2,000 |
| 2026-09-28 | 784 | 2,000 |
| 2026-09-30 | 59,989 | 2,000 |
| 2026-10-01 | 7,748 | 2,000 |
| 2026-10-02 | 1,310,033 | 2,000 |
| 2026-10-03 | 3,009 | 2,000 |
| 2026-10-04 | 7,007 | 2,000 |
| 2026-10-05 | 2,959 | 2,000 |
| 2026-10-06 | 8,376 | 2,000 |
| 2026-10-07 | 8,154 | 2,000 |
| 2026-10-08 | 7,428 | 2,000 |
| 2026-10-09 | 152,812 | 2,000 |

> Hinweis: Der Rueckstau von 2,761,432 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,469 |
| 2026-09-23 | 13,144 |
| 2026-09-24 | 16,812 |
| 2026-09-25 | 21,095 |
| 2026-09-26 | 17,593 |
| 2026-09-27 | 15,196 |
| 2026-09-28 | 11,658 |
| 2026-09-29 | 9,418 |
| 2026-09-30 | 10,280 |
| 2026-10-01 | 16,695 |
| 2026-10-02 | 7,788 |
| 2026-10-03 | 7,389 |
| 2026-10-04 | 12,761 |
| 2026-10-05 | 17,673 |
| 2026-10-06 | 16,247 |
| 2026-10-07 | 15,166 |
| 2026-10-08 | 61,974 |
| 2026-10-09 | 225,579 |
| 2026-10-10 | 53,510 |
| 2026-10-11 | 16,102 |
| 2026-10-12 | 66,684 |
| 2026-10-13 | 1,590,250 |
| 2026-10-14 | 32,958 |
| 2026-10-15 | 41,443 |
| 2026-10-16 | 51,489 |
| 2026-10-17 | 24,454 |
| 2026-10-18 | 14,372 |
| 2026-10-19 | 22,645 |
| 2026-10-20 | 11,211 |
| 2026-10-21 | 11,191 |
| 2026-10-22 | 30,948 |
| 2026-10-23 | 50,598 |
| 2026-10-24 | 41,898 |
| 2026-10-25 | 21,753 |
| 2026-10-26 | 20,507 |
| 2026-10-27 | 20,872 |
| 2026-10-28 | 15,927 |
| 2026-10-29 | 9,803 |
| 2026-10-30 | 62,358 |
| 2026-10-31 | 88,425 |
| 2026-11-01 | 28,046 |
| 2026-11-02 | 29,049 |
| 2026-11-03 | 30,113 |
| 2026-11-04 | 29,903 |
| 2026-11-05 | 25,482 |
| 2026-11-06 | 36,923 |
| 2026-11-07 | 24,652 |
| 2026-11-08 | 26,325 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 143190 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
