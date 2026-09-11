# Seen-DB Expiry Forecast

Lauf: 2026-09-11 15:46 CEST (Europe/Berlin)
Gesamt: 10,992,609 IPs in seen_db.json (8,106,890 aktiv/180-Tage-Pfad, 2,885,719 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 0 |
| 8-14 Tage | 57,418 |
| 15-30 Tage | 514,084 |
| 31-60 Tage | 2,517,382 |
| 61-90 Tage | 1,061,150 |
| 91-180 Tage | 3,956,856 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 488,414 |
| 0-3 Tage | 48,170 |
| 4-7 Tage | 36,486 |
| 8-14 Tage | 48,644 |
| 15-30 Tage | 2,264,005 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-11 | 11,315 |
| 2026-09-12 | 11,918 |
| 2026-09-13 | 12,063 |
| 2026-09-14 | 12,874 |
| 2026-09-15 | 15,627 |
| 2026-09-16 | 6,254 |
| 2026-09-17 | 5,793 |
| 2026-09-18 | 8,812 |
| 2026-09-19 | 5,164 |
| 2026-09-20 | 5,077 |
| 2026-09-21 | 5,064 |
| 2026-09-22 | 11,213 |
| 2026-09-23 | 5,171 |
| 2026-09-24 | 11,443 |
| 2026-09-25 | 5,512 |
| 2026-09-26 | 624,381 |
| 2026-09-27 | 6,353 |
| 2026-09-28 | 784 |
| 2026-09-30 | 59,931 |
| 2026-10-01 | 7,728 |
| 2026-10-02 | 1,309,657 |
| 2026-10-03 | 3,001 |
| 2026-10-04 | 6,994 |
| 2026-10-05 | 2,942 |
| 2026-10-06 | 8,357 |
| 2026-10-07 | 8,123 |
| 2026-10-08 | 7,398 |
| 2026-10-09 | 152,621 |
| 2026-10-10 | 8,335 |
| 2026-10-11 | 23,932 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **488,414** IPs. Brutto faellig in den naechsten 30 Tagen: **2,363,837**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,792,251**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-11 | 11,315 | 2,000 |
| 2026-09-12 | 11,918 | 2,000 |
| 2026-09-13 | 12,063 | 2,000 |
| 2026-09-14 | 12,874 | 2,000 |
| 2026-09-15 | 15,627 | 2,000 |
| 2026-09-16 | 6,254 | 2,000 |
| 2026-09-17 | 5,793 | 2,000 |
| 2026-09-18 | 8,812 | 2,000 |
| 2026-09-19 | 5,164 | 2,000 |
| 2026-09-20 | 5,077 | 2,000 |
| 2026-09-21 | 5,064 | 2,000 |
| 2026-09-22 | 11,213 | 2,000 |
| 2026-09-23 | 5,171 | 2,000 |
| 2026-09-24 | 11,443 | 2,000 |
| 2026-09-25 | 5,512 | 2,000 |
| 2026-09-26 | 624,381 | 2,000 |
| 2026-09-27 | 6,353 | 2,000 |
| 2026-09-28 | 784 | 2,000 |
| 2026-09-30 | 59,931 | 2,000 |
| 2026-10-01 | 7,728 | 2,000 |
| 2026-10-02 | 1,309,657 | 2,000 |
| 2026-10-03 | 3,001 | 2,000 |
| 2026-10-04 | 6,994 | 2,000 |
| 2026-10-05 | 2,942 | 2,000 |
| 2026-10-06 | 8,357 | 2,000 |
| 2026-10-07 | 8,123 | 2,000 |
| 2026-10-08 | 7,398 | 2,000 |
| 2026-10-09 | 152,621 | 2,000 |
| 2026-10-10 | 8,335 | 2,000 |
| 2026-10-11 | 23,932 | 2,000 |

> Hinweis: Der Rueckstau von 2,792,251 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,461 |
| 2026-09-23 | 13,121 |
| 2026-09-24 | 16,779 |
| 2026-09-25 | 21,057 |
| 2026-09-26 | 17,567 |
| 2026-09-27 | 15,163 |
| 2026-09-28 | 11,644 |
| 2026-09-29 | 9,406 |
| 2026-09-30 | 10,260 |
| 2026-10-01 | 16,680 |
| 2026-10-02 | 7,777 |
| 2026-10-03 | 7,382 |
| 2026-10-04 | 12,729 |
| 2026-10-05 | 17,652 |
| 2026-10-06 | 16,229 |
| 2026-10-07 | 15,153 |
| 2026-10-08 | 61,879 |
| 2026-10-09 | 224,985 |
| 2026-10-10 | 53,486 |
| 2026-10-11 | 16,092 |
| 2026-10-12 | 66,662 |
| 2026-10-13 | 1,589,215 |
| 2026-10-14 | 32,950 |
| 2026-10-15 | 41,438 |
| 2026-10-16 | 51,475 |
| 2026-10-17 | 24,437 |
| 2026-10-18 | 14,357 |
| 2026-10-19 | 22,599 |
| 2026-10-20 | 11,205 |
| 2026-10-21 | 11,181 |
| 2026-10-22 | 30,924 |
| 2026-10-23 | 50,579 |
| 2026-10-24 | 41,882 |
| 2026-10-25 | 21,744 |
| 2026-10-26 | 20,491 |
| 2026-10-27 | 20,847 |
| 2026-10-28 | 15,908 |
| 2026-10-29 | 9,784 |
| 2026-10-30 | 62,300 |
| 2026-10-31 | 88,398 |
| 2026-11-01 | 28,028 |
| 2026-11-02 | 29,022 |
| 2026-11-03 | 30,081 |
| 2026-11-04 | 29,867 |
| 2026-11-05 | 25,456 |
| 2026-11-06 | 36,896 |
| 2026-11-07 | 24,630 |
| 2026-11-08 | 26,305 |
| 2026-11-09 | 25,757 |
| 2026-11-10 | 32,964 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 189777 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
