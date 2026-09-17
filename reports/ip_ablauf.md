# Seen-DB Expiry Forecast

Lauf: 2026-09-18 01:02 CEST (Europe/Berlin)
Gesamt: 11,414,314 IPs in seen_db.json (8,473,515 aktiv/180-Tage-Pfad, 2,940,799 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 36,210 |
| 8-14 Tage | 101,330 |
| 15-30 Tage | 2,234,916 |
| 31-60 Tage | 830,602 |
| 61-90 Tage | 1,080,778 |
| 91-180 Tage | 4,189,679 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 555,872 |
| 0-3 Tage | 24,683 |
| 4-7 Tage | 32,718 |
| 8-14 Tage | 704,007 |
| 15-30 Tage | 1,623,519 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-17 | 5,750 |
| 2026-09-18 | 8,759 |
| 2026-09-19 | 5,131 |
| 2026-09-20 | 5,043 |
| 2026-09-21 | 5,024 |
| 2026-09-22 | 11,159 |
| 2026-09-23 | 5,125 |
| 2026-09-24 | 11,410 |
| 2026-09-25 | 5,479 |
| 2026-09-26 | 624,017 |
| 2026-09-27 | 6,299 |
| 2026-09-28 | 778 |
| 2026-09-30 | 59,756 |
| 2026-10-01 | 7,678 |
| 2026-10-02 | 1,308,043 |
| 2026-10-03 | 2,982 |
| 2026-10-04 | 6,935 |
| 2026-10-05 | 2,917 |
| 2026-10-06 | 8,300 |
| 2026-10-07 | 8,029 |
| 2026-10-08 | 7,350 |
| 2026-10-09 | 152,122 |
| 2026-10-10 | 8,234 |
| 2026-10-11 | 23,237 |
| 2026-10-12 | 33,375 |
| 2026-10-13 | 9,084 |
| 2026-10-14 | 8,127 |
| 2026-10-15 | 8,934 |
| 2026-10-16 | 16,317 |
| 2026-10-17 | 10,756 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **555,872** IPs. Brutto faellig in den naechsten 30 Tagen: **2,376,150**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,872,022**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-17 | 5,750 | 2,000 |
| 2026-09-18 | 8,759 | 2,000 |
| 2026-09-19 | 5,131 | 2,000 |
| 2026-09-20 | 5,043 | 2,000 |
| 2026-09-21 | 5,024 | 2,000 |
| 2026-09-22 | 11,159 | 2,000 |
| 2026-09-23 | 5,125 | 2,000 |
| 2026-09-24 | 11,410 | 2,000 |
| 2026-09-25 | 5,479 | 2,000 |
| 2026-09-26 | 624,017 | 2,000 |
| 2026-09-27 | 6,299 | 2,000 |
| 2026-09-28 | 778 | 2,000 |
| 2026-09-30 | 59,756 | 2,000 |
| 2026-10-01 | 7,678 | 2,000 |
| 2026-10-02 | 1,308,043 | 2,000 |
| 2026-10-03 | 2,982 | 2,000 |
| 2026-10-04 | 6,935 | 2,000 |
| 2026-10-05 | 2,917 | 2,000 |
| 2026-10-06 | 8,300 | 2,000 |
| 2026-10-07 | 8,029 | 2,000 |
| 2026-10-08 | 7,350 | 2,000 |
| 2026-10-09 | 152,122 | 2,000 |
| 2026-10-10 | 8,234 | 2,000 |
| 2026-10-11 | 23,237 | 2,000 |
| 2026-10-12 | 33,375 | 2,000 |
| 2026-10-13 | 9,084 | 2,000 |
| 2026-10-14 | 8,127 | 2,000 |
| 2026-10-15 | 8,934 | 2,000 |
| 2026-10-16 | 16,317 | 2,000 |
| 2026-10-17 | 10,756 | 2,000 |

> Hinweis: Der Rueckstau von 2,872,022 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,437 |
| 2026-09-23 | 13,080 |
| 2026-09-24 | 16,693 |
| 2026-09-25 | 20,963 |
| 2026-09-26 | 17,485 |
| 2026-09-27 | 15,065 |
| 2026-09-28 | 11,621 |
| 2026-09-29 | 9,370 |
| 2026-09-30 | 10,202 |
| 2026-10-01 | 16,624 |
| 2026-10-02 | 7,738 |
| 2026-10-03 | 7,346 |
| 2026-10-04 | 12,649 |
| 2026-10-05 | 17,580 |
| 2026-10-06 | 16,157 |
| 2026-10-07 | 15,098 |
| 2026-10-08 | 61,542 |
| 2026-10-09 | 223,768 |
| 2026-10-10 | 53,423 |
| 2026-10-11 | 16,071 |
| 2026-10-12 | 66,615 |
| 2026-10-13 | 1,586,848 |
| 2026-10-14 | 32,931 |
| 2026-10-15 | 41,374 |
| 2026-10-16 | 51,409 |
| 2026-10-17 | 24,367 |
| 2026-10-18 | 14,311 |
| 2026-10-19 | 22,454 |
| 2026-10-20 | 11,168 |
| 2026-10-21 | 11,142 |
| 2026-10-22 | 30,823 |
| 2026-10-23 | 50,496 |
| 2026-10-24 | 41,809 |
| 2026-10-25 | 21,679 |
| 2026-10-26 | 20,411 |
| 2026-10-27 | 20,768 |
| 2026-10-28 | 15,848 |
| 2026-10-29 | 9,730 |
| 2026-10-30 | 62,123 |
| 2026-10-31 | 88,300 |
| 2026-11-01 | 27,952 |
| 2026-11-02 | 28,928 |
| 2026-11-03 | 29,955 |
| 2026-11-04 | 29,762 |
| 2026-11-05 | 25,375 |
| 2026-11-06 | 36,805 |
| 2026-11-07 | 24,566 |
| 2026-11-08 | 26,228 |
| 2026-11-09 | 25,665 |
| 2026-11-10 | 32,856 |
| 2026-11-11 | 22,481 |
| 2026-11-12 | 20,580 |
| 2026-11-13 | 19,732 |
| 2026-11-14 | 23,066 |
| 2026-11-15 | 17,538 |
| 2026-11-16 | 18,051 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 192799 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
