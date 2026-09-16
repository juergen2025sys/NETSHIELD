# Seen-DB Expiry Forecast

Lauf: 2026-09-16 11:50 CEST (Europe/Berlin)
Gesamt: 11,317,217 IPs in seen_db.json (8,387,616 aktiv/180-Tage-Pfad, 2,929,601 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 19,526 |
| 8-14 Tage | 101,507 |
| 15-30 Tage | 2,228,009 |
| 31-60 Tage | 837,448 |
| 61-90 Tage | 1,082,571 |
| 91-180 Tage | 4,118,555 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 550,016 |
| 0-3 Tage | 25,895 |
| 4-7 Tage | 26,385 |
| 8-14 Tage | 707,889 |
| 15-30 Tage | 1,619,416 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-16 | 6,231 |
| 2026-09-17 | 5,757 |
| 2026-09-18 | 8,774 |
| 2026-09-19 | 5,133 |
| 2026-09-20 | 5,054 |
| 2026-09-21 | 5,030 |
| 2026-09-22 | 11,168 |
| 2026-09-23 | 5,133 |
| 2026-09-24 | 11,417 |
| 2026-09-25 | 5,485 |
| 2026-09-26 | 624,103 |
| 2026-09-27 | 6,318 |
| 2026-09-28 | 779 |
| 2026-09-30 | 59,787 |
| 2026-10-01 | 7,686 |
| 2026-10-02 | 1,308,472 |
| 2026-10-03 | 2,985 |
| 2026-10-04 | 6,948 |
| 2026-10-05 | 2,918 |
| 2026-10-06 | 8,308 |
| 2026-10-07 | 8,044 |
| 2026-10-08 | 7,360 |
| 2026-10-09 | 152,256 |
| 2026-10-10 | 8,257 |
| 2026-10-11 | 23,295 |
| 2026-10-12 | 33,415 |
| 2026-10-13 | 9,126 |
| 2026-10-14 | 8,150 |
| 2026-10-15 | 8,970 |
| 2026-10-16 | 16,951 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **550,016** IPs. Brutto faellig in den naechsten 30 Tagen: **2,373,310**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,863,326**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-16 | 6,231 | 2,000 |
| 2026-09-17 | 5,757 | 2,000 |
| 2026-09-18 | 8,774 | 2,000 |
| 2026-09-19 | 5,133 | 2,000 |
| 2026-09-20 | 5,054 | 2,000 |
| 2026-09-21 | 5,030 | 2,000 |
| 2026-09-22 | 11,168 | 2,000 |
| 2026-09-23 | 5,133 | 2,000 |
| 2026-09-24 | 11,417 | 2,000 |
| 2026-09-25 | 5,485 | 2,000 |
| 2026-09-26 | 624,103 | 2,000 |
| 2026-09-27 | 6,318 | 2,000 |
| 2026-09-28 | 779 | 2,000 |
| 2026-09-30 | 59,787 | 2,000 |
| 2026-10-01 | 7,686 | 2,000 |
| 2026-10-02 | 1,308,472 | 2,000 |
| 2026-10-03 | 2,985 | 2,000 |
| 2026-10-04 | 6,948 | 2,000 |
| 2026-10-05 | 2,918 | 2,000 |
| 2026-10-06 | 8,308 | 2,000 |
| 2026-10-07 | 8,044 | 2,000 |
| 2026-10-08 | 7,360 | 2,000 |
| 2026-10-09 | 152,256 | 2,000 |
| 2026-10-10 | 8,257 | 2,000 |
| 2026-10-11 | 23,295 | 2,000 |
| 2026-10-12 | 33,415 | 2,000 |
| 2026-10-13 | 9,126 | 2,000 |
| 2026-10-14 | 8,150 | 2,000 |
| 2026-10-15 | 8,970 | 2,000 |
| 2026-10-16 | 16,951 | 2,000 |

> Hinweis: Der Rueckstau von 2,863,326 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,441 |
| 2026-09-23 | 13,085 |
| 2026-09-24 | 16,709 |
| 2026-09-25 | 20,985 |
| 2026-09-26 | 17,501 |
| 2026-09-27 | 15,085 |
| 2026-09-28 | 11,625 |
| 2026-09-29 | 9,385 |
| 2026-09-30 | 10,217 |
| 2026-10-01 | 16,636 |
| 2026-10-02 | 7,750 |
| 2026-10-03 | 7,353 |
| 2026-10-04 | 12,668 |
| 2026-10-05 | 17,598 |
| 2026-10-06 | 16,173 |
| 2026-10-07 | 15,111 |
| 2026-10-08 | 61,617 |
| 2026-10-09 | 223,977 |
| 2026-10-10 | 53,440 |
| 2026-10-11 | 16,077 |
| 2026-10-12 | 66,627 |
| 2026-10-13 | 1,587,244 |
| 2026-10-14 | 32,938 |
| 2026-10-15 | 41,382 |
| 2026-10-16 | 51,418 |
| 2026-10-17 | 24,382 |
| 2026-10-18 | 14,326 |
| 2026-10-19 | 22,490 |
| 2026-10-20 | 11,177 |
| 2026-10-21 | 11,153 |
| 2026-10-22 | 30,846 |
| 2026-10-23 | 50,515 |
| 2026-10-24 | 41,825 |
| 2026-10-25 | 21,688 |
| 2026-10-26 | 20,428 |
| 2026-10-27 | 20,779 |
| 2026-10-28 | 15,863 |
| 2026-10-29 | 9,747 |
| 2026-10-30 | 62,158 |
| 2026-10-31 | 88,324 |
| 2026-11-01 | 27,966 |
| 2026-11-02 | 28,949 |
| 2026-11-03 | 29,971 |
| 2026-11-04 | 29,780 |
| 2026-11-05 | 25,396 |
| 2026-11-06 | 36,825 |
| 2026-11-07 | 24,579 |
| 2026-11-08 | 26,250 |
| 2026-11-09 | 25,689 |
| 2026-11-10 | 32,880 |
| 2026-11-11 | 22,500 |
| 2026-11-12 | 20,588 |
| 2026-11-13 | 19,744 |
| 2026-11-14 | 23,084 |
| 2026-11-15 | 17,546 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 192205 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
