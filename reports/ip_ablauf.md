# Seen-DB Expiry Forecast

Lauf: 2026-09-14 15:15 CEST (Europe/Berlin)
Gesamt: 11,139,256 IPs in seen_db.json (8,232,555 aktiv/180-Tage-Pfad, 2,906,701 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 0 |
| 8-14 Tage | 101,578 |
| 15-30 Tage | 2,156,381 |
| 31-60 Tage | 890,391 |
| 61-90 Tage | 1,073,959 |
| 91-180 Tage | 4,010,246 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 522,235 |
| 0-3 Tage | 40,441 |
| 4-7 Tage | 24,035 |
| 8-14 Tage | 664,573 |
| 15-30 Tage | 1,655,417 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-14 | 12,841 |
| 2026-09-15 | 15,588 |
| 2026-09-16 | 6,243 |
| 2026-09-17 | 5,769 |
| 2026-09-18 | 8,792 |
| 2026-09-19 | 5,147 |
| 2026-09-20 | 5,058 |
| 2026-09-21 | 5,038 |
| 2026-09-22 | 11,185 |
| 2026-09-23 | 5,146 |
| 2026-09-24 | 11,428 |
| 2026-09-25 | 5,497 |
| 2026-09-26 | 624,208 |
| 2026-09-27 | 6,327 |
| 2026-09-28 | 782 |
| 2026-09-30 | 59,847 |
| 2026-10-01 | 7,704 |
| 2026-10-02 | 1,308,970 |
| 2026-10-03 | 2,988 |
| 2026-10-04 | 6,969 |
| 2026-10-05 | 2,927 |
| 2026-10-06 | 8,329 |
| 2026-10-07 | 8,069 |
| 2026-10-08 | 7,373 |
| 2026-10-09 | 152,401 |
| 2026-10-10 | 8,279 |
| 2026-10-11 | 23,357 |
| 2026-10-12 | 33,452 |
| 2026-10-13 | 9,185 |
| 2026-10-14 | 8,361 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **522,235** IPs. Brutto faellig in den naechsten 30 Tagen: **2,377,260**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,839,495**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-14 | 12,841 | 2,000 |
| 2026-09-15 | 15,588 | 2,000 |
| 2026-09-16 | 6,243 | 2,000 |
| 2026-09-17 | 5,769 | 2,000 |
| 2026-09-18 | 8,792 | 2,000 |
| 2026-09-19 | 5,147 | 2,000 |
| 2026-09-20 | 5,058 | 2,000 |
| 2026-09-21 | 5,038 | 2,000 |
| 2026-09-22 | 11,185 | 2,000 |
| 2026-09-23 | 5,146 | 2,000 |
| 2026-09-24 | 11,428 | 2,000 |
| 2026-09-25 | 5,497 | 2,000 |
| 2026-09-26 | 624,208 | 2,000 |
| 2026-09-27 | 6,327 | 2,000 |
| 2026-09-28 | 782 | 2,000 |
| 2026-09-30 | 59,847 | 2,000 |
| 2026-10-01 | 7,704 | 2,000 |
| 2026-10-02 | 1,308,970 | 2,000 |
| 2026-10-03 | 2,988 | 2,000 |
| 2026-10-04 | 6,969 | 2,000 |
| 2026-10-05 | 2,927 | 2,000 |
| 2026-10-06 | 8,329 | 2,000 |
| 2026-10-07 | 8,069 | 2,000 |
| 2026-10-08 | 7,373 | 2,000 |
| 2026-10-09 | 152,401 | 2,000 |
| 2026-10-10 | 8,279 | 2,000 |
| 2026-10-11 | 23,357 | 2,000 |
| 2026-10-12 | 33,452 | 2,000 |
| 2026-10-13 | 9,185 | 2,000 |
| 2026-10-14 | 8,361 | 2,000 |

> Hinweis: Der Rueckstau von 2,839,495 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,448 |
| 2026-09-23 | 13,101 |
| 2026-09-24 | 16,743 |
| 2026-09-25 | 21,013 |
| 2026-09-26 | 17,519 |
| 2026-09-27 | 15,120 |
| 2026-09-28 | 11,634 |
| 2026-09-29 | 9,392 |
| 2026-09-30 | 10,237 |
| 2026-10-01 | 16,653 |
| 2026-10-02 | 7,756 |
| 2026-10-03 | 7,370 |
| 2026-10-04 | 12,699 |
| 2026-10-05 | 17,622 |
| 2026-10-06 | 16,195 |
| 2026-10-07 | 15,129 |
| 2026-10-08 | 61,750 |
| 2026-10-09 | 224,334 |
| 2026-10-10 | 53,459 |
| 2026-10-11 | 16,083 |
| 2026-10-12 | 66,643 |
| 2026-10-13 | 1,588,118 |
| 2026-10-14 | 32,941 |
| 2026-10-15 | 41,417 |
| 2026-10-16 | 51,442 |
| 2026-10-17 | 24,410 |
| 2026-10-18 | 14,336 |
| 2026-10-19 | 22,540 |
| 2026-10-20 | 11,188 |
| 2026-10-21 | 11,162 |
| 2026-10-22 | 30,871 |
| 2026-10-23 | 50,544 |
| 2026-10-24 | 41,846 |
| 2026-10-25 | 21,709 |
| 2026-10-26 | 20,456 |
| 2026-10-27 | 20,810 |
| 2026-10-28 | 15,876 |
| 2026-10-29 | 9,763 |
| 2026-10-30 | 62,215 |
| 2026-10-31 | 88,351 |
| 2026-11-01 | 27,992 |
| 2026-11-02 | 28,980 |
| 2026-11-03 | 30,020 |
| 2026-11-04 | 29,811 |
| 2026-11-05 | 25,419 |
| 2026-11-06 | 36,853 |
| 2026-11-07 | 24,606 |
| 2026-11-08 | 26,271 |
| 2026-11-09 | 25,715 |
| 2026-11-10 | 32,915 |
| 2026-11-11 | 22,515 |
| 2026-11-12 | 20,602 |
| 2026-11-13 | 19,756 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 191220 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
