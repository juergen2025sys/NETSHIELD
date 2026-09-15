# Seen-DB Expiry Forecast

Lauf: 2026-09-15 09:36 CEST (Europe/Berlin)
Gesamt: 11,226,826 IPs in seen_db.json (8,312,217 aktiv/180-Tage-Pfad, 2,914,609 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 6,445 |
| 8-14 Tage | 104,462 |
| 15-30 Tage | 2,187,685 |
| 31-60 Tage | 871,788 |
| 61-90 Tage | 1,074,157 |
| 91-180 Tage | 4,067,680 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 534,801 |
| 0-3 Tage | 36,368 |
| 4-7 Tage | 26,409 |
| 8-14 Tage | 653,320 |
| 15-30 Tage | 1,663,711 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-15 | 15,575 |
| 2026-09-16 | 6,243 |
| 2026-09-17 | 5,766 |
| 2026-09-18 | 8,784 |
| 2026-09-19 | 5,140 |
| 2026-09-20 | 5,057 |
| 2026-09-21 | 5,035 |
| 2026-09-22 | 11,177 |
| 2026-09-23 | 5,138 |
| 2026-09-24 | 11,420 |
| 2026-09-25 | 5,493 |
| 2026-09-26 | 624,165 |
| 2026-09-27 | 6,324 |
| 2026-09-28 | 780 |
| 2026-09-30 | 59,819 |
| 2026-10-01 | 7,697 |
| 2026-10-02 | 1,308,803 |
| 2026-10-03 | 2,986 |
| 2026-10-04 | 6,958 |
| 2026-10-05 | 2,923 |
| 2026-10-06 | 8,316 |
| 2026-10-07 | 8,057 |
| 2026-10-08 | 7,368 |
| 2026-10-09 | 152,346 |
| 2026-10-10 | 8,271 |
| 2026-10-11 | 23,327 |
| 2026-10-12 | 33,435 |
| 2026-10-13 | 9,145 |
| 2026-10-14 | 8,177 |
| 2026-10-15 | 9,410 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **534,801** IPs. Brutto faellig in den naechsten 30 Tagen: **2,373,135**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,847,936**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-15 | 15,575 | 2,000 |
| 2026-09-16 | 6,243 | 2,000 |
| 2026-09-17 | 5,766 | 2,000 |
| 2026-09-18 | 8,784 | 2,000 |
| 2026-09-19 | 5,140 | 2,000 |
| 2026-09-20 | 5,057 | 2,000 |
| 2026-09-21 | 5,035 | 2,000 |
| 2026-09-22 | 11,177 | 2,000 |
| 2026-09-23 | 5,138 | 2,000 |
| 2026-09-24 | 11,420 | 2,000 |
| 2026-09-25 | 5,493 | 2,000 |
| 2026-09-26 | 624,165 | 2,000 |
| 2026-09-27 | 6,324 | 2,000 |
| 2026-09-28 | 780 | 2,000 |
| 2026-09-30 | 59,819 | 2,000 |
| 2026-10-01 | 7,697 | 2,000 |
| 2026-10-02 | 1,308,803 | 2,000 |
| 2026-10-03 | 2,986 | 2,000 |
| 2026-10-04 | 6,958 | 2,000 |
| 2026-10-05 | 2,923 | 2,000 |
| 2026-10-06 | 8,316 | 2,000 |
| 2026-10-07 | 8,057 | 2,000 |
| 2026-10-08 | 7,368 | 2,000 |
| 2026-10-09 | 152,346 | 2,000 |
| 2026-10-10 | 8,271 | 2,000 |
| 2026-10-11 | 23,327 | 2,000 |
| 2026-10-12 | 33,435 | 2,000 |
| 2026-10-13 | 9,145 | 2,000 |
| 2026-10-14 | 8,177 | 2,000 |
| 2026-10-15 | 9,410 | 2,000 |

> Hinweis: Der Rueckstau von 2,847,936 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,445 |
| 2026-09-23 | 13,095 |
| 2026-09-24 | 16,734 |
| 2026-09-25 | 21,004 |
| 2026-09-26 | 17,511 |
| 2026-09-27 | 15,098 |
| 2026-09-28 | 11,629 |
| 2026-09-29 | 9,391 |
| 2026-09-30 | 10,235 |
| 2026-10-01 | 16,648 |
| 2026-10-02 | 7,754 |
| 2026-10-03 | 7,363 |
| 2026-10-04 | 12,696 |
| 2026-10-05 | 17,617 |
| 2026-10-06 | 16,184 |
| 2026-10-07 | 15,115 |
| 2026-10-08 | 61,716 |
| 2026-10-09 | 224,166 |
| 2026-10-10 | 53,450 |
| 2026-10-11 | 16,082 |
| 2026-10-12 | 66,638 |
| 2026-10-13 | 1,587,669 |
| 2026-10-14 | 32,939 |
| 2026-10-15 | 41,413 |
| 2026-10-16 | 51,436 |
| 2026-10-17 | 24,398 |
| 2026-10-18 | 14,331 |
| 2026-10-19 | 22,529 |
| 2026-10-20 | 11,183 |
| 2026-10-21 | 11,160 |
| 2026-10-22 | 30,863 |
| 2026-10-23 | 50,530 |
| 2026-10-24 | 41,835 |
| 2026-10-25 | 21,700 |
| 2026-10-26 | 20,446 |
| 2026-10-27 | 20,799 |
| 2026-10-28 | 15,871 |
| 2026-10-29 | 9,760 |
| 2026-10-30 | 62,194 |
| 2026-10-31 | 88,338 |
| 2026-11-01 | 27,980 |
| 2026-11-02 | 28,965 |
| 2026-11-03 | 30,008 |
| 2026-11-04 | 29,796 |
| 2026-11-05 | 25,406 |
| 2026-11-06 | 36,842 |
| 2026-11-07 | 24,595 |
| 2026-11-08 | 26,264 |
| 2026-11-09 | 25,706 |
| 2026-11-10 | 32,899 |
| 2026-11-11 | 22,505 |
| 2026-11-12 | 20,596 |
| 2026-11-13 | 19,752 |
| 2026-11-14 | 23,101 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 191659 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
