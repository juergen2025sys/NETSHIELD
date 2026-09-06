# Seen-DB Expiry Forecast

Lauf: 2026-09-07 01:44 CEST (Europe/Berlin)
Gesamt: 11,158,149 IPs in seen_db.json (8,493,541 aktiv/180-Tage-Pfad, 2,664,608 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 662,559 |
| 8-14 Tage | 0 |
| 15-30 Tage | 200,600 |
| 31-60 Tage | 2,747,664 |
| 61-90 Tage | 1,034,151 |
| 91-180 Tage | 3,848,567 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 414,033 |
| 0-3 Tage | 66,803 |
| 4-7 Tage | 44,247 |
| 8-14 Tage | 59,899 |
| 15-30 Tage | 2,079,626 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-06 | 20,488 |
| 2026-09-07 | 16,228 |
| 2026-09-08 | 13,076 |
| 2026-09-09 | 17,011 |
| 2026-09-10 | 8,800 |
| 2026-09-11 | 11,374 |
| 2026-09-12 | 11,965 |
| 2026-09-13 | 12,108 |
| 2026-09-14 | 12,934 |
| 2026-09-15 | 15,701 |
| 2026-09-16 | 6,287 |
| 2026-09-17 | 5,829 |
| 2026-09-18 | 8,862 |
| 2026-09-19 | 5,187 |
| 2026-09-20 | 5,099 |
| 2026-09-21 | 5,085 |
| 2026-09-22 | 11,264 |
| 2026-09-23 | 5,196 |
| 2026-09-24 | 11,475 |
| 2026-09-25 | 5,552 |
| 2026-09-26 | 624,677 |
| 2026-09-27 | 6,391 |
| 2026-09-28 | 789 |
| 2026-09-30 | 60,076 |
| 2026-10-01 | 7,773 |
| 2026-10-02 | 1,310,856 |
| 2026-10-03 | 3,026 |
| 2026-10-04 | 7,045 |
| 2026-10-05 | 3,010 |
| 2026-10-06 | 8,538 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **414,033** IPs. Brutto faellig in den naechsten 30 Tagen: **2,241,702**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,595,735**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-06 | 20,488 | 2,000 |
| 2026-09-07 | 16,228 | 2,000 |
| 2026-09-08 | 13,076 | 2,000 |
| 2026-09-09 | 17,011 | 2,000 |
| 2026-09-10 | 8,800 | 2,000 |
| 2026-09-11 | 11,374 | 2,000 |
| 2026-09-12 | 11,965 | 2,000 |
| 2026-09-13 | 12,108 | 2,000 |
| 2026-09-14 | 12,934 | 2,000 |
| 2026-09-15 | 15,701 | 2,000 |
| 2026-09-16 | 6,287 | 2,000 |
| 2026-09-17 | 5,829 | 2,000 |
| 2026-09-18 | 8,862 | 2,000 |
| 2026-09-19 | 5,187 | 2,000 |
| 2026-09-20 | 5,099 | 2,000 |
| 2026-09-21 | 5,085 | 2,000 |
| 2026-09-22 | 11,264 | 2,000 |
| 2026-09-23 | 5,196 | 2,000 |
| 2026-09-24 | 11,475 | 2,000 |
| 2026-09-25 | 5,552 | 2,000 |
| 2026-09-26 | 624,677 | 2,000 |
| 2026-09-27 | 6,391 | 2,000 |
| 2026-09-28 | 789 | 2,000 |
| 2026-09-30 | 60,076 | 2,000 |
| 2026-10-01 | 7,773 | 2,000 |
| 2026-10-02 | 1,310,856 | 2,000 |
| 2026-10-03 | 3,026 | 2,000 |
| 2026-10-04 | 7,045 | 2,000 |
| 2026-10-05 | 3,010 | 2,000 |
| 2026-10-06 | 8,538 | 2,000 |

> Hinweis: Der Rueckstau von 2,595,735 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-08 | 662,559 |
| 2026-09-22 | 6,481 |
| 2026-09-23 | 13,177 |
| 2026-09-24 | 16,859 |
| 2026-09-25 | 21,126 |
| 2026-09-26 | 17,641 |
| 2026-09-27 | 15,221 |
| 2026-09-28 | 11,679 |
| 2026-09-29 | 9,434 |
| 2026-09-30 | 10,295 |
| 2026-10-01 | 16,725 |
| 2026-10-02 | 7,806 |
| 2026-10-03 | 7,401 |
| 2026-10-04 | 12,783 |
| 2026-10-05 | 17,701 |
| 2026-10-06 | 16,271 |
| 2026-10-07 | 15,198 |
| 2026-10-08 | 62,128 |
| 2026-10-09 | 226,174 |
| 2026-10-10 | 53,530 |
| 2026-10-11 | 16,117 |
| 2026-10-12 | 66,707 |
| 2026-10-13 | 1,591,490 |
| 2026-10-14 | 32,963 |
| 2026-10-15 | 41,451 |
| 2026-10-16 | 51,518 |
| 2026-10-17 | 24,489 |
| 2026-10-18 | 14,394 |
| 2026-10-19 | 22,720 |
| 2026-10-20 | 11,234 |
| 2026-10-21 | 11,212 |
| 2026-10-22 | 30,995 |
| 2026-10-23 | 50,630 |
| 2026-10-24 | 41,942 |
| 2026-10-25 | 21,790 |
| 2026-10-26 | 20,549 |
| 2026-10-27 | 20,899 |
| 2026-10-28 | 15,950 |
| 2026-10-29 | 9,828 |
| 2026-10-30 | 62,450 |
| 2026-10-31 | 88,479 |
| 2026-11-01 | 28,084 |
| 2026-11-02 | 29,095 |
| 2026-11-03 | 30,168 |
| 2026-11-04 | 29,958 |
| 2026-11-05 | 25,522 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 247 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
