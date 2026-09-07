# Seen-DB Expiry Forecast

Lauf: 2026-09-07 15:10 CEST (Europe/Berlin)
Gesamt: 11,190,798 IPs in seen_db.json (8,522,979 aktiv/180-Tage-Pfad, 2,667,819 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 662,390 |
| 8-14 Tage | 0 |
| 15-30 Tage | 215,730 |
| 31-60 Tage | 2,769,040 |
| 61-90 Tage | 1,027,409 |
| 91-180 Tage | 3,848,410 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 434,495 |
| 0-3 Tage | 55,098 |
| 4-7 Tage | 48,357 |
| 8-14 Tage | 52,018 |
| 15-30 Tage | 2,077,851 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-07 | 16,220 |
| 2026-09-08 | 13,074 |
| 2026-09-09 | 17,010 |
| 2026-09-10 | 8,794 |
| 2026-09-11 | 11,369 |
| 2026-09-12 | 11,956 |
| 2026-09-13 | 12,102 |
| 2026-09-14 | 12,930 |
| 2026-09-15 | 15,689 |
| 2026-09-16 | 6,283 |
| 2026-09-17 | 5,826 |
| 2026-09-18 | 8,858 |
| 2026-09-19 | 5,184 |
| 2026-09-20 | 5,097 |
| 2026-09-21 | 5,081 |
| 2026-09-22 | 11,262 |
| 2026-09-23 | 5,193 |
| 2026-09-24 | 11,474 |
| 2026-09-25 | 5,548 |
| 2026-09-26 | 624,633 |
| 2026-09-27 | 6,384 |
| 2026-09-28 | 787 |
| 2026-09-30 | 60,063 |
| 2026-10-01 | 7,770 |
| 2026-10-02 | 1,310,717 |
| 2026-10-03 | 3,026 |
| 2026-10-04 | 7,035 |
| 2026-10-05 | 3,000 |
| 2026-10-06 | 8,512 |
| 2026-10-07 | 8,343 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **434,495** IPs. Brutto faellig in den naechsten 30 Tagen: **2,229,220**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,603,715**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-07 | 16,220 | 2,000 |
| 2026-09-08 | 13,074 | 2,000 |
| 2026-09-09 | 17,010 | 2,000 |
| 2026-09-10 | 8,794 | 2,000 |
| 2026-09-11 | 11,369 | 2,000 |
| 2026-09-12 | 11,956 | 2,000 |
| 2026-09-13 | 12,102 | 2,000 |
| 2026-09-14 | 12,930 | 2,000 |
| 2026-09-15 | 15,689 | 2,000 |
| 2026-09-16 | 6,283 | 2,000 |
| 2026-09-17 | 5,826 | 2,000 |
| 2026-09-18 | 8,858 | 2,000 |
| 2026-09-19 | 5,184 | 2,000 |
| 2026-09-20 | 5,097 | 2,000 |
| 2026-09-21 | 5,081 | 2,000 |
| 2026-09-22 | 11,262 | 2,000 |
| 2026-09-23 | 5,193 | 2,000 |
| 2026-09-24 | 11,474 | 2,000 |
| 2026-09-25 | 5,548 | 2,000 |
| 2026-09-26 | 624,633 | 2,000 |
| 2026-09-27 | 6,384 | 2,000 |
| 2026-09-28 | 787 | 2,000 |
| 2026-09-30 | 60,063 | 2,000 |
| 2026-10-01 | 7,770 | 2,000 |
| 2026-10-02 | 1,310,717 | 2,000 |
| 2026-10-03 | 3,026 | 2,000 |
| 2026-10-04 | 7,035 | 2,000 |
| 2026-10-05 | 3,000 | 2,000 |
| 2026-10-06 | 8,512 | 2,000 |
| 2026-10-07 | 8,343 | 2,000 |

> Hinweis: Der Rueckstau von 2,603,715 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-08 | 662,390 |
| 2026-09-22 | 6,476 |
| 2026-09-23 | 13,174 |
| 2026-09-24 | 16,850 |
| 2026-09-25 | 21,121 |
| 2026-09-26 | 17,635 |
| 2026-09-27 | 15,218 |
| 2026-09-28 | 11,675 |
| 2026-09-29 | 9,432 |
| 2026-09-30 | 10,293 |
| 2026-10-01 | 16,721 |
| 2026-10-02 | 7,805 |
| 2026-10-03 | 7,397 |
| 2026-10-04 | 12,780 |
| 2026-10-05 | 17,699 |
| 2026-10-06 | 16,265 |
| 2026-10-07 | 15,189 |
| 2026-10-08 | 62,094 |
| 2026-10-09 | 226,096 |
| 2026-10-10 | 53,525 |
| 2026-10-11 | 16,115 |
| 2026-10-12 | 66,703 |
| 2026-10-13 | 1,591,369 |
| 2026-10-14 | 32,963 |
| 2026-10-15 | 41,448 |
| 2026-10-16 | 51,511 |
| 2026-10-17 | 24,480 |
| 2026-10-18 | 14,392 |
| 2026-10-19 | 22,713 |
| 2026-10-20 | 11,228 |
| 2026-10-21 | 11,209 |
| 2026-10-22 | 30,988 |
| 2026-10-23 | 50,625 |
| 2026-10-24 | 41,930 |
| 2026-10-25 | 21,779 |
| 2026-10-26 | 20,539 |
| 2026-10-27 | 20,895 |
| 2026-10-28 | 15,945 |
| 2026-10-29 | 9,823 |
| 2026-10-30 | 62,436 |
| 2026-10-31 | 88,475 |
| 2026-11-01 | 28,078 |
| 2026-11-02 | 29,089 |
| 2026-11-03 | 30,162 |
| 2026-11-04 | 29,951 |
| 2026-11-05 | 25,511 |
| 2026-11-06 | 36,968 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 267 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
