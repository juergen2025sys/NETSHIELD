# Seen-DB Expiry Forecast

Lauf: 2026-09-08 00:45 CEST (Europe/Berlin)
Gesamt: 11,230,473 IPs in seen_db.json (8,559,055 aktiv/180-Tage-Pfad, 2,671,418 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 662,324 |
| 8-14 Tage | 0 |
| 15-30 Tage | 215,704 |
| 31-60 Tage | 2,768,664 |
| 61-90 Tage | 1,027,266 |
| 91-180 Tage | 3,885,097 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 434,474 |
| 0-3 Tage | 55,083 |
| 4-7 Tage | 48,341 |
| 8-14 Tage | 52,004 |
| 15-30 Tage | 2,081,516 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-07 | 16,213 |
| 2026-09-08 | 13,069 |
| 2026-09-09 | 17,010 |
| 2026-09-10 | 8,791 |
| 2026-09-11 | 11,366 |
| 2026-09-12 | 11,952 |
| 2026-09-13 | 12,096 |
| 2026-09-14 | 12,927 |
| 2026-09-15 | 15,683 |
| 2026-09-16 | 6,280 |
| 2026-09-17 | 5,825 |
| 2026-09-18 | 8,856 |
| 2026-09-19 | 5,183 |
| 2026-09-20 | 5,096 |
| 2026-09-21 | 5,081 |
| 2026-09-22 | 11,262 |
| 2026-09-23 | 5,193 |
| 2026-09-24 | 11,473 |
| 2026-09-25 | 5,543 |
| 2026-09-26 | 624,619 |
| 2026-09-27 | 6,382 |
| 2026-09-28 | 787 |
| 2026-09-30 | 60,052 |
| 2026-10-01 | 7,767 |
| 2026-10-02 | 1,310,664 |
| 2026-10-03 | 3,024 |
| 2026-10-04 | 7,032 |
| 2026-10-05 | 2,997 |
| 2026-10-06 | 8,500 |
| 2026-10-07 | 8,309 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **434,474** IPs. Brutto faellig in den naechsten 30 Tagen: **2,229,032**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,603,506**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-07 | 16,213 | 2,000 |
| 2026-09-08 | 13,069 | 2,000 |
| 2026-09-09 | 17,010 | 2,000 |
| 2026-09-10 | 8,791 | 2,000 |
| 2026-09-11 | 11,366 | 2,000 |
| 2026-09-12 | 11,952 | 2,000 |
| 2026-09-13 | 12,096 | 2,000 |
| 2026-09-14 | 12,927 | 2,000 |
| 2026-09-15 | 15,683 | 2,000 |
| 2026-09-16 | 6,280 | 2,000 |
| 2026-09-17 | 5,825 | 2,000 |
| 2026-09-18 | 8,856 | 2,000 |
| 2026-09-19 | 5,183 | 2,000 |
| 2026-09-20 | 5,096 | 2,000 |
| 2026-09-21 | 5,081 | 2,000 |
| 2026-09-22 | 11,262 | 2,000 |
| 2026-09-23 | 5,193 | 2,000 |
| 2026-09-24 | 11,473 | 2,000 |
| 2026-09-25 | 5,543 | 2,000 |
| 2026-09-26 | 624,619 | 2,000 |
| 2026-09-27 | 6,382 | 2,000 |
| 2026-09-28 | 787 | 2,000 |
| 2026-09-30 | 60,052 | 2,000 |
| 2026-10-01 | 7,767 | 2,000 |
| 2026-10-02 | 1,310,664 | 2,000 |
| 2026-10-03 | 3,024 | 2,000 |
| 2026-10-04 | 7,032 | 2,000 |
| 2026-10-05 | 2,997 | 2,000 |
| 2026-10-06 | 8,500 | 2,000 |
| 2026-10-07 | 8,309 | 2,000 |

> Hinweis: Der Rueckstau von 2,603,506 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-08 | 662,324 |
| 2026-09-22 | 6,475 |
| 2026-09-23 | 13,172 |
| 2026-09-24 | 16,849 |
| 2026-09-25 | 21,119 |
| 2026-09-26 | 17,633 |
| 2026-09-27 | 15,217 |
| 2026-09-28 | 11,673 |
| 2026-09-29 | 9,432 |
| 2026-09-30 | 10,290 |
| 2026-10-01 | 16,719 |
| 2026-10-02 | 7,805 |
| 2026-10-03 | 7,395 |
| 2026-10-04 | 12,780 |
| 2026-10-05 | 17,697 |
| 2026-10-06 | 16,264 |
| 2026-10-07 | 15,184 |
| 2026-10-08 | 62,089 |
| 2026-10-09 | 226,047 |
| 2026-10-10 | 53,524 |
| 2026-10-11 | 16,115 |
| 2026-10-12 | 66,701 |
| 2026-10-13 | 1,591,171 |
| 2026-10-14 | 32,963 |
| 2026-10-15 | 41,448 |
| 2026-10-16 | 51,510 |
| 2026-10-17 | 24,473 |
| 2026-10-18 | 14,390 |
| 2026-10-19 | 22,697 |
| 2026-10-20 | 11,224 |
| 2026-10-21 | 11,206 |
| 2026-10-22 | 30,981 |
| 2026-10-23 | 50,617 |
| 2026-10-24 | 41,925 |
| 2026-10-25 | 21,775 |
| 2026-10-26 | 20,537 |
| 2026-10-27 | 20,890 |
| 2026-10-28 | 15,945 |
| 2026-10-29 | 9,821 |
| 2026-10-30 | 62,426 |
| 2026-10-31 | 88,465 |
| 2026-11-01 | 28,072 |
| 2026-11-02 | 29,084 |
| 2026-11-03 | 30,155 |
| 2026-11-04 | 29,945 |
| 2026-11-05 | 25,504 |
| 2026-11-06 | 36,964 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 267 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
