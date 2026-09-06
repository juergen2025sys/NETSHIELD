# Seen-DB Expiry Forecast

Lauf: 2026-09-06 12:45 CEST (Europe/Berlin)
Gesamt: 11,118,199 IPs in seen_db.json (8,455,665 aktiv/180-Tage-Pfad, 2,662,534 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 662,701 |
| 8-14 Tage | 0 |
| 15-30 Tage | 200,698 |
| 31-60 Tage | 2,748,219 |
| 61-90 Tage | 1,034,400 |
| 91-180 Tage | 3,809,647 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 414,059 |
| 0-3 Tage | 66,851 |
| 4-7 Tage | 44,271 |
| 8-14 Tage | 59,943 |
| 15-30 Tage | 2,077,410 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-06 | 20,496 |
| 2026-09-07 | 16,250 |
| 2026-09-08 | 13,086 |
| 2026-09-09 | 17,019 |
| 2026-09-10 | 8,809 |
| 2026-09-11 | 11,381 |
| 2026-09-12 | 11,972 |
| 2026-09-13 | 12,109 |
| 2026-09-14 | 12,940 |
| 2026-09-15 | 15,711 |
| 2026-09-16 | 6,292 |
| 2026-09-17 | 5,837 |
| 2026-09-18 | 8,868 |
| 2026-09-19 | 5,192 |
| 2026-09-20 | 5,103 |
| 2026-09-21 | 5,090 |
| 2026-09-22 | 11,267 |
| 2026-09-23 | 5,198 |
| 2026-09-24 | 11,477 |
| 2026-09-25 | 5,558 |
| 2026-09-26 | 624,703 |
| 2026-09-27 | 6,398 |
| 2026-09-28 | 790 |
| 2026-09-30 | 60,099 |
| 2026-10-01 | 7,780 |
| 2026-10-02 | 1,310,996 |
| 2026-10-03 | 3,029 |
| 2026-10-04 | 7,055 |
| 2026-10-05 | 3,029 |
| 2026-10-06 | 8,863 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **414,059** IPs. Brutto faellig in den naechsten 30 Tagen: **2,242,397**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,596,456**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-06 | 20,496 | 2,000 |
| 2026-09-07 | 16,250 | 2,000 |
| 2026-09-08 | 13,086 | 2,000 |
| 2026-09-09 | 17,019 | 2,000 |
| 2026-09-10 | 8,809 | 2,000 |
| 2026-09-11 | 11,381 | 2,000 |
| 2026-09-12 | 11,972 | 2,000 |
| 2026-09-13 | 12,109 | 2,000 |
| 2026-09-14 | 12,940 | 2,000 |
| 2026-09-15 | 15,711 | 2,000 |
| 2026-09-16 | 6,292 | 2,000 |
| 2026-09-17 | 5,837 | 2,000 |
| 2026-09-18 | 8,868 | 2,000 |
| 2026-09-19 | 5,192 | 2,000 |
| 2026-09-20 | 5,103 | 2,000 |
| 2026-09-21 | 5,090 | 2,000 |
| 2026-09-22 | 11,267 | 2,000 |
| 2026-09-23 | 5,198 | 2,000 |
| 2026-09-24 | 11,477 | 2,000 |
| 2026-09-25 | 5,558 | 2,000 |
| 2026-09-26 | 624,703 | 2,000 |
| 2026-09-27 | 6,398 | 2,000 |
| 2026-09-28 | 790 | 2,000 |
| 2026-09-30 | 60,099 | 2,000 |
| 2026-10-01 | 7,780 | 2,000 |
| 2026-10-02 | 1,310,996 | 2,000 |
| 2026-10-03 | 3,029 | 2,000 |
| 2026-10-04 | 7,055 | 2,000 |
| 2026-10-05 | 3,029 | 2,000 |
| 2026-10-06 | 8,863 | 2,000 |

> Hinweis: Der Rueckstau von 2,596,456 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-08 | 662,701 |
| 2026-09-22 | 6,486 |
| 2026-09-23 | 13,183 |
| 2026-09-24 | 16,865 |
| 2026-09-25 | 21,137 |
| 2026-09-26 | 17,645 |
| 2026-09-27 | 15,231 |
| 2026-09-28 | 11,683 |
| 2026-09-29 | 9,442 |
| 2026-09-30 | 10,298 |
| 2026-10-01 | 16,732 |
| 2026-10-02 | 7,810 |
| 2026-10-03 | 7,407 |
| 2026-10-04 | 12,790 |
| 2026-10-05 | 17,709 |
| 2026-10-06 | 16,280 |
| 2026-10-07 | 15,205 |
| 2026-10-08 | 62,156 |
| 2026-10-09 | 226,261 |
| 2026-10-10 | 53,542 |
| 2026-10-11 | 16,120 |
| 2026-10-12 | 66,711 |
| 2026-10-13 | 1,591,737 |
| 2026-10-14 | 32,965 |
| 2026-10-15 | 41,455 |
| 2026-10-16 | 51,522 |
| 2026-10-17 | 24,498 |
| 2026-10-18 | 14,399 |
| 2026-10-19 | 22,730 |
| 2026-10-20 | 11,237 |
| 2026-10-21 | 11,218 |
| 2026-10-22 | 31,006 |
| 2026-10-23 | 50,637 |
| 2026-10-24 | 41,949 |
| 2026-10-25 | 21,797 |
| 2026-10-26 | 20,553 |
| 2026-10-27 | 20,907 |
| 2026-10-28 | 15,952 |
| 2026-10-29 | 9,831 |
| 2026-10-30 | 62,471 |
| 2026-10-31 | 88,492 |
| 2026-11-01 | 28,089 |
| 2026-11-02 | 29,101 |
| 2026-11-03 | 30,179 |
| 2026-11-04 | 29,972 |
| 2026-11-05 | 25,527 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 247 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
