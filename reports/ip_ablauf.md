# Seen-DB Expiry Forecast

Lauf: 2026-09-06 21:27 CEST (Europe/Berlin)
Gesamt: 11,150,438 IPs in seen_db.json (8,486,026 aktiv/180-Tage-Pfad, 2,664,412 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 662,577 |
| 8-14 Tage | 0 |
| 15-30 Tage | 200,616 |
| 31-60 Tage | 2,747,795 |
| 61-90 Tage | 1,034,208 |
| 91-180 Tage | 3,840,830 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 414,042 |
| 0-3 Tage | 66,810 |
| 4-7 Tage | 44,251 |
| 8-14 Tage | 59,907 |
| 15-30 Tage | 2,079,402 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-06 | 20,489 |
| 2026-09-07 | 16,231 |
| 2026-09-08 | 13,078 |
| 2026-09-09 | 17,012 |
| 2026-09-10 | 8,802 |
| 2026-09-11 | 11,374 |
| 2026-09-12 | 11,967 |
| 2026-09-13 | 12,108 |
| 2026-09-14 | 12,935 |
| 2026-09-15 | 15,704 |
| 2026-09-16 | 6,288 |
| 2026-09-17 | 5,829 |
| 2026-09-18 | 8,863 |
| 2026-09-19 | 5,188 |
| 2026-09-20 | 5,100 |
| 2026-09-21 | 5,085 |
| 2026-09-22 | 11,266 |
| 2026-09-23 | 5,196 |
| 2026-09-24 | 11,475 |
| 2026-09-25 | 5,552 |
| 2026-09-26 | 624,684 |
| 2026-09-27 | 6,392 |
| 2026-09-28 | 789 |
| 2026-09-30 | 60,080 |
| 2026-10-01 | 7,774 |
| 2026-10-02 | 1,310,877 |
| 2026-10-03 | 3,027 |
| 2026-10-04 | 7,048 |
| 2026-10-05 | 3,013 |
| 2026-10-06 | 8,549 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **414,042** IPs. Brutto faellig in den naechsten 30 Tagen: **2,241,775**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,595,817**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-06 | 20,489 | 2,000 |
| 2026-09-07 | 16,231 | 2,000 |
| 2026-09-08 | 13,078 | 2,000 |
| 2026-09-09 | 17,012 | 2,000 |
| 2026-09-10 | 8,802 | 2,000 |
| 2026-09-11 | 11,374 | 2,000 |
| 2026-09-12 | 11,967 | 2,000 |
| 2026-09-13 | 12,108 | 2,000 |
| 2026-09-14 | 12,935 | 2,000 |
| 2026-09-15 | 15,704 | 2,000 |
| 2026-09-16 | 6,288 | 2,000 |
| 2026-09-17 | 5,829 | 2,000 |
| 2026-09-18 | 8,863 | 2,000 |
| 2026-09-19 | 5,188 | 2,000 |
| 2026-09-20 | 5,100 | 2,000 |
| 2026-09-21 | 5,085 | 2,000 |
| 2026-09-22 | 11,266 | 2,000 |
| 2026-09-23 | 5,196 | 2,000 |
| 2026-09-24 | 11,475 | 2,000 |
| 2026-09-25 | 5,552 | 2,000 |
| 2026-09-26 | 624,684 | 2,000 |
| 2026-09-27 | 6,392 | 2,000 |
| 2026-09-28 | 789 | 2,000 |
| 2026-09-30 | 60,080 | 2,000 |
| 2026-10-01 | 7,774 | 2,000 |
| 2026-10-02 | 1,310,877 | 2,000 |
| 2026-10-03 | 3,027 | 2,000 |
| 2026-10-04 | 7,048 | 2,000 |
| 2026-10-05 | 3,013 | 2,000 |
| 2026-10-06 | 8,549 | 2,000 |

> Hinweis: Der Rueckstau von 2,595,817 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-08 | 662,577 |
| 2026-09-22 | 6,482 |
| 2026-09-23 | 13,178 |
| 2026-09-24 | 16,859 |
| 2026-09-25 | 21,127 |
| 2026-09-26 | 17,641 |
| 2026-09-27 | 15,222 |
| 2026-09-28 | 11,679 |
| 2026-09-29 | 9,435 |
| 2026-09-30 | 10,296 |
| 2026-10-01 | 16,727 |
| 2026-10-02 | 7,807 |
| 2026-10-03 | 7,402 |
| 2026-10-04 | 12,783 |
| 2026-10-05 | 17,704 |
| 2026-10-06 | 16,274 |
| 2026-10-07 | 15,198 |
| 2026-10-08 | 62,133 |
| 2026-10-09 | 226,190 |
| 2026-10-10 | 53,533 |
| 2026-10-11 | 16,118 |
| 2026-10-12 | 66,708 |
| 2026-10-13 | 1,591,565 |
| 2026-10-14 | 32,963 |
| 2026-10-15 | 41,451 |
| 2026-10-16 | 51,518 |
| 2026-10-17 | 24,493 |
| 2026-10-18 | 14,395 |
| 2026-10-19 | 22,723 |
| 2026-10-20 | 11,235 |
| 2026-10-21 | 11,212 |
| 2026-10-22 | 30,999 |
| 2026-10-23 | 50,630 |
| 2026-10-24 | 41,943 |
| 2026-10-25 | 21,792 |
| 2026-10-26 | 20,550 |
| 2026-10-27 | 20,901 |
| 2026-10-28 | 15,950 |
| 2026-10-29 | 9,828 |
| 2026-10-30 | 62,453 |
| 2026-10-31 | 88,479 |
| 2026-11-01 | 28,085 |
| 2026-11-02 | 29,096 |
| 2026-11-03 | 30,170 |
| 2026-11-04 | 29,962 |
| 2026-11-05 | 25,522 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 247 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
