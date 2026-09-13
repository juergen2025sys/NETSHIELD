# Seen-DB Expiry Forecast

Lauf: 2026-09-14 01:26 CEST (Europe/Berlin)
Gesamt: 11,106,292 IPs in seen_db.json (8,205,985 aktiv/180-Tage-Pfad, 2,900,307 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 0 |
| 8-14 Tage | 89,970 |
| 15-30 Tage | 2,135,422 |
| 31-60 Tage | 903,773 |
| 61-90 Tage | 1,069,832 |
| 91-180 Tage | 4,006,988 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 510,534 |
| 0-3 Tage | 46,731 |
| 4-7 Tage | 24,787 |
| 8-14 Tage | 668,925 |
| 15-30 Tage | 1,649,330 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-13 | 12,034 |
| 2026-09-14 | 12,845 |
| 2026-09-15 | 15,608 |
| 2026-09-16 | 6,244 |
| 2026-09-17 | 5,776 |
| 2026-09-18 | 8,797 |
| 2026-09-19 | 5,151 |
| 2026-09-20 | 5,063 |
| 2026-09-21 | 5,049 |
| 2026-09-22 | 11,191 |
| 2026-09-23 | 5,157 |
| 2026-09-24 | 11,434 |
| 2026-09-25 | 5,505 |
| 2026-09-26 | 624,249 |
| 2026-09-27 | 6,340 |
| 2026-09-28 | 783 |
| 2026-09-30 | 59,880 |
| 2026-10-01 | 7,717 |
| 2026-10-02 | 1,309,101 |
| 2026-10-03 | 2,994 |
| 2026-10-04 | 6,976 |
| 2026-10-05 | 2,930 |
| 2026-10-06 | 8,337 |
| 2026-10-07 | 8,087 |
| 2026-10-08 | 7,379 |
| 2026-10-09 | 152,447 |
| 2026-10-10 | 8,293 |
| 2026-10-11 | 23,373 |
| 2026-10-12 | 33,474 |
| 2026-10-13 | 9,263 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **510,534** IPs. Brutto faellig in den naechsten 30 Tagen: **2,381,477**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,832,011**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-13 | 12,034 | 2,000 |
| 2026-09-14 | 12,845 | 2,000 |
| 2026-09-15 | 15,608 | 2,000 |
| 2026-09-16 | 6,244 | 2,000 |
| 2026-09-17 | 5,776 | 2,000 |
| 2026-09-18 | 8,797 | 2,000 |
| 2026-09-19 | 5,151 | 2,000 |
| 2026-09-20 | 5,063 | 2,000 |
| 2026-09-21 | 5,049 | 2,000 |
| 2026-09-22 | 11,191 | 2,000 |
| 2026-09-23 | 5,157 | 2,000 |
| 2026-09-24 | 11,434 | 2,000 |
| 2026-09-25 | 5,505 | 2,000 |
| 2026-09-26 | 624,249 | 2,000 |
| 2026-09-27 | 6,340 | 2,000 |
| 2026-09-28 | 783 | 2,000 |
| 2026-09-30 | 59,880 | 2,000 |
| 2026-10-01 | 7,717 | 2,000 |
| 2026-10-02 | 1,309,101 | 2,000 |
| 2026-10-03 | 2,994 | 2,000 |
| 2026-10-04 | 6,976 | 2,000 |
| 2026-10-05 | 2,930 | 2,000 |
| 2026-10-06 | 8,337 | 2,000 |
| 2026-10-07 | 8,087 | 2,000 |
| 2026-10-08 | 7,379 | 2,000 |
| 2026-10-09 | 152,447 | 2,000 |
| 2026-10-10 | 8,293 | 2,000 |
| 2026-10-11 | 23,373 | 2,000 |
| 2026-10-12 | 33,474 | 2,000 |
| 2026-10-13 | 9,263 | 2,000 |

> Hinweis: Der Rueckstau von 2,832,011 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,450 |
| 2026-09-23 | 13,104 |
| 2026-09-24 | 16,746 |
| 2026-09-25 | 21,019 |
| 2026-09-26 | 17,525 |
| 2026-09-27 | 15,126 |
| 2026-09-28 | 11,634 |
| 2026-09-29 | 9,393 |
| 2026-09-30 | 10,245 |
| 2026-10-01 | 16,657 |
| 2026-10-02 | 7,763 |
| 2026-10-03 | 7,371 |
| 2026-10-04 | 12,703 |
| 2026-10-05 | 17,629 |
| 2026-10-06 | 16,201 |
| 2026-10-07 | 15,134 |
| 2026-10-08 | 61,773 |
| 2026-10-09 | 224,445 |
| 2026-10-10 | 53,467 |
| 2026-10-11 | 16,084 |
| 2026-10-12 | 66,647 |
| 2026-10-13 | 1,588,276 |
| 2026-10-14 | 32,943 |
| 2026-10-15 | 41,422 |
| 2026-10-16 | 51,450 |
| 2026-10-17 | 24,416 |
| 2026-10-18 | 14,339 |
| 2026-10-19 | 22,548 |
| 2026-10-20 | 11,189 |
| 2026-10-21 | 11,163 |
| 2026-10-22 | 30,881 |
| 2026-10-23 | 50,551 |
| 2026-10-24 | 41,855 |
| 2026-10-25 | 21,715 |
| 2026-10-26 | 20,464 |
| 2026-10-27 | 20,814 |
| 2026-10-28 | 15,877 |
| 2026-10-29 | 9,763 |
| 2026-10-30 | 62,229 |
| 2026-10-31 | 88,358 |
| 2026-11-01 | 28,003 |
| 2026-11-02 | 28,987 |
| 2026-11-03 | 30,029 |
| 2026-11-04 | 29,825 |
| 2026-11-05 | 25,424 |
| 2026-11-06 | 36,863 |
| 2026-11-07 | 24,610 |
| 2026-11-08 | 26,277 |
| 2026-11-09 | 25,725 |
| 2026-11-10 | 32,926 |
| 2026-11-11 | 22,523 |
| 2026-11-12 | 20,604 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 190850 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
