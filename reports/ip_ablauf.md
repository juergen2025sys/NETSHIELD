# Seen-DB Expiry Forecast

Lauf: 2026-09-10 13:07 CEST (Europe/Berlin)
Gesamt: 10,860,609 IPs in seen_db.json (8,025,973 aktiv/180-Tage-Pfad, 2,834,636 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 0 |
| 8-14 Tage | 36,399 |
| 15-30 Tage | 519,709 |
| 31-60 Tage | 2,501,601 |
| 61-90 Tage | 1,069,266 |
| 91-180 Tage | 3,898,998 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 479,901 |
| 0-3 Tage | 44,075 |
| 4-7 Tage | 40,593 |
| 8-14 Tage | 51,978 |
| 15-30 Tage | 2,218,089 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-10 | 8,752 |
| 2026-09-11 | 11,323 |
| 2026-09-12 | 11,926 |
| 2026-09-13 | 12,074 |
| 2026-09-14 | 12,887 |
| 2026-09-15 | 15,644 |
| 2026-09-16 | 6,261 |
| 2026-09-17 | 5,801 |
| 2026-09-18 | 8,817 |
| 2026-09-19 | 5,166 |
| 2026-09-20 | 5,083 |
| 2026-09-21 | 5,068 |
| 2026-09-22 | 11,220 |
| 2026-09-23 | 5,176 |
| 2026-09-24 | 11,448 |
| 2026-09-25 | 5,523 |
| 2026-09-26 | 624,454 |
| 2026-09-27 | 6,357 |
| 2026-09-28 | 784 |
| 2026-09-30 | 59,977 |
| 2026-10-01 | 7,742 |
| 2026-10-02 | 1,309,895 |
| 2026-10-03 | 3,006 |
| 2026-10-04 | 7,004 |
| 2026-10-05 | 2,954 |
| 2026-10-06 | 8,371 |
| 2026-10-07 | 8,143 |
| 2026-10-08 | 7,415 |
| 2026-10-09 | 152,736 |
| 2026-10-10 | 8,787 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **479,901** IPs. Brutto faellig in den naechsten 30 Tagen: **2,349,794**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,769,695**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-10 | 8,752 | 2,000 |
| 2026-09-11 | 11,323 | 2,000 |
| 2026-09-12 | 11,926 | 2,000 |
| 2026-09-13 | 12,074 | 2,000 |
| 2026-09-14 | 12,887 | 2,000 |
| 2026-09-15 | 15,644 | 2,000 |
| 2026-09-16 | 6,261 | 2,000 |
| 2026-09-17 | 5,801 | 2,000 |
| 2026-09-18 | 8,817 | 2,000 |
| 2026-09-19 | 5,166 | 2,000 |
| 2026-09-20 | 5,083 | 2,000 |
| 2026-09-21 | 5,068 | 2,000 |
| 2026-09-22 | 11,220 | 2,000 |
| 2026-09-23 | 5,176 | 2,000 |
| 2026-09-24 | 11,448 | 2,000 |
| 2026-09-25 | 5,523 | 2,000 |
| 2026-09-26 | 624,454 | 2,000 |
| 2026-09-27 | 6,357 | 2,000 |
| 2026-09-28 | 784 | 2,000 |
| 2026-09-30 | 59,977 | 2,000 |
| 2026-10-01 | 7,742 | 2,000 |
| 2026-10-02 | 1,309,895 | 2,000 |
| 2026-10-03 | 3,006 | 2,000 |
| 2026-10-04 | 7,004 | 2,000 |
| 2026-10-05 | 2,954 | 2,000 |
| 2026-10-06 | 8,371 | 2,000 |
| 2026-10-07 | 8,143 | 2,000 |
| 2026-10-08 | 7,415 | 2,000 |
| 2026-10-09 | 152,736 | 2,000 |
| 2026-10-10 | 8,787 | 2,000 |

> Hinweis: Der Rueckstau von 2,769,695 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,467 |
| 2026-09-23 | 13,135 |
| 2026-09-24 | 16,797 |
| 2026-09-25 | 21,086 |
| 2026-09-26 | 17,586 |
| 2026-09-27 | 15,182 |
| 2026-09-28 | 11,653 |
| 2026-09-29 | 9,413 |
| 2026-09-30 | 10,272 |
| 2026-10-01 | 16,691 |
| 2026-10-02 | 7,785 |
| 2026-10-03 | 7,386 |
| 2026-10-04 | 12,747 |
| 2026-10-05 | 17,667 |
| 2026-10-06 | 16,241 |
| 2026-10-07 | 15,160 |
| 2026-10-08 | 61,948 |
| 2026-10-09 | 225,387 |
| 2026-10-10 | 53,505 |
| 2026-10-11 | 16,098 |
| 2026-10-12 | 66,678 |
| 2026-10-13 | 1,589,913 |
| 2026-10-14 | 32,953 |
| 2026-10-15 | 41,442 |
| 2026-10-16 | 51,483 |
| 2026-10-17 | 24,443 |
| 2026-10-18 | 14,368 |
| 2026-10-19 | 22,632 |
| 2026-10-20 | 11,209 |
| 2026-10-21 | 11,189 |
| 2026-10-22 | 30,935 |
| 2026-10-23 | 50,590 |
| 2026-10-24 | 41,894 |
| 2026-10-25 | 21,749 |
| 2026-10-26 | 20,498 |
| 2026-10-27 | 20,861 |
| 2026-10-28 | 15,925 |
| 2026-10-29 | 9,798 |
| 2026-10-30 | 62,338 |
| 2026-10-31 | 88,417 |
| 2026-11-01 | 28,038 |
| 2026-11-02 | 29,039 |
| 2026-11-03 | 30,100 |
| 2026-11-04 | 29,890 |
| 2026-11-05 | 25,471 |
| 2026-11-06 | 36,914 |
| 2026-11-07 | 24,643 |
| 2026-11-08 | 26,320 |
| 2026-11-09 | 25,773 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 143646 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
