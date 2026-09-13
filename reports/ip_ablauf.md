# Seen-DB Expiry Forecast

Lauf: 2026-09-13 07:18 CEST (Europe/Berlin)
Gesamt: 11,084,039 IPs in seen_db.json (8,184,540 aktiv/180-Tage-Pfad, 2,899,499 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 0 |
| 8-14 Tage | 90,023 |
| 15-30 Tage | 2,135,863 |
| 31-60 Tage | 904,063 |
| 61-90 Tage | 1,070,095 |
| 91-180 Tage | 3,984,496 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 510,812 |
| 0-3 Tage | 46,760 |
| 4-7 Tage | 24,806 |
| 8-14 Tage | 668,999 |
| 15-30 Tage | 1,648,122 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-13 | 12,044 |
| 2026-09-14 | 12,856 |
| 2026-09-15 | 15,613 |
| 2026-09-16 | 6,247 |
| 2026-09-17 | 5,781 |
| 2026-09-18 | 8,802 |
| 2026-09-19 | 5,156 |
| 2026-09-20 | 5,067 |
| 2026-09-21 | 5,055 |
| 2026-09-22 | 11,199 |
| 2026-09-23 | 5,162 |
| 2026-09-24 | 11,440 |
| 2026-09-25 | 5,508 |
| 2026-09-26 | 624,292 |
| 2026-09-27 | 6,343 |
| 2026-09-28 | 783 |
| 2026-09-30 | 59,892 |
| 2026-10-01 | 7,721 |
| 2026-10-02 | 1,309,276 |
| 2026-10-03 | 2,997 |
| 2026-10-04 | 6,978 |
| 2026-10-05 | 2,934 |
| 2026-10-06 | 8,340 |
| 2026-10-07 | 8,097 |
| 2026-10-08 | 7,386 |
| 2026-10-09 | 152,498 |
| 2026-10-10 | 8,299 |
| 2026-10-11 | 23,406 |
| 2026-10-12 | 33,514 |
| 2026-10-13 | 9,594 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **510,812** IPs. Brutto faellig in den naechsten 30 Tagen: **2,382,280**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,833,092**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-13 | 12,044 | 2,000 |
| 2026-09-14 | 12,856 | 2,000 |
| 2026-09-15 | 15,613 | 2,000 |
| 2026-09-16 | 6,247 | 2,000 |
| 2026-09-17 | 5,781 | 2,000 |
| 2026-09-18 | 8,802 | 2,000 |
| 2026-09-19 | 5,156 | 2,000 |
| 2026-09-20 | 5,067 | 2,000 |
| 2026-09-21 | 5,055 | 2,000 |
| 2026-09-22 | 11,199 | 2,000 |
| 2026-09-23 | 5,162 | 2,000 |
| 2026-09-24 | 11,440 | 2,000 |
| 2026-09-25 | 5,508 | 2,000 |
| 2026-09-26 | 624,292 | 2,000 |
| 2026-09-27 | 6,343 | 2,000 |
| 2026-09-28 | 783 | 2,000 |
| 2026-09-30 | 59,892 | 2,000 |
| 2026-10-01 | 7,721 | 2,000 |
| 2026-10-02 | 1,309,276 | 2,000 |
| 2026-10-03 | 2,997 | 2,000 |
| 2026-10-04 | 6,978 | 2,000 |
| 2026-10-05 | 2,934 | 2,000 |
| 2026-10-06 | 8,340 | 2,000 |
| 2026-10-07 | 8,097 | 2,000 |
| 2026-10-08 | 7,386 | 2,000 |
| 2026-10-09 | 152,498 | 2,000 |
| 2026-10-10 | 8,299 | 2,000 |
| 2026-10-11 | 23,406 | 2,000 |
| 2026-10-12 | 33,514 | 2,000 |
| 2026-10-13 | 9,594 | 2,000 |

> Hinweis: Der Rueckstau von 2,833,092 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,453 |
| 2026-09-23 | 13,106 |
| 2026-09-24 | 16,757 |
| 2026-09-25 | 21,029 |
| 2026-09-26 | 17,540 |
| 2026-09-27 | 15,138 |
| 2026-09-28 | 11,638 |
| 2026-09-29 | 9,398 |
| 2026-09-30 | 10,249 |
| 2026-10-01 | 16,668 |
| 2026-10-02 | 7,765 |
| 2026-10-03 | 7,373 |
| 2026-10-04 | 12,715 |
| 2026-10-05 | 17,635 |
| 2026-10-06 | 16,213 |
| 2026-10-07 | 15,139 |
| 2026-10-08 | 61,817 |
| 2026-10-09 | 224,560 |
| 2026-10-10 | 53,471 |
| 2026-10-11 | 16,086 |
| 2026-10-12 | 66,651 |
| 2026-10-13 | 1,588,485 |
| 2026-10-14 | 32,946 |
| 2026-10-15 | 41,428 |
| 2026-10-16 | 51,458 |
| 2026-10-17 | 24,418 |
| 2026-10-18 | 14,348 |
| 2026-10-19 | 22,562 |
| 2026-10-20 | 11,193 |
| 2026-10-21 | 11,165 |
| 2026-10-22 | 30,897 |
| 2026-10-23 | 50,565 |
| 2026-10-24 | 41,866 |
| 2026-10-25 | 21,723 |
| 2026-10-26 | 20,477 |
| 2026-10-27 | 20,823 |
| 2026-10-28 | 15,888 |
| 2026-10-29 | 9,774 |
| 2026-10-30 | 62,246 |
| 2026-10-31 | 88,374 |
| 2026-11-01 | 28,011 |
| 2026-11-02 | 28,999 |
| 2026-11-03 | 30,046 |
| 2026-11-04 | 29,841 |
| 2026-11-05 | 25,435 |
| 2026-11-06 | 36,870 |
| 2026-11-07 | 24,616 |
| 2026-11-08 | 26,283 |
| 2026-11-09 | 25,732 |
| 2026-11-10 | 32,937 |
| 2026-11-11 | 22,532 |
| 2026-11-12 | 20,610 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 190758 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
