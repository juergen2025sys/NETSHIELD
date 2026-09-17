# Seen-DB Expiry Forecast

Lauf: 2026-09-17 18:48 CEST (Europe/Berlin)
Gesamt: 11,400,539 IPs in seen_db.json (8,461,263 aktiv/180-Tage-Pfad, 2,939,276 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 36,212 |
| 8-14 Tage | 101,335 |
| 15-30 Tage | 2,234,992 |
| 31-60 Tage | 830,648 |
| 61-90 Tage | 1,080,856 |
| 91-180 Tage | 4,177,220 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 555,907 |
| 0-3 Tage | 24,686 |
| 4-7 Tage | 32,723 |
| 8-14 Tage | 704,025 |
| 15-30 Tage | 1,621,935 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-17 | 5,750 |
| 2026-09-18 | 8,760 |
| 2026-09-19 | 5,131 |
| 2026-09-20 | 5,045 |
| 2026-09-21 | 5,026 |
| 2026-09-22 | 11,160 |
| 2026-09-23 | 5,126 |
| 2026-09-24 | 11,411 |
| 2026-09-25 | 5,479 |
| 2026-09-26 | 624,029 |
| 2026-09-27 | 6,300 |
| 2026-09-28 | 778 |
| 2026-09-30 | 59,760 |
| 2026-10-01 | 7,679 |
| 2026-10-02 | 1,308,073 |
| 2026-10-03 | 2,982 |
| 2026-10-04 | 6,936 |
| 2026-10-05 | 2,917 |
| 2026-10-06 | 8,302 |
| 2026-10-07 | 8,029 |
| 2026-10-08 | 7,353 |
| 2026-10-09 | 152,139 |
| 2026-10-10 | 8,236 |
| 2026-10-11 | 23,246 |
| 2026-10-12 | 33,378 |
| 2026-10-13 | 9,088 |
| 2026-10-14 | 8,130 |
| 2026-10-15 | 8,936 |
| 2026-10-16 | 16,321 |
| 2026-10-17 | 10,761 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **555,907** IPs. Brutto faellig in den naechsten 30 Tagen: **2,376,261**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,872,168**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-17 | 5,750 | 2,000 |
| 2026-09-18 | 8,760 | 2,000 |
| 2026-09-19 | 5,131 | 2,000 |
| 2026-09-20 | 5,045 | 2,000 |
| 2026-09-21 | 5,026 | 2,000 |
| 2026-09-22 | 11,160 | 2,000 |
| 2026-09-23 | 5,126 | 2,000 |
| 2026-09-24 | 11,411 | 2,000 |
| 2026-09-25 | 5,479 | 2,000 |
| 2026-09-26 | 624,029 | 2,000 |
| 2026-09-27 | 6,300 | 2,000 |
| 2026-09-28 | 778 | 2,000 |
| 2026-09-30 | 59,760 | 2,000 |
| 2026-10-01 | 7,679 | 2,000 |
| 2026-10-02 | 1,308,073 | 2,000 |
| 2026-10-03 | 2,982 | 2,000 |
| 2026-10-04 | 6,936 | 2,000 |
| 2026-10-05 | 2,917 | 2,000 |
| 2026-10-06 | 8,302 | 2,000 |
| 2026-10-07 | 8,029 | 2,000 |
| 2026-10-08 | 7,353 | 2,000 |
| 2026-10-09 | 152,139 | 2,000 |
| 2026-10-10 | 8,236 | 2,000 |
| 2026-10-11 | 23,246 | 2,000 |
| 2026-10-12 | 33,378 | 2,000 |
| 2026-10-13 | 9,088 | 2,000 |
| 2026-10-14 | 8,130 | 2,000 |
| 2026-10-15 | 8,936 | 2,000 |
| 2026-10-16 | 16,321 | 2,000 |
| 2026-10-17 | 10,761 | 2,000 |

> Hinweis: Der Rueckstau von 2,872,168 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,437 |
| 2026-09-23 | 13,081 |
| 2026-09-24 | 16,694 |
| 2026-09-25 | 20,963 |
| 2026-09-26 | 17,485 |
| 2026-09-27 | 15,066 |
| 2026-09-28 | 11,621 |
| 2026-09-29 | 9,371 |
| 2026-09-30 | 10,204 |
| 2026-10-01 | 16,625 |
| 2026-10-02 | 7,740 |
| 2026-10-03 | 7,350 |
| 2026-10-04 | 12,650 |
| 2026-10-05 | 17,582 |
| 2026-10-06 | 16,159 |
| 2026-10-07 | 15,099 |
| 2026-10-08 | 61,550 |
| 2026-10-09 | 223,786 |
| 2026-10-10 | 53,423 |
| 2026-10-11 | 16,072 |
| 2026-10-12 | 66,615 |
| 2026-10-13 | 1,586,879 |
| 2026-10-14 | 32,932 |
| 2026-10-15 | 41,376 |
| 2026-10-16 | 51,411 |
| 2026-10-17 | 24,368 |
| 2026-10-18 | 14,312 |
| 2026-10-19 | 22,458 |
| 2026-10-20 | 11,169 |
| 2026-10-21 | 11,144 |
| 2026-10-22 | 30,823 |
| 2026-10-23 | 50,499 |
| 2026-10-24 | 41,810 |
| 2026-10-25 | 21,679 |
| 2026-10-26 | 20,411 |
| 2026-10-27 | 20,771 |
| 2026-10-28 | 15,848 |
| 2026-10-29 | 9,731 |
| 2026-10-30 | 62,126 |
| 2026-10-31 | 88,302 |
| 2026-11-01 | 27,955 |
| 2026-11-02 | 28,928 |
| 2026-11-03 | 29,956 |
| 2026-11-04 | 29,762 |
| 2026-11-05 | 25,375 |
| 2026-11-06 | 36,806 |
| 2026-11-07 | 24,568 |
| 2026-11-08 | 26,229 |
| 2026-11-09 | 25,669 |
| 2026-11-10 | 32,861 |
| 2026-11-11 | 22,484 |
| 2026-11-12 | 20,581 |
| 2026-11-13 | 19,734 |
| 2026-11-14 | 23,067 |
| 2026-11-15 | 17,538 |
| 2026-11-16 | 18,052 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 192755 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
