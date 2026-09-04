# Seen-DB Expiry Forecast

Lauf: 2026-09-04 21:50 CEST (Europe/Berlin)
Gesamt: 11,195,318 IPs in seen_db.json (8,546,609 aktiv/180-Tage-Pfad, 2,648,709 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 836,694 |
| 8-14 Tage | 0 |
| 15-30 Tage | 166,847 |
| 31-60 Tage | 2,727,834 |
| 61-90 Tage | 1,035,894 |
| 91-180 Tage | 3,779,340 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 196,684 |
| 0-3 Tage | 254,199 |
| 4-7 Tage | 50,339 |
| 8-14 Tage | 73,821 |
| 15-30 Tage | 2,073,666 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-04 | 148,094 |
| 2026-09-05 | 69,321 |
| 2026-09-06 | 20,509 |
| 2026-09-07 | 16,275 |
| 2026-09-08 | 13,097 |
| 2026-09-09 | 17,027 |
| 2026-09-10 | 8,818 |
| 2026-09-11 | 11,397 |
| 2026-09-12 | 11,980 |
| 2026-09-13 | 12,127 |
| 2026-09-14 | 12,961 |
| 2026-09-15 | 15,726 |
| 2026-09-16 | 6,299 |
| 2026-09-17 | 5,846 |
| 2026-09-18 | 8,882 |
| 2026-09-19 | 5,197 |
| 2026-09-20 | 5,112 |
| 2026-09-21 | 5,104 |
| 2026-09-22 | 11,286 |
| 2026-09-23 | 5,205 |
| 2026-09-24 | 11,489 |
| 2026-09-25 | 5,571 |
| 2026-09-26 | 624,767 |
| 2026-09-27 | 6,412 |
| 2026-09-28 | 790 |
| 2026-09-30 | 60,146 |
| 2026-10-01 | 7,793 |
| 2026-10-02 | 1,311,328 |
| 2026-10-03 | 3,051 |
| 2026-10-04 | 7,118 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **196,684** IPs. Brutto faellig in den naechsten 30 Tagen: **2,448,728**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,585,412**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-04 | 148,094 | 2,000 |
| 2026-09-05 | 69,321 | 2,000 |
| 2026-09-06 | 20,509 | 2,000 |
| 2026-09-07 | 16,275 | 2,000 |
| 2026-09-08 | 13,097 | 2,000 |
| 2026-09-09 | 17,027 | 2,000 |
| 2026-09-10 | 8,818 | 2,000 |
| 2026-09-11 | 11,397 | 2,000 |
| 2026-09-12 | 11,980 | 2,000 |
| 2026-09-13 | 12,127 | 2,000 |
| 2026-09-14 | 12,961 | 2,000 |
| 2026-09-15 | 15,726 | 2,000 |
| 2026-09-16 | 6,299 | 2,000 |
| 2026-09-17 | 5,846 | 2,000 |
| 2026-09-18 | 8,882 | 2,000 |
| 2026-09-19 | 5,197 | 2,000 |
| 2026-09-20 | 5,112 | 2,000 |
| 2026-09-21 | 5,104 | 2,000 |
| 2026-09-22 | 11,286 | 2,000 |
| 2026-09-23 | 5,205 | 2,000 |
| 2026-09-24 | 11,489 | 2,000 |
| 2026-09-25 | 5,571 | 2,000 |
| 2026-09-26 | 624,767 | 2,000 |
| 2026-09-27 | 6,412 | 2,000 |
| 2026-09-28 | 790 | 2,000 |
| 2026-09-30 | 60,146 | 2,000 |
| 2026-10-01 | 7,793 | 2,000 |
| 2026-10-02 | 1,311,328 | 2,000 |
| 2026-10-03 | 3,051 | 2,000 |
| 2026-10-04 | 7,118 | 2,000 |

> Hinweis: Der Rueckstau von 2,585,412 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-05 | 173,665 |
| 2026-09-08 | 663,029 |
| 2026-09-22 | 6,491 |
| 2026-09-23 | 13,192 |
| 2026-09-24 | 16,878 |
| 2026-09-25 | 21,159 |
| 2026-09-26 | 17,665 |
| 2026-09-27 | 15,245 |
| 2026-09-28 | 11,688 |
| 2026-09-29 | 9,448 |
| 2026-09-30 | 10,309 |
| 2026-10-01 | 16,742 |
| 2026-10-02 | 7,817 |
| 2026-10-03 | 7,412 |
| 2026-10-04 | 12,801 |
| 2026-10-05 | 17,725 |
| 2026-10-06 | 16,292 |
| 2026-10-07 | 15,211 |
| 2026-10-08 | 62,231 |
| 2026-10-09 | 226,478 |
| 2026-10-10 | 53,548 |
| 2026-10-11 | 16,122 |
| 2026-10-12 | 66,722 |
| 2026-10-13 | 1,592,169 |
| 2026-10-14 | 32,971 |
| 2026-10-15 | 41,462 |
| 2026-10-16 | 51,537 |
| 2026-10-17 | 24,505 |
| 2026-10-18 | 14,410 |
| 2026-10-19 | 22,764 |
| 2026-10-20 | 11,246 |
| 2026-10-21 | 11,227 |
| 2026-10-22 | 31,023 |
| 2026-10-23 | 50,660 |
| 2026-10-24 | 41,963 |
| 2026-10-25 | 21,818 |
| 2026-10-26 | 20,572 |
| 2026-10-27 | 20,926 |
| 2026-10-28 | 15,963 |
| 2026-10-29 | 9,839 |
| 2026-10-30 | 62,507 |
| 2026-10-31 | 88,510 |
| 2026-11-01 | 28,098 |
| 2026-11-02 | 29,124 |
| 2026-11-03 | 30,211 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
