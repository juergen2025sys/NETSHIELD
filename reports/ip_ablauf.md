# Seen-DB Expiry Forecast

Lauf: 2026-09-02 06:11 CEST (Europe/Berlin)
Gesamt: 11,093,086 IPs in seen_db.json (8,455,343 aktiv/180-Tage-Pfad, 2,637,743 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 837,306 |
| 8-14 Tage | 0 |
| 15-30 Tage | 146,835 |
| 31-60 Tage | 2,690,319 |
| 61-90 Tage | 1,043,156 |
| 91-180 Tage | 3,737,727 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 176,267 |
| 0-3 Tage | 237,879 |
| 4-7 Tage | 67,030 |
| 8-14 Tage | 79,501 |
| 15-30 Tage | 2,077,066 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-02 | 9,329 |
| 2026-09-03 | 10,967 |
| 2026-09-04 | 148,138 |
| 2026-09-05 | 69,445 |
| 2026-09-06 | 20,539 |
| 2026-09-07 | 16,325 |
| 2026-09-08 | 13,113 |
| 2026-09-09 | 17,053 |
| 2026-09-10 | 8,848 |
| 2026-09-11 | 11,422 |
| 2026-09-12 | 12,011 |
| 2026-09-13 | 12,154 |
| 2026-09-14 | 12,992 |
| 2026-09-15 | 15,766 |
| 2026-09-16 | 6,308 |
| 2026-09-17 | 5,858 |
| 2026-09-18 | 8,901 |
| 2026-09-19 | 5,214 |
| 2026-09-20 | 5,124 |
| 2026-09-21 | 5,117 |
| 2026-09-22 | 11,317 |
| 2026-09-23 | 5,224 |
| 2026-09-24 | 11,516 |
| 2026-09-25 | 5,586 |
| 2026-09-26 | 624,887 |
| 2026-09-27 | 6,458 |
| 2026-09-28 | 797 |
| 2026-09-30 | 60,265 |
| 2026-10-01 | 7,845 |
| 2026-10-02 | 1,312,837 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **176,267** IPs. Brutto faellig in den naechsten 30 Tagen: **2,461,356**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,577,623**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-02 | 9,329 | 2,000 |
| 2026-09-03 | 10,967 | 2,000 |
| 2026-09-04 | 148,138 | 2,000 |
| 2026-09-05 | 69,445 | 2,000 |
| 2026-09-06 | 20,539 | 2,000 |
| 2026-09-07 | 16,325 | 2,000 |
| 2026-09-08 | 13,113 | 2,000 |
| 2026-09-09 | 17,053 | 2,000 |
| 2026-09-10 | 8,848 | 2,000 |
| 2026-09-11 | 11,422 | 2,000 |
| 2026-09-12 | 12,011 | 2,000 |
| 2026-09-13 | 12,154 | 2,000 |
| 2026-09-14 | 12,992 | 2,000 |
| 2026-09-15 | 15,766 | 2,000 |
| 2026-09-16 | 6,308 | 2,000 |
| 2026-09-17 | 5,858 | 2,000 |
| 2026-09-18 | 8,901 | 2,000 |
| 2026-09-19 | 5,214 | 2,000 |
| 2026-09-20 | 5,124 | 2,000 |
| 2026-09-21 | 5,117 | 2,000 |
| 2026-09-22 | 11,317 | 2,000 |
| 2026-09-23 | 5,224 | 2,000 |
| 2026-09-24 | 11,516 | 2,000 |
| 2026-09-25 | 5,586 | 2,000 |
| 2026-09-26 | 624,887 | 2,000 |
| 2026-09-27 | 6,458 | 2,000 |
| 2026-09-28 | 797 | 2,000 |
| 2026-09-30 | 60,265 | 2,000 |
| 2026-10-01 | 7,845 | 2,000 |
| 2026-10-02 | 1,312,837 | 2,000 |

> Hinweis: Der Rueckstau von 2,577,623 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-05 | 173,689 |
| 2026-09-08 | 663,617 |
| 2026-09-22 | 6,504 |
| 2026-09-23 | 13,211 |
| 2026-09-24 | 16,897 |
| 2026-09-25 | 21,191 |
| 2026-09-26 | 17,689 |
| 2026-09-27 | 15,266 |
| 2026-09-28 | 11,698 |
| 2026-09-29 | 9,456 |
| 2026-09-30 | 10,330 |
| 2026-10-01 | 16,764 |
| 2026-10-02 | 7,829 |
| 2026-10-03 | 7,424 |
| 2026-10-04 | 12,829 |
| 2026-10-05 | 17,747 |
| 2026-10-06 | 16,313 |
| 2026-10-07 | 15,241 |
| 2026-10-08 | 62,365 |
| 2026-10-09 | 226,770 |
| 2026-10-10 | 53,564 |
| 2026-10-11 | 16,131 |
| 2026-10-12 | 66,737 |
| 2026-10-13 | 1,592,617 |
| 2026-10-14 | 32,978 |
| 2026-10-15 | 41,481 |
| 2026-10-16 | 51,559 |
| 2026-10-17 | 24,523 |
| 2026-10-18 | 14,417 |
| 2026-10-19 | 22,828 |
| 2026-10-20 | 11,259 |
| 2026-10-21 | 11,246 |
| 2026-10-22 | 31,051 |
| 2026-10-23 | 50,699 |
| 2026-10-24 | 41,995 |
| 2026-10-25 | 21,867 |
| 2026-10-26 | 20,612 |
| 2026-10-27 | 20,950 |
| 2026-10-28 | 15,985 |
| 2026-10-29 | 9,855 |
| 2026-10-30 | 62,595 |
| 2026-10-31 | 88,540 |
| 2026-11-01 | 28,141 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
