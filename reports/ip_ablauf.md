# Seen-DB Expiry Forecast

Lauf: 2026-09-02 19:50 CEST (Europe/Berlin)
Gesamt: 11,138,217 IPs in seen_db.json (8,474,450 aktiv/180-Tage-Pfad, 2,663,767 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 837,140 |
| 8-14 Tage | 0 |
| 15-30 Tage | 146,784 |
| 31-60 Tage | 2,689,886 |
| 61-90 Tage | 1,042,883 |
| 91-180 Tage | 3,757,757 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 176,668 |
| 0-3 Tage | 237,800 |
| 4-7 Tage | 66,988 |
| 8-14 Tage | 79,449 |
| 15-30 Tage | 2,102,862 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-02 | 9,321 |
| 2026-09-03 | 10,960 |
| 2026-09-04 | 148,124 |
| 2026-09-05 | 69,395 |
| 2026-09-06 | 20,526 |
| 2026-09-07 | 16,312 |
| 2026-09-08 | 13,111 |
| 2026-09-09 | 17,039 |
| 2026-09-10 | 8,836 |
| 2026-09-11 | 11,417 |
| 2026-09-12 | 12,002 |
| 2026-09-13 | 12,151 |
| 2026-09-14 | 12,985 |
| 2026-09-15 | 15,752 |
| 2026-09-16 | 6,306 |
| 2026-09-17 | 5,853 |
| 2026-09-18 | 8,894 |
| 2026-09-19 | 5,211 |
| 2026-09-20 | 5,119 |
| 2026-09-21 | 5,115 |
| 2026-09-22 | 11,304 |
| 2026-09-23 | 5,221 |
| 2026-09-24 | 11,503 |
| 2026-09-25 | 5,582 |
| 2026-09-26 | 624,853 |
| 2026-09-27 | 6,440 |
| 2026-09-28 | 796 |
| 2026-09-30 | 60,231 |
| 2026-10-01 | 7,827 |
| 2026-10-02 | 1,311,928 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **176,668** IPs. Brutto faellig in den naechsten 30 Tagen: **2,460,114**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,576,782**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-02 | 9,321 | 2,000 |
| 2026-09-03 | 10,960 | 2,000 |
| 2026-09-04 | 148,124 | 2,000 |
| 2026-09-05 | 69,395 | 2,000 |
| 2026-09-06 | 20,526 | 2,000 |
| 2026-09-07 | 16,312 | 2,000 |
| 2026-09-08 | 13,111 | 2,000 |
| 2026-09-09 | 17,039 | 2,000 |
| 2026-09-10 | 8,836 | 2,000 |
| 2026-09-11 | 11,417 | 2,000 |
| 2026-09-12 | 12,002 | 2,000 |
| 2026-09-13 | 12,151 | 2,000 |
| 2026-09-14 | 12,985 | 2,000 |
| 2026-09-15 | 15,752 | 2,000 |
| 2026-09-16 | 6,306 | 2,000 |
| 2026-09-17 | 5,853 | 2,000 |
| 2026-09-18 | 8,894 | 2,000 |
| 2026-09-19 | 5,211 | 2,000 |
| 2026-09-20 | 5,119 | 2,000 |
| 2026-09-21 | 5,115 | 2,000 |
| 2026-09-22 | 11,304 | 2,000 |
| 2026-09-23 | 5,221 | 2,000 |
| 2026-09-24 | 11,503 | 2,000 |
| 2026-09-25 | 5,582 | 2,000 |
| 2026-09-26 | 624,853 | 2,000 |
| 2026-09-27 | 6,440 | 2,000 |
| 2026-09-28 | 796 | 2,000 |
| 2026-09-30 | 60,231 | 2,000 |
| 2026-10-01 | 7,827 | 2,000 |
| 2026-10-02 | 1,311,928 | 2,000 |

> Hinweis: Der Rueckstau von 2,576,782 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-05 | 173,683 |
| 2026-09-08 | 663,457 |
| 2026-09-22 | 6,500 |
| 2026-09-23 | 13,206 |
| 2026-09-24 | 16,893 |
| 2026-09-25 | 21,181 |
| 2026-09-26 | 17,684 |
| 2026-09-27 | 15,264 |
| 2026-09-28 | 11,696 |
| 2026-09-29 | 9,454 |
| 2026-09-30 | 10,322 |
| 2026-10-01 | 16,757 |
| 2026-10-02 | 7,827 |
| 2026-10-03 | 7,421 |
| 2026-10-04 | 12,822 |
| 2026-10-05 | 17,739 |
| 2026-10-06 | 16,310 |
| 2026-10-07 | 15,227 |
| 2026-10-08 | 62,330 |
| 2026-10-09 | 226,686 |
| 2026-10-10 | 53,563 |
| 2026-10-11 | 16,126 |
| 2026-10-12 | 66,731 |
| 2026-10-13 | 1,592,520 |
| 2026-10-14 | 32,976 |
| 2026-10-15 | 41,475 |
| 2026-10-16 | 51,554 |
| 2026-10-17 | 24,518 |
| 2026-10-18 | 14,417 |
| 2026-10-19 | 22,803 |
| 2026-10-20 | 11,254 |
| 2026-10-21 | 11,243 |
| 2026-10-22 | 31,047 |
| 2026-10-23 | 50,692 |
| 2026-10-24 | 41,987 |
| 2026-10-25 | 21,854 |
| 2026-10-26 | 20,599 |
| 2026-10-27 | 20,940 |
| 2026-10-28 | 15,978 |
| 2026-10-29 | 9,851 |
| 2026-10-30 | 62,559 |
| 2026-10-31 | 88,532 |
| 2026-11-01 | 28,132 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
