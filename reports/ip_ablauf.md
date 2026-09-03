# Seen-DB Expiry Forecast

Lauf: 2026-09-03 03:22 CEST (Europe/Berlin)
Gesamt: 11,128,935 IPs in seen_db.json (8,488,899 aktiv/180-Tage-Pfad, 2,640,036 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 837,095 |
| 8-14 Tage | 0 |
| 15-30 Tage | 154,180 |
| 31-60 Tage | 2,711,468 |
| 61-90 Tage | 1,040,221 |
| 91-180 Tage | 3,745,935 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 185,647 |
| 0-3 Tage | 248,985 |
| 4-7 Tage | 55,291 |
| 8-14 Tage | 76,452 |
| 15-30 Tage | 2,073,661 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-03 | 10,959 |
| 2026-09-04 | 148,120 |
| 2026-09-05 | 69,384 |
| 2026-09-06 | 20,522 |
| 2026-09-07 | 16,308 |
| 2026-09-08 | 13,110 |
| 2026-09-09 | 17,038 |
| 2026-09-10 | 8,835 |
| 2026-09-11 | 11,415 |
| 2026-09-12 | 12,001 |
| 2026-09-13 | 12,149 |
| 2026-09-14 | 12,982 |
| 2026-09-15 | 15,747 |
| 2026-09-16 | 6,305 |
| 2026-09-17 | 5,853 |
| 2026-09-18 | 8,893 |
| 2026-09-19 | 5,209 |
| 2026-09-20 | 5,119 |
| 2026-09-21 | 5,115 |
| 2026-09-22 | 11,299 |
| 2026-09-23 | 5,220 |
| 2026-09-24 | 11,502 |
| 2026-09-25 | 5,581 |
| 2026-09-26 | 624,844 |
| 2026-09-27 | 6,439 |
| 2026-09-28 | 795 |
| 2026-09-30 | 60,218 |
| 2026-10-01 | 7,819 |
| 2026-10-02 | 1,311,835 |
| 2026-10-03 | 3,611 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **185,647** IPs. Brutto faellig in den naechsten 30 Tagen: **2,454,227**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,579,874**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-03 | 10,959 | 2,000 |
| 2026-09-04 | 148,120 | 2,000 |
| 2026-09-05 | 69,384 | 2,000 |
| 2026-09-06 | 20,522 | 2,000 |
| 2026-09-07 | 16,308 | 2,000 |
| 2026-09-08 | 13,110 | 2,000 |
| 2026-09-09 | 17,038 | 2,000 |
| 2026-09-10 | 8,835 | 2,000 |
| 2026-09-11 | 11,415 | 2,000 |
| 2026-09-12 | 12,001 | 2,000 |
| 2026-09-13 | 12,149 | 2,000 |
| 2026-09-14 | 12,982 | 2,000 |
| 2026-09-15 | 15,747 | 2,000 |
| 2026-09-16 | 6,305 | 2,000 |
| 2026-09-17 | 5,853 | 2,000 |
| 2026-09-18 | 8,893 | 2,000 |
| 2026-09-19 | 5,209 | 2,000 |
| 2026-09-20 | 5,119 | 2,000 |
| 2026-09-21 | 5,115 | 2,000 |
| 2026-09-22 | 11,299 | 2,000 |
| 2026-09-23 | 5,220 | 2,000 |
| 2026-09-24 | 11,502 | 2,000 |
| 2026-09-25 | 5,581 | 2,000 |
| 2026-09-26 | 624,844 | 2,000 |
| 2026-09-27 | 6,439 | 2,000 |
| 2026-09-28 | 795 | 2,000 |
| 2026-09-30 | 60,218 | 2,000 |
| 2026-10-01 | 7,819 | 2,000 |
| 2026-10-02 | 1,311,835 | 2,000 |
| 2026-10-03 | 3,611 | 2,000 |

> Hinweis: Der Rueckstau von 2,579,874 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-05 | 173,679 |
| 2026-09-08 | 663,416 |
| 2026-09-22 | 6,499 |
| 2026-09-23 | 13,206 |
| 2026-09-24 | 16,888 |
| 2026-09-25 | 21,178 |
| 2026-09-26 | 17,682 |
| 2026-09-27 | 15,263 |
| 2026-09-28 | 11,695 |
| 2026-09-29 | 9,452 |
| 2026-09-30 | 10,321 |
| 2026-10-01 | 16,750 |
| 2026-10-02 | 7,827 |
| 2026-10-03 | 7,419 |
| 2026-10-04 | 12,820 |
| 2026-10-05 | 17,735 |
| 2026-10-06 | 16,308 |
| 2026-10-07 | 15,224 |
| 2026-10-08 | 62,320 |
| 2026-10-09 | 226,670 |
| 2026-10-10 | 53,562 |
| 2026-10-11 | 16,126 |
| 2026-10-12 | 66,731 |
| 2026-10-13 | 1,592,482 |
| 2026-10-14 | 32,976 |
| 2026-10-15 | 41,472 |
| 2026-10-16 | 51,551 |
| 2026-10-17 | 24,516 |
| 2026-10-18 | 14,415 |
| 2026-10-19 | 22,801 |
| 2026-10-20 | 11,251 |
| 2026-10-21 | 11,238 |
| 2026-10-22 | 31,043 |
| 2026-10-23 | 50,686 |
| 2026-10-24 | 41,981 |
| 2026-10-25 | 21,848 |
| 2026-10-26 | 20,595 |
| 2026-10-27 | 20,940 |
| 2026-10-28 | 15,977 |
| 2026-10-29 | 9,848 |
| 2026-10-30 | 62,552 |
| 2026-10-31 | 88,527 |
| 2026-11-01 | 28,130 |
| 2026-11-02 | 29,143 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
