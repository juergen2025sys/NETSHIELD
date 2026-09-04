# Seen-DB Expiry Forecast

Lauf: 2026-09-04 06:13 CEST (Europe/Berlin)
Gesamt: 11,171,181 IPs in seen_db.json (8,524,728 aktiv/180-Tage-Pfad, 2,646,453 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 836,844 |
| 8-14 Tage | 0 |
| 15-30 Tage | 166,886 |
| 31-60 Tage | 2,728,248 |
| 61-90 Tage | 1,036,093 |
| 91-180 Tage | 3,756,657 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 196,653 |
| 0-3 Tage | 254,251 |
| 4-7 Tage | 50,358 |
| 8-14 Tage | 73,858 |
| 15-30 Tage | 2,071,333 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-04 | 148,105 |
| 2026-09-05 | 69,346 |
| 2026-09-06 | 20,512 |
| 2026-09-07 | 16,288 |
| 2026-09-08 | 13,104 |
| 2026-09-09 | 17,031 |
| 2026-09-10 | 8,821 |
| 2026-09-11 | 11,402 |
| 2026-09-12 | 11,990 |
| 2026-09-13 | 12,133 |
| 2026-09-14 | 12,968 |
| 2026-09-15 | 15,731 |
| 2026-09-16 | 6,301 |
| 2026-09-17 | 5,849 |
| 2026-09-18 | 8,886 |
| 2026-09-19 | 5,201 |
| 2026-09-20 | 5,115 |
| 2026-09-21 | 5,107 |
| 2026-09-22 | 11,290 |
| 2026-09-23 | 5,213 |
| 2026-09-24 | 11,493 |
| 2026-09-25 | 5,575 |
| 2026-09-26 | 624,781 |
| 2026-09-27 | 6,422 |
| 2026-09-28 | 791 |
| 2026-09-30 | 60,164 |
| 2026-10-01 | 7,798 |
| 2026-10-02 | 1,311,484 |
| 2026-10-03 | 3,072 |
| 2026-10-04 | 7,566 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **196,653** IPs. Brutto faellig in den naechsten 30 Tagen: **2,449,539**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,586,192**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-04 | 148,105 | 2,000 |
| 2026-09-05 | 69,346 | 2,000 |
| 2026-09-06 | 20,512 | 2,000 |
| 2026-09-07 | 16,288 | 2,000 |
| 2026-09-08 | 13,104 | 2,000 |
| 2026-09-09 | 17,031 | 2,000 |
| 2026-09-10 | 8,821 | 2,000 |
| 2026-09-11 | 11,402 | 2,000 |
| 2026-09-12 | 11,990 | 2,000 |
| 2026-09-13 | 12,133 | 2,000 |
| 2026-09-14 | 12,968 | 2,000 |
| 2026-09-15 | 15,731 | 2,000 |
| 2026-09-16 | 6,301 | 2,000 |
| 2026-09-17 | 5,849 | 2,000 |
| 2026-09-18 | 8,886 | 2,000 |
| 2026-09-19 | 5,201 | 2,000 |
| 2026-09-20 | 5,115 | 2,000 |
| 2026-09-21 | 5,107 | 2,000 |
| 2026-09-22 | 11,290 | 2,000 |
| 2026-09-23 | 5,213 | 2,000 |
| 2026-09-24 | 11,493 | 2,000 |
| 2026-09-25 | 5,575 | 2,000 |
| 2026-09-26 | 624,781 | 2,000 |
| 2026-09-27 | 6,422 | 2,000 |
| 2026-09-28 | 791 | 2,000 |
| 2026-09-30 | 60,164 | 2,000 |
| 2026-10-01 | 7,798 | 2,000 |
| 2026-10-02 | 1,311,484 | 2,000 |
| 2026-10-03 | 3,072 | 2,000 |
| 2026-10-04 | 7,566 | 2,000 |

> Hinweis: Der Rueckstau von 2,586,192 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-05 | 173,671 |
| 2026-09-08 | 663,173 |
| 2026-09-22 | 6,493 |
| 2026-09-23 | 13,194 |
| 2026-09-24 | 16,883 |
| 2026-09-25 | 21,167 |
| 2026-09-26 | 17,670 |
| 2026-09-27 | 15,250 |
| 2026-09-28 | 11,689 |
| 2026-09-29 | 9,450 |
| 2026-09-30 | 10,311 |
| 2026-10-01 | 16,742 |
| 2026-10-02 | 7,819 |
| 2026-10-03 | 7,413 |
| 2026-10-04 | 12,805 |
| 2026-10-05 | 17,727 |
| 2026-10-06 | 16,295 |
| 2026-10-07 | 15,213 |
| 2026-10-08 | 62,257 |
| 2026-10-09 | 226,566 |
| 2026-10-10 | 53,555 |
| 2026-10-11 | 16,124 |
| 2026-10-12 | 66,724 |
| 2026-10-13 | 1,592,308 |
| 2026-10-14 | 32,972 |
| 2026-10-15 | 41,465 |
| 2026-10-16 | 51,543 |
| 2026-10-17 | 24,509 |
| 2026-10-18 | 14,412 |
| 2026-10-19 | 22,785 |
| 2026-10-20 | 11,248 |
| 2026-10-21 | 11,228 |
| 2026-10-22 | 31,028 |
| 2026-10-23 | 50,671 |
| 2026-10-24 | 41,970 |
| 2026-10-25 | 21,827 |
| 2026-10-26 | 20,579 |
| 2026-10-27 | 20,932 |
| 2026-10-28 | 15,969 |
| 2026-10-29 | 9,843 |
| 2026-10-30 | 62,527 |
| 2026-10-31 | 88,516 |
| 2026-11-01 | 28,103 |
| 2026-11-02 | 29,131 |
| 2026-11-03 | 30,221 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
