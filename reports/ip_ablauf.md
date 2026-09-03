# Seen-DB Expiry Forecast

Lauf: 2026-09-03 13:38 CEST (Europe/Berlin)
Gesamt: 11,145,357 IPs in seen_db.json (8,500,062 aktiv/180-Tage-Pfad, 2,645,295 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 837,007 |
| 8-14 Tage | 0 |
| 15-30 Tage | 154,150 |
| 31-60 Tage | 2,711,224 |
| 61-90 Tage | 1,040,109 |
| 91-180 Tage | 3,757,572 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 185,709 |
| 0-3 Tage | 248,963 |
| 4-7 Tage | 55,271 |
| 8-14 Tage | 76,428 |
| 15-30 Tage | 2,078,924 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-03 | 10,952 |
| 2026-09-04 | 148,117 |
| 2026-09-05 | 69,375 |
| 2026-09-06 | 20,519 |
| 2026-09-07 | 16,302 |
| 2026-09-08 | 13,106 |
| 2026-09-09 | 17,036 |
| 2026-09-10 | 8,827 |
| 2026-09-11 | 11,413 |
| 2026-09-12 | 11,998 |
| 2026-09-13 | 12,142 |
| 2026-09-14 | 12,977 |
| 2026-09-15 | 15,741 |
| 2026-09-16 | 6,305 |
| 2026-09-17 | 5,852 |
| 2026-09-18 | 8,890 |
| 2026-09-19 | 5,207 |
| 2026-09-20 | 5,117 |
| 2026-09-21 | 5,111 |
| 2026-09-22 | 11,296 |
| 2026-09-23 | 5,217 |
| 2026-09-24 | 11,495 |
| 2026-09-25 | 5,578 |
| 2026-09-26 | 624,820 |
| 2026-09-27 | 6,433 |
| 2026-09-28 | 794 |
| 2026-09-30 | 60,191 |
| 2026-10-01 | 7,807 |
| 2026-10-02 | 1,311,674 |
| 2026-10-03 | 3,524 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **185,709** IPs. Brutto faellig in den naechsten 30 Tagen: **2,453,816**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,579,525**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-03 | 10,952 | 2,000 |
| 2026-09-04 | 148,117 | 2,000 |
| 2026-09-05 | 69,375 | 2,000 |
| 2026-09-06 | 20,519 | 2,000 |
| 2026-09-07 | 16,302 | 2,000 |
| 2026-09-08 | 13,106 | 2,000 |
| 2026-09-09 | 17,036 | 2,000 |
| 2026-09-10 | 8,827 | 2,000 |
| 2026-09-11 | 11,413 | 2,000 |
| 2026-09-12 | 11,998 | 2,000 |
| 2026-09-13 | 12,142 | 2,000 |
| 2026-09-14 | 12,977 | 2,000 |
| 2026-09-15 | 15,741 | 2,000 |
| 2026-09-16 | 6,305 | 2,000 |
| 2026-09-17 | 5,852 | 2,000 |
| 2026-09-18 | 8,890 | 2,000 |
| 2026-09-19 | 5,207 | 2,000 |
| 2026-09-20 | 5,117 | 2,000 |
| 2026-09-21 | 5,111 | 2,000 |
| 2026-09-22 | 11,296 | 2,000 |
| 2026-09-23 | 5,217 | 2,000 |
| 2026-09-24 | 11,495 | 2,000 |
| 2026-09-25 | 5,578 | 2,000 |
| 2026-09-26 | 624,820 | 2,000 |
| 2026-09-27 | 6,433 | 2,000 |
| 2026-09-28 | 794 | 2,000 |
| 2026-09-30 | 60,191 | 2,000 |
| 2026-10-01 | 7,807 | 2,000 |
| 2026-10-02 | 1,311,674 | 2,000 |
| 2026-10-03 | 3,524 | 2,000 |

> Hinweis: Der Rueckstau von 2,579,525 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-05 | 173,676 |
| 2026-09-08 | 663,331 |
| 2026-09-22 | 6,497 |
| 2026-09-23 | 13,201 |
| 2026-09-24 | 16,885 |
| 2026-09-25 | 21,177 |
| 2026-09-26 | 17,678 |
| 2026-09-27 | 15,260 |
| 2026-09-28 | 11,695 |
| 2026-09-29 | 9,451 |
| 2026-09-30 | 10,317 |
| 2026-10-01 | 16,748 |
| 2026-10-02 | 7,824 |
| 2026-10-03 | 7,417 |
| 2026-10-04 | 12,818 |
| 2026-10-05 | 17,731 |
| 2026-10-06 | 16,303 |
| 2026-10-07 | 15,219 |
| 2026-10-08 | 62,299 |
| 2026-10-09 | 226,633 |
| 2026-10-10 | 53,561 |
| 2026-10-11 | 16,125 |
| 2026-10-12 | 66,729 |
| 2026-10-13 | 1,592,403 |
| 2026-10-14 | 32,974 |
| 2026-10-15 | 41,471 |
| 2026-10-16 | 51,548 |
| 2026-10-17 | 24,513 |
| 2026-10-18 | 14,414 |
| 2026-10-19 | 22,799 |
| 2026-10-20 | 11,251 |
| 2026-10-21 | 11,234 |
| 2026-10-22 | 31,036 |
| 2026-10-23 | 50,680 |
| 2026-10-24 | 41,976 |
| 2026-10-25 | 21,840 |
| 2026-10-26 | 20,589 |
| 2026-10-27 | 20,937 |
| 2026-10-28 | 15,975 |
| 2026-10-29 | 9,847 |
| 2026-10-30 | 62,545 |
| 2026-10-31 | 88,523 |
| 2026-11-01 | 28,116 |
| 2026-11-02 | 29,135 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
