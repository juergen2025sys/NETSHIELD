# Seen-DB Expiry Forecast

Lauf: 2026-09-02 15:34 CEST (Europe/Berlin)
Gesamt: 11,107,873 IPs in seen_db.json (8,468,993 aktiv/180-Tage-Pfad, 2,638,880 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 837,166 |
| 8-14 Tage | 0 |
| 15-30 Tage | 146,790 |
| 31-60 Tage | 2,689,943 |
| 61-90 Tage | 1,042,931 |
| 91-180 Tage | 3,752,163 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 176,334 |
| 0-3 Tage | 237,811 |
| 4-7 Tage | 66,991 |
| 8-14 Tage | 79,455 |
| 15-30 Tage | 2,078,289 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-02 | 9,323 |
| 2026-09-03 | 10,962 |
| 2026-09-04 | 148,127 |
| 2026-09-05 | 69,399 |
| 2026-09-06 | 20,526 |
| 2026-09-07 | 16,313 |
| 2026-09-08 | 13,112 |
| 2026-09-09 | 17,040 |
| 2026-09-10 | 8,836 |
| 2026-09-11 | 11,418 |
| 2026-09-12 | 12,003 |
| 2026-09-13 | 12,151 |
| 2026-09-14 | 12,986 |
| 2026-09-15 | 15,753 |
| 2026-09-16 | 6,308 |
| 2026-09-17 | 5,853 |
| 2026-09-18 | 8,894 |
| 2026-09-19 | 5,211 |
| 2026-09-20 | 5,119 |
| 2026-09-21 | 5,116 |
| 2026-09-22 | 11,307 |
| 2026-09-23 | 5,222 |
| 2026-09-24 | 11,503 |
| 2026-09-25 | 5,582 |
| 2026-09-26 | 624,860 |
| 2026-09-27 | 6,441 |
| 2026-09-28 | 796 |
| 2026-09-30 | 60,239 |
| 2026-10-01 | 7,832 |
| 2026-10-02 | 1,311,971 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **176,334** IPs. Brutto faellig in den naechsten 30 Tagen: **2,460,203**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,576,537**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-02 | 9,323 | 2,000 |
| 2026-09-03 | 10,962 | 2,000 |
| 2026-09-04 | 148,127 | 2,000 |
| 2026-09-05 | 69,399 | 2,000 |
| 2026-09-06 | 20,526 | 2,000 |
| 2026-09-07 | 16,313 | 2,000 |
| 2026-09-08 | 13,112 | 2,000 |
| 2026-09-09 | 17,040 | 2,000 |
| 2026-09-10 | 8,836 | 2,000 |
| 2026-09-11 | 11,418 | 2,000 |
| 2026-09-12 | 12,003 | 2,000 |
| 2026-09-13 | 12,151 | 2,000 |
| 2026-09-14 | 12,986 | 2,000 |
| 2026-09-15 | 15,753 | 2,000 |
| 2026-09-16 | 6,308 | 2,000 |
| 2026-09-17 | 5,853 | 2,000 |
| 2026-09-18 | 8,894 | 2,000 |
| 2026-09-19 | 5,211 | 2,000 |
| 2026-09-20 | 5,119 | 2,000 |
| 2026-09-21 | 5,116 | 2,000 |
| 2026-09-22 | 11,307 | 2,000 |
| 2026-09-23 | 5,222 | 2,000 |
| 2026-09-24 | 11,503 | 2,000 |
| 2026-09-25 | 5,582 | 2,000 |
| 2026-09-26 | 624,860 | 2,000 |
| 2026-09-27 | 6,441 | 2,000 |
| 2026-09-28 | 796 | 2,000 |
| 2026-09-30 | 60,239 | 2,000 |
| 2026-10-01 | 7,832 | 2,000 |
| 2026-10-02 | 1,311,971 | 2,000 |

> Hinweis: Der Rueckstau von 2,576,537 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-05 | 173,683 |
| 2026-09-08 | 663,483 |
| 2026-09-22 | 6,500 |
| 2026-09-23 | 13,208 |
| 2026-09-24 | 16,894 |
| 2026-09-25 | 21,182 |
| 2026-09-26 | 17,684 |
| 2026-09-27 | 15,264 |
| 2026-09-28 | 11,696 |
| 2026-09-29 | 9,454 |
| 2026-09-30 | 10,323 |
| 2026-10-01 | 16,758 |
| 2026-10-02 | 7,827 |
| 2026-10-03 | 7,421 |
| 2026-10-04 | 12,823 |
| 2026-10-05 | 17,739 |
| 2026-10-06 | 16,310 |
| 2026-10-07 | 15,227 |
| 2026-10-08 | 62,335 |
| 2026-10-09 | 226,691 |
| 2026-10-10 | 53,563 |
| 2026-10-11 | 16,127 |
| 2026-10-12 | 66,731 |
| 2026-10-13 | 1,592,537 |
| 2026-10-14 | 32,976 |
| 2026-10-15 | 41,475 |
| 2026-10-16 | 51,555 |
| 2026-10-17 | 24,518 |
| 2026-10-18 | 14,417 |
| 2026-10-19 | 22,806 |
| 2026-10-20 | 11,254 |
| 2026-10-21 | 11,244 |
| 2026-10-22 | 31,049 |
| 2026-10-23 | 50,692 |
| 2026-10-24 | 41,988 |
| 2026-10-25 | 21,857 |
| 2026-10-26 | 20,602 |
| 2026-10-27 | 20,942 |
| 2026-10-28 | 15,979 |
| 2026-10-29 | 9,851 |
| 2026-10-30 | 62,566 |
| 2026-10-31 | 88,534 |
| 2026-11-01 | 28,134 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
