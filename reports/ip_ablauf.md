# Seen-DB Expiry Forecast

Lauf: 2026-09-02 10:58 CEST (Europe/Berlin)
Gesamt: 11,100,052 IPs in seen_db.json (8,461,254 aktiv/180-Tage-Pfad, 2,638,798 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 837,240 |
| 8-14 Tage | 0 |
| 15-30 Tage | 146,809 |
| 31-60 Tage | 2,690,101 |
| 61-90 Tage | 1,043,028 |
| 91-180 Tage | 3,744,076 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 176,333 |
| 0-3 Tage | 237,838 |
| 4-7 Tage | 67,004 |
| 8-14 Tage | 79,469 |
| 15-30 Tage | 2,078,154 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-02 | 9,327 |
| 2026-09-03 | 10,965 |
| 2026-09-04 | 148,132 |
| 2026-09-05 | 69,414 |
| 2026-09-06 | 20,534 |
| 2026-09-07 | 16,316 |
| 2026-09-08 | 13,112 |
| 2026-09-09 | 17,042 |
| 2026-09-10 | 8,841 |
| 2026-09-11 | 11,420 |
| 2026-09-12 | 12,004 |
| 2026-09-13 | 12,151 |
| 2026-09-14 | 12,988 |
| 2026-09-15 | 15,757 |
| 2026-09-16 | 6,308 |
| 2026-09-17 | 5,856 |
| 2026-09-18 | 8,898 |
| 2026-09-19 | 5,213 |
| 2026-09-20 | 5,121 |
| 2026-09-21 | 5,116 |
| 2026-09-22 | 11,311 |
| 2026-09-23 | 5,222 |
| 2026-09-24 | 11,515 |
| 2026-09-25 | 5,585 |
| 2026-09-26 | 624,874 |
| 2026-09-27 | 6,454 |
| 2026-09-28 | 796 |
| 2026-09-30 | 60,250 |
| 2026-10-01 | 7,837 |
| 2026-10-02 | 1,312,627 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **176,333** IPs. Brutto faellig in den naechsten 30 Tagen: **2,460,986**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,577,319**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-02 | 9,327 | 2,000 |
| 2026-09-03 | 10,965 | 2,000 |
| 2026-09-04 | 148,132 | 2,000 |
| 2026-09-05 | 69,414 | 2,000 |
| 2026-09-06 | 20,534 | 2,000 |
| 2026-09-07 | 16,316 | 2,000 |
| 2026-09-08 | 13,112 | 2,000 |
| 2026-09-09 | 17,042 | 2,000 |
| 2026-09-10 | 8,841 | 2,000 |
| 2026-09-11 | 11,420 | 2,000 |
| 2026-09-12 | 12,004 | 2,000 |
| 2026-09-13 | 12,151 | 2,000 |
| 2026-09-14 | 12,988 | 2,000 |
| 2026-09-15 | 15,757 | 2,000 |
| 2026-09-16 | 6,308 | 2,000 |
| 2026-09-17 | 5,856 | 2,000 |
| 2026-09-18 | 8,898 | 2,000 |
| 2026-09-19 | 5,213 | 2,000 |
| 2026-09-20 | 5,121 | 2,000 |
| 2026-09-21 | 5,116 | 2,000 |
| 2026-09-22 | 11,311 | 2,000 |
| 2026-09-23 | 5,222 | 2,000 |
| 2026-09-24 | 11,515 | 2,000 |
| 2026-09-25 | 5,585 | 2,000 |
| 2026-09-26 | 624,874 | 2,000 |
| 2026-09-27 | 6,454 | 2,000 |
| 2026-09-28 | 796 | 2,000 |
| 2026-09-30 | 60,250 | 2,000 |
| 2026-10-01 | 7,837 | 2,000 |
| 2026-10-02 | 1,312,627 | 2,000 |

> Hinweis: Der Rueckstau von 2,577,319 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-05 | 173,686 |
| 2026-09-08 | 663,554 |
| 2026-09-22 | 6,501 |
| 2026-09-23 | 13,211 |
| 2026-09-24 | 16,895 |
| 2026-09-25 | 21,186 |
| 2026-09-26 | 17,687 |
| 2026-09-27 | 15,265 |
| 2026-09-28 | 11,697 |
| 2026-09-29 | 9,455 |
| 2026-09-30 | 10,325 |
| 2026-10-01 | 16,759 |
| 2026-10-02 | 7,828 |
| 2026-10-03 | 7,423 |
| 2026-10-04 | 12,824 |
| 2026-10-05 | 17,743 |
| 2026-10-06 | 16,311 |
| 2026-10-07 | 15,232 |
| 2026-10-08 | 62,354 |
| 2026-10-09 | 226,729 |
| 2026-10-10 | 53,563 |
| 2026-10-11 | 16,129 |
| 2026-10-12 | 66,733 |
| 2026-10-13 | 1,592,575 |
| 2026-10-14 | 32,978 |
| 2026-10-15 | 41,475 |
| 2026-10-16 | 51,556 |
| 2026-10-17 | 24,519 |
| 2026-10-18 | 14,417 |
| 2026-10-19 | 22,813 |
| 2026-10-20 | 11,255 |
| 2026-10-21 | 11,245 |
| 2026-10-22 | 31,049 |
| 2026-10-23 | 50,696 |
| 2026-10-24 | 41,993 |
| 2026-10-25 | 21,859 |
| 2026-10-26 | 20,605 |
| 2026-10-27 | 20,945 |
| 2026-10-28 | 15,981 |
| 2026-10-29 | 9,853 |
| 2026-10-30 | 62,576 |
| 2026-10-31 | 88,535 |
| 2026-11-01 | 28,135 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
