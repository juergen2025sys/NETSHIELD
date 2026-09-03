# Seen-DB Expiry Forecast

Lauf: 2026-09-03 18:18 CEST (Europe/Berlin)
Gesamt: 11,152,005 IPs in seen_db.json (8,507,179 aktiv/180-Tage-Pfad, 2,644,826 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 836,946 |
| 8-14 Tage | 0 |
| 15-30 Tage | 154,125 |
| 31-60 Tage | 2,711,085 |
| 61-90 Tage | 1,040,019 |
| 91-180 Tage | 3,765,004 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 185,706 |
| 0-3 Tage | 248,934 |
| 4-7 Tage | 55,254 |
| 8-14 Tage | 76,408 |
| 15-30 Tage | 2,078,524 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-03 | 10,947 |
| 2026-09-04 | 148,110 |
| 2026-09-05 | 69,360 |
| 2026-09-06 | 20,517 |
| 2026-09-07 | 16,293 |
| 2026-09-08 | 13,105 |
| 2026-09-09 | 17,032 |
| 2026-09-10 | 8,824 |
| 2026-09-11 | 11,409 |
| 2026-09-12 | 11,995 |
| 2026-09-13 | 12,138 |
| 2026-09-14 | 12,975 |
| 2026-09-15 | 15,737 |
| 2026-09-16 | 6,304 |
| 2026-09-17 | 5,850 |
| 2026-09-18 | 8,888 |
| 2026-09-19 | 5,207 |
| 2026-09-20 | 5,116 |
| 2026-09-21 | 5,110 |
| 2026-09-22 | 11,295 |
| 2026-09-23 | 5,217 |
| 2026-09-24 | 11,494 |
| 2026-09-25 | 5,577 |
| 2026-09-26 | 624,806 |
| 2026-09-27 | 6,424 |
| 2026-09-28 | 794 |
| 2026-09-30 | 60,180 |
| 2026-10-01 | 7,804 |
| 2026-10-02 | 1,311,583 |
| 2026-10-03 | 3,107 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **185,706** IPs. Brutto faellig in den naechsten 30 Tagen: **2,453,198**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,578,904**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-03 | 10,947 | 2,000 |
| 2026-09-04 | 148,110 | 2,000 |
| 2026-09-05 | 69,360 | 2,000 |
| 2026-09-06 | 20,517 | 2,000 |
| 2026-09-07 | 16,293 | 2,000 |
| 2026-09-08 | 13,105 | 2,000 |
| 2026-09-09 | 17,032 | 2,000 |
| 2026-09-10 | 8,824 | 2,000 |
| 2026-09-11 | 11,409 | 2,000 |
| 2026-09-12 | 11,995 | 2,000 |
| 2026-09-13 | 12,138 | 2,000 |
| 2026-09-14 | 12,975 | 2,000 |
| 2026-09-15 | 15,737 | 2,000 |
| 2026-09-16 | 6,304 | 2,000 |
| 2026-09-17 | 5,850 | 2,000 |
| 2026-09-18 | 8,888 | 2,000 |
| 2026-09-19 | 5,207 | 2,000 |
| 2026-09-20 | 5,116 | 2,000 |
| 2026-09-21 | 5,110 | 2,000 |
| 2026-09-22 | 11,295 | 2,000 |
| 2026-09-23 | 5,217 | 2,000 |
| 2026-09-24 | 11,494 | 2,000 |
| 2026-09-25 | 5,577 | 2,000 |
| 2026-09-26 | 624,806 | 2,000 |
| 2026-09-27 | 6,424 | 2,000 |
| 2026-09-28 | 794 | 2,000 |
| 2026-09-30 | 60,180 | 2,000 |
| 2026-10-01 | 7,804 | 2,000 |
| 2026-10-02 | 1,311,583 | 2,000 |
| 2026-10-03 | 3,107 | 2,000 |

> Hinweis: Der Rueckstau von 2,578,904 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-05 | 173,675 |
| 2026-09-08 | 663,271 |
| 2026-09-22 | 6,496 |
| 2026-09-23 | 13,196 |
| 2026-09-24 | 16,885 |
| 2026-09-25 | 21,173 |
| 2026-09-26 | 17,673 |
| 2026-09-27 | 15,256 |
| 2026-09-28 | 11,692 |
| 2026-09-29 | 9,451 |
| 2026-09-30 | 10,316 |
| 2026-10-01 | 16,747 |
| 2026-10-02 | 7,823 |
| 2026-10-03 | 7,417 |
| 2026-10-04 | 12,813 |
| 2026-10-05 | 17,729 |
| 2026-10-06 | 16,301 |
| 2026-10-07 | 15,217 |
| 2026-10-08 | 62,282 |
| 2026-10-09 | 226,608 |
| 2026-10-10 | 53,561 |
| 2026-10-11 | 16,124 |
| 2026-10-12 | 66,727 |
| 2026-10-13 | 1,592,360 |
| 2026-10-14 | 32,974 |
| 2026-10-15 | 41,469 |
| 2026-10-16 | 51,546 |
| 2026-10-17 | 24,512 |
| 2026-10-18 | 14,413 |
| 2026-10-19 | 22,797 |
| 2026-10-20 | 11,250 |
| 2026-10-21 | 11,230 |
| 2026-10-22 | 31,036 |
| 2026-10-23 | 50,677 |
| 2026-10-24 | 41,975 |
| 2026-10-25 | 21,839 |
| 2026-10-26 | 20,587 |
| 2026-10-27 | 20,937 |
| 2026-10-28 | 15,972 |
| 2026-10-29 | 9,845 |
| 2026-10-30 | 62,538 |
| 2026-10-31 | 88,519 |
| 2026-11-01 | 28,113 |
| 2026-11-02 | 29,134 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
