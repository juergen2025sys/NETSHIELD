# Seen-DB Expiry Forecast

Lauf: 2026-09-16 01:39 CEST (Europe/Berlin)
Gesamt: 11,292,784 IPs in seen_db.json (8,368,053 aktiv/180-Tage-Pfad, 2,924,731 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 6,441 |
| 8-14 Tage | 104,405 |
| 15-30 Tage | 2,187,009 |
| 31-60 Tage | 871,450 |
| 61-90 Tage | 1,073,694 |
| 91-180 Tage | 4,125,054 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 534,545 |
| 0-3 Tage | 36,335 |
| 4-7 Tage | 26,393 |
| 8-14 Tage | 653,260 |
| 15-30 Tage | 1,674,198 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-15 | 15,567 |
| 2026-09-16 | 6,233 |
| 2026-09-17 | 5,759 |
| 2026-09-18 | 8,776 |
| 2026-09-19 | 5,135 |
| 2026-09-20 | 5,056 |
| 2026-09-21 | 5,031 |
| 2026-09-22 | 11,171 |
| 2026-09-23 | 5,135 |
| 2026-09-24 | 11,418 |
| 2026-09-25 | 5,487 |
| 2026-09-26 | 624,122 |
| 2026-09-27 | 6,319 |
| 2026-09-28 | 779 |
| 2026-09-30 | 59,795 |
| 2026-10-01 | 7,689 |
| 2026-10-02 | 1,308,579 |
| 2026-10-03 | 2,985 |
| 2026-10-04 | 6,954 |
| 2026-10-05 | 2,919 |
| 2026-10-06 | 8,310 |
| 2026-10-07 | 8,048 |
| 2026-10-08 | 7,364 |
| 2026-10-09 | 152,284 |
| 2026-10-10 | 8,263 |
| 2026-10-11 | 23,305 |
| 2026-10-12 | 33,422 |
| 2026-10-13 | 9,133 |
| 2026-10-14 | 8,163 |
| 2026-10-15 | 9,309 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **534,545** IPs. Brutto faellig in den naechsten 30 Tagen: **2,372,510**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,847,055**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-15 | 15,567 | 2,000 |
| 2026-09-16 | 6,233 | 2,000 |
| 2026-09-17 | 5,759 | 2,000 |
| 2026-09-18 | 8,776 | 2,000 |
| 2026-09-19 | 5,135 | 2,000 |
| 2026-09-20 | 5,056 | 2,000 |
| 2026-09-21 | 5,031 | 2,000 |
| 2026-09-22 | 11,171 | 2,000 |
| 2026-09-23 | 5,135 | 2,000 |
| 2026-09-24 | 11,418 | 2,000 |
| 2026-09-25 | 5,487 | 2,000 |
| 2026-09-26 | 624,122 | 2,000 |
| 2026-09-27 | 6,319 | 2,000 |
| 2026-09-28 | 779 | 2,000 |
| 2026-09-30 | 59,795 | 2,000 |
| 2026-10-01 | 7,689 | 2,000 |
| 2026-10-02 | 1,308,579 | 2,000 |
| 2026-10-03 | 2,985 | 2,000 |
| 2026-10-04 | 6,954 | 2,000 |
| 2026-10-05 | 2,919 | 2,000 |
| 2026-10-06 | 8,310 | 2,000 |
| 2026-10-07 | 8,048 | 2,000 |
| 2026-10-08 | 7,364 | 2,000 |
| 2026-10-09 | 152,284 | 2,000 |
| 2026-10-10 | 8,263 | 2,000 |
| 2026-10-11 | 23,305 | 2,000 |
| 2026-10-12 | 33,422 | 2,000 |
| 2026-10-13 | 9,133 | 2,000 |
| 2026-10-14 | 8,163 | 2,000 |
| 2026-10-15 | 9,309 | 2,000 |

> Hinweis: Der Rueckstau von 2,847,055 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,441 |
| 2026-09-23 | 13,088 |
| 2026-09-24 | 16,724 |
| 2026-09-25 | 20,990 |
| 2026-09-26 | 17,503 |
| 2026-09-27 | 15,088 |
| 2026-09-28 | 11,625 |
| 2026-09-29 | 9,387 |
| 2026-09-30 | 10,223 |
| 2026-10-01 | 16,638 |
| 2026-10-02 | 7,751 |
| 2026-10-03 | 7,354 |
| 2026-10-04 | 12,674 |
| 2026-10-05 | 17,600 |
| 2026-10-06 | 16,177 |
| 2026-10-07 | 15,112 |
| 2026-10-08 | 61,659 |
| 2026-10-09 | 224,018 |
| 2026-10-10 | 53,444 |
| 2026-10-11 | 16,079 |
| 2026-10-12 | 66,629 |
| 2026-10-13 | 1,587,326 |
| 2026-10-14 | 32,938 |
| 2026-10-15 | 41,387 |
| 2026-10-16 | 51,422 |
| 2026-10-17 | 24,385 |
| 2026-10-18 | 14,327 |
| 2026-10-19 | 22,499 |
| 2026-10-20 | 11,180 |
| 2026-10-21 | 11,157 |
| 2026-10-22 | 30,851 |
| 2026-10-23 | 50,519 |
| 2026-10-24 | 41,830 |
| 2026-10-25 | 21,693 |
| 2026-10-26 | 20,431 |
| 2026-10-27 | 20,785 |
| 2026-10-28 | 15,866 |
| 2026-10-29 | 9,752 |
| 2026-10-30 | 62,167 |
| 2026-10-31 | 88,326 |
| 2026-11-01 | 27,973 |
| 2026-11-02 | 28,953 |
| 2026-11-03 | 29,974 |
| 2026-11-04 | 29,784 |
| 2026-11-05 | 25,397 |
| 2026-11-06 | 36,833 |
| 2026-11-07 | 24,585 |
| 2026-11-08 | 26,254 |
| 2026-11-09 | 25,698 |
| 2026-11-10 | 32,887 |
| 2026-11-11 | 22,502 |
| 2026-11-12 | 20,588 |
| 2026-11-13 | 19,744 |
| 2026-11-14 | 23,088 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 191765 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
