# Seen-DB Expiry Forecast

Lauf: 2026-10-19 00:23 CEST (Europe/Berlin)
Gesamt: 10,919,354 IPs in seen_db.json (7,835,641 aktiv/180-Tage-Pfad, 3,083,713 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 187,694 |
| 8-14 Tage | 243,000 |
| 15-30 Tage | 393,194 |
| 31-60 Tage | 1,082,002 |
| 61-90 Tage | 695,434 |
| 91-180 Tage | 5,234,317 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,692,632 |
| 0-3 Tage | 32,693 |
| 4-7 Tage | 48,716 |
| 8-14 Tage | 117,808 |
| 15-30 Tage | 191,864 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-18 | 8,611 |
| 2026-10-19 | 5,107 |
| 2026-10-20 | 9,505 |
| 2026-10-21 | 9,470 |
| 2026-10-22 | 10,335 |
| 2026-10-23 | 12,332 |
| 2026-10-24 | 15,000 |
| 2026-10-25 | 11,049 |
| 2026-10-26 | 9,403 |
| 2026-10-27 | 35,088 |
| 2026-10-28 | 11,245 |
| 2026-10-29 | 9,806 |
| 2026-10-30 | 20,048 |
| 2026-10-31 | 16,905 |
| 2026-11-01 | 15,313 |
| 2026-11-02 | 11,878 |
| 2026-11-03 | 16,584 |
| 2026-11-04 | 10,045 |
| 2026-11-05 | 7,228 |
| 2026-11-06 | 12,050 |
| 2026-11-07 | 13,339 |
| 2026-11-08 | 6,254 |
| 2026-11-09 | 11,471 |
| 2026-11-10 | 23,825 |
| 2026-11-11 | 9,889 |
| 2026-11-12 | 8,051 |
| 2026-11-13 | 3,344 |
| 2026-11-14 | 11,636 |
| 2026-11-15 | 14,366 |
| 2026-11-16 | 18,973 |
| 2026-11-17 | 9,398 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,692,632** IPs. Brutto faellig in den naechsten 30 Tagen: **387,548**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,018,180**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-18 | 8,611 | 2,000 |
| 2026-10-19 | 5,107 | 2,000 |
| 2026-10-20 | 9,505 | 2,000 |
| 2026-10-21 | 9,470 | 2,000 |
| 2026-10-22 | 10,335 | 2,000 |
| 2026-10-23 | 12,332 | 2,000 |
| 2026-10-24 | 15,000 | 2,000 |
| 2026-10-25 | 11,049 | 2,000 |
| 2026-10-26 | 9,403 | 2,000 |
| 2026-10-27 | 35,088 | 2,000 |
| 2026-10-28 | 11,245 | 2,000 |
| 2026-10-29 | 9,806 | 2,000 |
| 2026-10-30 | 20,048 | 2,000 |
| 2026-10-31 | 16,905 | 2,000 |
| 2026-11-01 | 15,313 | 2,000 |
| 2026-11-02 | 11,878 | 2,000 |
| 2026-11-03 | 16,584 | 2,000 |
| 2026-11-04 | 10,045 | 2,000 |
| 2026-11-05 | 7,228 | 2,000 |
| 2026-11-06 | 12,050 | 2,000 |
| 2026-11-07 | 13,339 | 2,000 |
| 2026-11-08 | 6,254 | 2,000 |
| 2026-11-09 | 11,471 | 2,000 |
| 2026-11-10 | 23,825 | 2,000 |
| 2026-11-11 | 9,889 | 2,000 |
| 2026-11-12 | 8,051 | 2,000 |
| 2026-11-13 | 3,344 | 2,000 |
| 2026-11-14 | 11,636 | 2,000 |
| 2026-11-15 | 14,366 | 2,000 |
| 2026-11-16 | 18,973 | 2,000 |
| 2026-11-17 | 9,398 | 2,000 |

> Hinweis: Der Rueckstau von 3,018,180 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-19 | 21,951 |
| 2026-10-20 | 11,054 |
| 2026-10-21 | 11,013 |
| 2026-10-22 | 30,451 |
| 2026-10-23 | 50,192 |
| 2026-10-24 | 41,561 |
| 2026-10-25 | 21,472 |
| 2026-10-26 | 20,181 |
| 2026-10-27 | 20,420 |
| 2026-10-28 | 15,551 |
| 2026-10-29 | 9,521 |
| 2026-10-30 | 61,576 |
| 2026-10-31 | 88,032 |
| 2026-11-01 | 27,719 |
| 2026-11-02 | 28,674 |
| 2026-11-03 | 29,616 |
| 2026-11-04 | 29,470 |
| 2026-11-05 | 25,152 |
| 2026-11-06 | 36,205 |
| 2026-11-07 | 24,354 |
| 2026-11-08 | 26,014 |
| 2026-11-09 | 25,437 |
| 2026-11-10 | 32,598 |
| 2026-11-11 | 22,267 |
| 2026-11-12 | 20,439 |
| 2026-11-13 | 19,586 |
| 2026-11-14 | 22,880 |
| 2026-11-15 | 17,405 |
| 2026-11-16 | 17,905 |
| 2026-11-17 | 15,192 |
| 2026-11-18 | 19,447 |
| 2026-11-19 | 173,439 |
| 2026-11-20 | 26,075 |
| 2026-11-21 | 61,239 |
| 2026-11-22 | 30,333 |
| 2026-11-23 | 25,591 |
| 2026-11-24 | 26,399 |
| 2026-11-25 | 27,455 |
| 2026-11-26 | 28,599 |
| 2026-11-27 | 27,784 |
| 2026-11-28 | 109,120 |
| 2026-11-29 | 28,122 |
| 2026-11-30 | 25,481 |
| 2026-12-01 | 26,492 |
| 2026-12-02 | 26,148 |
| 2026-12-03 | 25,966 |
| 2026-12-04 | 27,870 |
| 2026-12-05 | 25,916 |
| 2026-12-06 | 30,089 |
| 2026-12-07 | 23,706 |
| 2026-12-08 | 39,335 |
| 2026-12-09 | 55,060 |
| 2026-12-10 | 25,058 |
| 2026-12-11 | 27,736 |
| 2026-12-12 | 24,365 |
| 2026-12-13 | 23,835 |
| 2026-12-14 | 23,446 |
| 2026-12-15 | 26,231 |
| 2026-12-16 | 16,660 |
| 2026-12-17 | 25,005 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
