# Seen-DB Expiry Forecast

Lauf: 2026-10-17 21:42 CEST (Europe/Berlin)
Gesamt: 10,863,828 IPs in seen_db.json (7,784,204 aktiv/180-Tage-Pfad, 3,079,624 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 180,401 |
| 8-14 Tage | 236,798 |
| 15-30 Tage | 405,777 |
| 31-60 Tage | 1,072,317 |
| 61-90 Tage | 693,666 |
| 91-180 Tage | 5,195,245 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,683,201 |
| 0-3 Tage | 33,134 |
| 4-7 Tage | 47,146 |
| 8-14 Tage | 113,575 |
| 15-30 Tage | 202,568 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-17 | 9,907 |
| 2026-10-18 | 8,612 |
| 2026-10-19 | 5,108 |
| 2026-10-20 | 9,507 |
| 2026-10-21 | 9,473 |
| 2026-10-22 | 10,336 |
| 2026-10-23 | 12,334 |
| 2026-10-24 | 15,003 |
| 2026-10-25 | 11,051 |
| 2026-10-26 | 9,407 |
| 2026-10-27 | 35,103 |
| 2026-10-28 | 11,249 |
| 2026-10-29 | 9,808 |
| 2026-10-30 | 20,049 |
| 2026-10-31 | 16,908 |
| 2026-11-01 | 15,315 |
| 2026-11-02 | 11,879 |
| 2026-11-03 | 16,586 |
| 2026-11-04 | 10,046 |
| 2026-11-05 | 7,230 |
| 2026-11-06 | 12,052 |
| 2026-11-07 | 13,344 |
| 2026-11-08 | 6,257 |
| 2026-11-09 | 11,473 |
| 2026-11-10 | 23,836 |
| 2026-11-11 | 9,899 |
| 2026-11-12 | 8,058 |
| 2026-11-13 | 3,346 |
| 2026-11-14 | 11,654 |
| 2026-11-15 | 14,382 |
| 2026-11-16 | 18,997 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,683,201** IPs. Brutto faellig in den naechsten 30 Tagen: **388,209**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,009,410**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-17 | 9,907 | 2,000 |
| 2026-10-18 | 8,612 | 2,000 |
| 2026-10-19 | 5,108 | 2,000 |
| 2026-10-20 | 9,507 | 2,000 |
| 2026-10-21 | 9,473 | 2,000 |
| 2026-10-22 | 10,336 | 2,000 |
| 2026-10-23 | 12,334 | 2,000 |
| 2026-10-24 | 15,003 | 2,000 |
| 2026-10-25 | 11,051 | 2,000 |
| 2026-10-26 | 9,407 | 2,000 |
| 2026-10-27 | 35,103 | 2,000 |
| 2026-10-28 | 11,249 | 2,000 |
| 2026-10-29 | 9,808 | 2,000 |
| 2026-10-30 | 20,049 | 2,000 |
| 2026-10-31 | 16,908 | 2,000 |
| 2026-11-01 | 15,315 | 2,000 |
| 2026-11-02 | 11,879 | 2,000 |
| 2026-11-03 | 16,586 | 2,000 |
| 2026-11-04 | 10,046 | 2,000 |
| 2026-11-05 | 7,230 | 2,000 |
| 2026-11-06 | 12,052 | 2,000 |
| 2026-11-07 | 13,344 | 2,000 |
| 2026-11-08 | 6,257 | 2,000 |
| 2026-11-09 | 11,473 | 2,000 |
| 2026-11-10 | 23,836 | 2,000 |
| 2026-11-11 | 9,899 | 2,000 |
| 2026-11-12 | 8,058 | 2,000 |
| 2026-11-13 | 3,346 | 2,000 |
| 2026-11-14 | 11,654 | 2,000 |
| 2026-11-15 | 14,382 | 2,000 |
| 2026-11-16 | 18,997 | 2,000 |

> Hinweis: Der Rueckstau von 3,009,410 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-18 | 14,154 |
| 2026-10-19 | 21,958 |
| 2026-10-20 | 11,054 |
| 2026-10-21 | 11,015 |
| 2026-10-22 | 30,457 |
| 2026-10-23 | 50,197 |
| 2026-10-24 | 41,566 |
| 2026-10-25 | 21,474 |
| 2026-10-26 | 20,183 |
| 2026-10-27 | 20,428 |
| 2026-10-28 | 15,570 |
| 2026-10-29 | 9,525 |
| 2026-10-30 | 61,581 |
| 2026-10-31 | 88,037 |
| 2026-11-01 | 27,722 |
| 2026-11-02 | 28,677 |
| 2026-11-03 | 29,621 |
| 2026-11-04 | 29,474 |
| 2026-11-05 | 25,155 |
| 2026-11-06 | 36,211 |
| 2026-11-07 | 24,358 |
| 2026-11-08 | 26,015 |
| 2026-11-09 | 25,444 |
| 2026-11-10 | 32,601 |
| 2026-11-11 | 22,273 |
| 2026-11-12 | 20,441 |
| 2026-11-13 | 19,590 |
| 2026-11-14 | 22,882 |
| 2026-11-15 | 17,406 |
| 2026-11-16 | 17,907 |
| 2026-11-17 | 15,193 |
| 2026-11-18 | 19,448 |
| 2026-11-19 | 173,448 |
| 2026-11-20 | 26,079 |
| 2026-11-21 | 61,243 |
| 2026-11-22 | 30,334 |
| 2026-11-23 | 25,594 |
| 2026-11-24 | 26,402 |
| 2026-11-25 | 27,458 |
| 2026-11-26 | 28,601 |
| 2026-11-27 | 27,785 |
| 2026-11-28 | 109,123 |
| 2026-11-29 | 28,125 |
| 2026-11-30 | 25,482 |
| 2026-12-01 | 26,499 |
| 2026-12-02 | 26,154 |
| 2026-12-03 | 25,969 |
| 2026-12-04 | 27,873 |
| 2026-12-05 | 25,920 |
| 2026-12-06 | 30,094 |
| 2026-12-07 | 23,707 |
| 2026-12-08 | 39,336 |
| 2026-12-09 | 55,075 |
| 2026-12-10 | 25,062 |
| 2026-12-11 | 27,740 |
| 2026-12-12 | 24,371 |
| 2026-12-13 | 23,838 |
| 2026-12-14 | 23,450 |
| 2026-12-15 | 26,240 |
| 2026-12-16 | 16,674 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
