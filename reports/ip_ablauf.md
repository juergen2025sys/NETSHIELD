# Seen-DB Expiry Forecast

Lauf: 2026-10-18 07:01 CEST (Europe/Berlin)
Gesamt: 10,870,469 IPs in seen_db.json (7,788,531 aktiv/180-Tage-Pfad, 3,081,938 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 187,713 |
| 8-14 Tage | 243,031 |
| 15-30 Tage | 393,228 |
| 31-60 Tage | 1,082,091 |
| 61-90 Tage | 695,520 |
| 91-180 Tage | 5,186,948 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,692,752 |
| 0-3 Tage | 32,700 |
| 4-7 Tage | 48,722 |
| 8-14 Tage | 117,834 |
| 15-30 Tage | 189,930 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-18 | 8,612 |
| 2026-10-19 | 5,108 |
| 2026-10-20 | 9,507 |
| 2026-10-21 | 9,473 |
| 2026-10-22 | 10,336 |
| 2026-10-23 | 12,333 |
| 2026-10-24 | 15,003 |
| 2026-10-25 | 11,050 |
| 2026-10-26 | 9,407 |
| 2026-10-27 | 35,099 |
| 2026-10-28 | 11,249 |
| 2026-10-29 | 9,808 |
| 2026-10-30 | 20,049 |
| 2026-10-31 | 16,907 |
| 2026-11-01 | 15,315 |
| 2026-11-02 | 11,879 |
| 2026-11-03 | 16,586 |
| 2026-11-04 | 10,046 |
| 2026-11-05 | 7,230 |
| 2026-11-06 | 12,052 |
| 2026-11-07 | 13,344 |
| 2026-11-08 | 6,256 |
| 2026-11-09 | 11,473 |
| 2026-11-10 | 23,833 |
| 2026-11-11 | 9,896 |
| 2026-11-12 | 8,056 |
| 2026-11-13 | 3,345 |
| 2026-11-14 | 11,651 |
| 2026-11-15 | 14,380 |
| 2026-11-16 | 18,990 |
| 2026-11-17 | 9,422 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,692,752** IPs. Brutto faellig in den naechsten 30 Tagen: **387,695**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,018,447**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-18 | 8,612 | 2,000 |
| 2026-10-19 | 5,108 | 2,000 |
| 2026-10-20 | 9,507 | 2,000 |
| 2026-10-21 | 9,473 | 2,000 |
| 2026-10-22 | 10,336 | 2,000 |
| 2026-10-23 | 12,333 | 2,000 |
| 2026-10-24 | 15,003 | 2,000 |
| 2026-10-25 | 11,050 | 2,000 |
| 2026-10-26 | 9,407 | 2,000 |
| 2026-10-27 | 35,099 | 2,000 |
| 2026-10-28 | 11,249 | 2,000 |
| 2026-10-29 | 9,808 | 2,000 |
| 2026-10-30 | 20,049 | 2,000 |
| 2026-10-31 | 16,907 | 2,000 |
| 2026-11-01 | 15,315 | 2,000 |
| 2026-11-02 | 11,879 | 2,000 |
| 2026-11-03 | 16,586 | 2,000 |
| 2026-11-04 | 10,046 | 2,000 |
| 2026-11-05 | 7,230 | 2,000 |
| 2026-11-06 | 12,052 | 2,000 |
| 2026-11-07 | 13,344 | 2,000 |
| 2026-11-08 | 6,256 | 2,000 |
| 2026-11-09 | 11,473 | 2,000 |
| 2026-11-10 | 23,833 | 2,000 |
| 2026-11-11 | 9,896 | 2,000 |
| 2026-11-12 | 8,056 | 2,000 |
| 2026-11-13 | 3,345 | 2,000 |
| 2026-11-14 | 11,651 | 2,000 |
| 2026-11-15 | 14,380 | 2,000 |
| 2026-11-16 | 18,990 | 2,000 |
| 2026-11-17 | 9,422 | 2,000 |

> Hinweis: Der Rueckstau von 3,018,447 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-19 | 21,957 |
| 2026-10-20 | 11,054 |
| 2026-10-21 | 11,014 |
| 2026-10-22 | 30,454 |
| 2026-10-23 | 50,196 |
| 2026-10-24 | 41,564 |
| 2026-10-25 | 21,474 |
| 2026-10-26 | 20,182 |
| 2026-10-27 | 20,424 |
| 2026-10-28 | 15,563 |
| 2026-10-29 | 9,524 |
| 2026-10-30 | 61,580 |
| 2026-10-31 | 88,036 |
| 2026-11-01 | 27,722 |
| 2026-11-02 | 28,675 |
| 2026-11-03 | 29,620 |
| 2026-11-04 | 29,474 |
| 2026-11-05 | 25,153 |
| 2026-11-06 | 36,208 |
| 2026-11-07 | 24,357 |
| 2026-11-08 | 26,014 |
| 2026-11-09 | 25,442 |
| 2026-11-10 | 32,599 |
| 2026-11-11 | 22,272 |
| 2026-11-12 | 20,440 |
| 2026-11-13 | 19,587 |
| 2026-11-14 | 22,881 |
| 2026-11-15 | 17,406 |
| 2026-11-16 | 17,907 |
| 2026-11-17 | 15,193 |
| 2026-11-18 | 19,448 |
| 2026-11-19 | 173,444 |
| 2026-11-20 | 26,076 |
| 2026-11-21 | 61,242 |
| 2026-11-22 | 30,334 |
| 2026-11-23 | 25,593 |
| 2026-11-24 | 26,399 |
| 2026-11-25 | 27,458 |
| 2026-11-26 | 28,600 |
| 2026-11-27 | 27,785 |
| 2026-11-28 | 109,123 |
| 2026-11-29 | 28,124 |
| 2026-11-30 | 25,481 |
| 2026-12-01 | 26,497 |
| 2026-12-02 | 26,153 |
| 2026-12-03 | 25,967 |
| 2026-12-04 | 27,871 |
| 2026-12-05 | 25,920 |
| 2026-12-06 | 30,092 |
| 2026-12-07 | 23,707 |
| 2026-12-08 | 39,336 |
| 2026-12-09 | 55,073 |
| 2026-12-10 | 25,062 |
| 2026-12-11 | 27,740 |
| 2026-12-12 | 24,367 |
| 2026-12-13 | 23,837 |
| 2026-12-14 | 23,450 |
| 2026-12-15 | 26,236 |
| 2026-12-16 | 16,667 |
| 2026-12-17 | 25,009 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
