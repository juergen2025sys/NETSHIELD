# Seen-DB Expiry Forecast

Lauf: 2026-10-02 04:32 CEST (Europe/Berlin)
Gesamt: 12,035,157 IPs in seen_db.json (9,104,798 aktiv/180-Tage-Pfad, 2,930,359 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 351,040 |
| 8-14 Tage | 1,843,883 |
| 15-30 Tage | 471,256 |
| 31-60 Tage | 1,032,111 |
| 61-90 Tage | 760,918 |
| 91-180 Tage | 4,645,590 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 1,311,729 |
| 0-3 Tage | 1,316,066 |
| 4-7 Tage | 33,240 |
| 8-14 Tage | 57,127 |
| 15-30 Tage | 212,197 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-02 | 1,303,422 |
| 2026-10-03 | 2,947 |
| 2026-10-04 | 6,836 |
| 2026-10-05 | 2,861 |
| 2026-10-06 | 7,942 |
| 2026-10-07 | 7,905 |
| 2026-10-08 | 7,257 |
| 2026-10-09 | 10,136 |
| 2026-10-10 | 7,539 |
| 2026-10-11 | 6,244 |
| 2026-10-12 | 3,866 |
| 2026-10-13 | 8,265 |
| 2026-10-14 | 7,428 |
| 2026-10-15 | 8,308 |
| 2026-10-16 | 15,477 |
| 2026-10-17 | 9,943 |
| 2026-10-18 | 8,660 |
| 2026-10-19 | 5,153 |
| 2026-10-20 | 9,608 |
| 2026-10-21 | 9,558 |
| 2026-10-22 | 10,409 |
| 2026-10-23 | 12,438 |
| 2026-10-24 | 15,102 |
| 2026-10-25 | 11,131 |
| 2026-10-26 | 9,487 |
| 2026-10-27 | 35,340 |
| 2026-10-28 | 11,328 |
| 2026-10-29 | 9,895 |
| 2026-10-30 | 20,233 |
| 2026-10-31 | 17,232 |
| 2026-11-01 | 15,938 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **1,311,729** IPs. Brutto faellig in den naechsten 30 Tagen: **1,617,888**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **2,867,617**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-02 | 1,303,422 | 2,000 |
| 2026-10-03 | 2,947 | 2,000 |
| 2026-10-04 | 6,836 | 2,000 |
| 2026-10-05 | 2,861 | 2,000 |
| 2026-10-06 | 7,942 | 2,000 |
| 2026-10-07 | 7,905 | 2,000 |
| 2026-10-08 | 7,257 | 2,000 |
| 2026-10-09 | 10,136 | 2,000 |
| 2026-10-10 | 7,539 | 2,000 |
| 2026-10-11 | 6,244 | 2,000 |
| 2026-10-12 | 3,866 | 2,000 |
| 2026-10-13 | 8,265 | 2,000 |
| 2026-10-14 | 7,428 | 2,000 |
| 2026-10-15 | 8,308 | 2,000 |
| 2026-10-16 | 15,477 | 2,000 |
| 2026-10-17 | 9,943 | 2,000 |
| 2026-10-18 | 8,660 | 2,000 |
| 2026-10-19 | 5,153 | 2,000 |
| 2026-10-20 | 9,608 | 2,000 |
| 2026-10-21 | 9,558 | 2,000 |
| 2026-10-22 | 10,409 | 2,000 |
| 2026-10-23 | 12,438 | 2,000 |
| 2026-10-24 | 15,102 | 2,000 |
| 2026-10-25 | 11,131 | 2,000 |
| 2026-10-26 | 9,487 | 2,000 |
| 2026-10-27 | 35,340 | 2,000 |
| 2026-10-28 | 11,328 | 2,000 |
| 2026-10-29 | 9,895 | 2,000 |
| 2026-10-30 | 20,233 | 2,000 |
| 2026-10-31 | 17,232 | 2,000 |
| 2026-11-01 | 15,938 | 2,000 |

> Hinweis: Der Rueckstau von 2,867,617 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-03 | 7,295 |
| 2026-10-04 | 12,550 |
| 2026-10-05 | 17,475 |
| 2026-10-06 | 16,047 |
| 2026-10-07 | 14,982 |
| 2026-10-08 | 61,116 |
| 2026-10-09 | 221,575 |
| 2026-10-10 | 53,303 |
| 2026-10-11 | 16,015 |
| 2026-10-12 | 66,531 |
| 2026-10-13 | 1,582,587 |
| 2026-10-14 | 32,912 |
| 2026-10-15 | 41,303 |
| 2026-10-16 | 51,232 |
| 2026-10-17 | 24,225 |
| 2026-10-18 | 14,233 |
| 2026-10-19 | 22,205 |
| 2026-10-20 | 11,117 |
| 2026-10-21 | 11,078 |
| 2026-10-22 | 30,686 |
| 2026-10-23 | 50,348 |
| 2026-10-24 | 41,664 |
| 2026-10-25 | 21,572 |
| 2026-10-26 | 20,291 |
| 2026-10-27 | 20,620 |
| 2026-10-28 | 15,754 |
| 2026-10-29 | 9,645 |
| 2026-10-30 | 61,828 |
| 2026-10-31 | 88,167 |
| 2026-11-01 | 27,823 |
| 2026-11-02 | 28,782 |
| 2026-11-03 | 29,753 |
| 2026-11-04 | 29,594 |
| 2026-11-05 | 25,248 |
| 2026-11-06 | 36,349 |
| 2026-11-07 | 24,454 |
| 2026-11-08 | 26,109 |
| 2026-11-09 | 25,550 |
| 2026-11-10 | 32,713 |
| 2026-11-11 | 22,362 |
| 2026-11-12 | 20,503 |
| 2026-11-13 | 19,652 |
| 2026-11-14 | 22,970 |
| 2026-11-15 | 17,456 |
| 2026-11-16 | 17,971 |
| 2026-11-17 | 15,259 |
| 2026-11-18 | 19,507 |
| 2026-11-19 | 173,863 |
| 2026-11-20 | 26,177 |
| 2026-11-21 | 61,431 |
| 2026-11-22 | 30,448 |
| 2026-11-23 | 25,704 |
| 2026-11-24 | 26,494 |
| 2026-11-25 | 27,577 |
| 2026-11-26 | 28,691 |
| 2026-11-27 | 27,867 |
| 2026-11-28 | 109,246 |
| 2026-11-29 | 28,212 |
| 2026-11-30 | 25,579 |
| 2026-12-01 | 26,590 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
