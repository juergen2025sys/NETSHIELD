# Seen-DB Expiry Forecast

Lauf: 2026-09-27 03:17 CEST (Europe/Berlin)
Gesamt: 11,765,767 IPs in seen_db.json (8,902,695 aktiv/180-Tage-Pfad, 2,863,072 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 75,252 |
| 8-14 Tage | 401,558 |
| 15-30 Tage | 2,044,647 |
| 31-60 Tage | 1,019,352 |
| 61-90 Tage | 863,601 |
| 91-180 Tage | 4,498,285 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 1,237,724 |
| 0-3 Tage | 66,633 |
| 4-7 Tage | 1,323,896 |
| 8-14 Tage | 50,082 |
| 15-30 Tage | 184,737 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-27 | 6,255 |
| 2026-09-28 | 770 |
| 2026-09-30 | 59,608 |
| 2026-10-01 | 7,623 |
| 2026-10-02 | 1,306,405 |
| 2026-10-03 | 2,962 |
| 2026-10-04 | 6,906 |
| 2026-10-05 | 2,892 |
| 2026-10-06 | 7,991 |
| 2026-10-07 | 7,932 |
| 2026-10-08 | 7,277 |
| 2026-10-09 | 10,162 |
| 2026-10-10 | 7,570 |
| 2026-10-11 | 6,258 |
| 2026-10-12 | 3,876 |
| 2026-10-13 | 8,309 |
| 2026-10-14 | 7,452 |
| 2026-10-15 | 8,331 |
| 2026-10-16 | 15,513 |
| 2026-10-17 | 9,966 |
| 2026-10-18 | 8,699 |
| 2026-10-19 | 5,177 |
| 2026-10-20 | 9,668 |
| 2026-10-21 | 9,607 |
| 2026-10-22 | 10,489 |
| 2026-10-23 | 12,529 |
| 2026-10-24 | 15,222 |
| 2026-10-25 | 11,181 |
| 2026-10-26 | 9,575 |
| 2026-10-27 | 35,807 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **1,237,724** IPs. Brutto faellig in den naechsten 30 Tagen: **1,622,012**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,799,736**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-27 | 6,255 | 2,000 |
| 2026-09-28 | 770 | 2,000 |
| 2026-09-30 | 59,608 | 2,000 |
| 2026-10-01 | 7,623 | 2,000 |
| 2026-10-02 | 1,306,405 | 2,000 |
| 2026-10-03 | 2,962 | 2,000 |
| 2026-10-04 | 6,906 | 2,000 |
| 2026-10-05 | 2,892 | 2,000 |
| 2026-10-06 | 7,991 | 2,000 |
| 2026-10-07 | 7,932 | 2,000 |
| 2026-10-08 | 7,277 | 2,000 |
| 2026-10-09 | 10,162 | 2,000 |
| 2026-10-10 | 7,570 | 2,000 |
| 2026-10-11 | 6,258 | 2,000 |
| 2026-10-12 | 3,876 | 2,000 |
| 2026-10-13 | 8,309 | 2,000 |
| 2026-10-14 | 7,452 | 2,000 |
| 2026-10-15 | 8,331 | 2,000 |
| 2026-10-16 | 15,513 | 2,000 |
| 2026-10-17 | 9,966 | 2,000 |
| 2026-10-18 | 8,699 | 2,000 |
| 2026-10-19 | 5,177 | 2,000 |
| 2026-10-20 | 9,668 | 2,000 |
| 2026-10-21 | 9,607 | 2,000 |
| 2026-10-22 | 10,489 | 2,000 |
| 2026-10-23 | 12,529 | 2,000 |
| 2026-10-24 | 15,222 | 2,000 |
| 2026-10-25 | 11,181 | 2,000 |
| 2026-10-26 | 9,575 | 2,000 |
| 2026-10-27 | 35,807 | 2,000 |

> Hinweis: Der Rueckstau von 2,799,736 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-28 | 11,589 |
| 2026-09-29 | 9,332 |
| 2026-09-30 | 10,146 |
| 2026-10-01 | 16,573 |
| 2026-10-02 | 7,707 |
| 2026-10-03 | 7,315 |
| 2026-10-04 | 12,590 |
| 2026-10-05 | 17,509 |
| 2026-10-06 | 16,092 |
| 2026-10-07 | 15,020 |
| 2026-10-08 | 61,301 |
| 2026-10-09 | 222,256 |
| 2026-10-10 | 53,342 |
| 2026-10-11 | 16,038 |
| 2026-10-12 | 66,566 |
| 2026-10-13 | 1,583,984 |
| 2026-10-14 | 32,918 |
| 2026-10-15 | 41,331 |
| 2026-10-16 | 51,285 |
| 2026-10-17 | 24,263 |
| 2026-10-18 | 14,260 |
| 2026-10-19 | 22,312 |
| 2026-10-20 | 11,136 |
| 2026-10-21 | 11,106 |
| 2026-10-22 | 30,730 |
| 2026-10-23 | 50,411 |
| 2026-10-24 | 41,712 |
| 2026-10-25 | 21,611 |
| 2026-10-26 | 20,334 |
| 2026-10-27 | 20,688 |
| 2026-10-28 | 15,799 |
| 2026-10-29 | 9,679 |
| 2026-10-30 | 61,938 |
| 2026-10-31 | 88,229 |
| 2026-11-01 | 27,871 |
| 2026-11-02 | 28,835 |
| 2026-11-03 | 29,811 |
| 2026-11-04 | 29,646 |
| 2026-11-05 | 25,298 |
| 2026-11-06 | 36,414 |
| 2026-11-07 | 24,488 |
| 2026-11-08 | 26,146 |
| 2026-11-09 | 25,585 |
| 2026-11-10 | 32,769 |
| 2026-11-11 | 22,406 |
| 2026-11-12 | 20,528 |
| 2026-11-13 | 19,685 |
| 2026-11-14 | 23,001 |
| 2026-11-15 | 17,488 |
| 2026-11-16 | 17,994 |
| 2026-11-17 | 15,275 |
| 2026-11-18 | 19,532 |
| 2026-11-19 | 174,058 |
| 2026-11-20 | 26,221 |
| 2026-11-21 | 61,525 |
| 2026-11-22 | 30,509 |
| 2026-11-23 | 25,744 |
| 2026-11-24 | 26,535 |
| 2026-11-25 | 27,620 |
| 2026-11-26 | 28,723 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
