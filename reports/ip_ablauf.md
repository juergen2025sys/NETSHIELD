# Seen-DB Expiry Forecast

Lauf: 2026-09-28 13:57 CEST (Europe/Berlin)
Gesamt: 11,827,769 IPs in seen_db.json (8,948,263 aktiv/180-Tage-Pfad, 2,879,506 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 81,115 |
| 8-14 Tage | 450,350 |
| 15-30 Tage | 1,993,400 |
| 31-60 Tage | 1,031,136 |
| 61-90 Tage | 860,281 |
| 91-180 Tage | 4,531,981 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 1,245,369 |
| 0-3 Tage | 67,916 |
| 4-7 Tage | 1,318,986 |
| 8-14 Tage | 51,034 |
| 15-30 Tage | 196,201 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-28 | 770 |
| 2026-09-30 | 59,528 |
| 2026-10-01 | 7,618 |
| 2026-10-02 | 1,306,248 |
| 2026-10-03 | 2,962 |
| 2026-10-04 | 6,895 |
| 2026-10-05 | 2,881 |
| 2026-10-06 | 7,986 |
| 2026-10-07 | 7,926 |
| 2026-10-08 | 7,273 |
| 2026-10-09 | 10,156 |
| 2026-10-10 | 7,563 |
| 2026-10-11 | 6,255 |
| 2026-10-12 | 3,875 |
| 2026-10-13 | 8,299 |
| 2026-10-14 | 7,443 |
| 2026-10-15 | 8,326 |
| 2026-10-16 | 15,508 |
| 2026-10-17 | 9,960 |
| 2026-10-18 | 8,692 |
| 2026-10-19 | 5,171 |
| 2026-10-20 | 9,652 |
| 2026-10-21 | 9,589 |
| 2026-10-22 | 10,471 |
| 2026-10-23 | 12,509 |
| 2026-10-24 | 15,182 |
| 2026-10-25 | 11,166 |
| 2026-10-26 | 9,538 |
| 2026-10-27 | 35,469 |
| 2026-10-28 | 11,687 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **1,245,369** IPs. Brutto faellig in den naechsten 30 Tagen: **1,626,598**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,811,967**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-28 | 770 | 2,000 |
| 2026-09-30 | 59,528 | 2,000 |
| 2026-10-01 | 7,618 | 2,000 |
| 2026-10-02 | 1,306,248 | 2,000 |
| 2026-10-03 | 2,962 | 2,000 |
| 2026-10-04 | 6,895 | 2,000 |
| 2026-10-05 | 2,881 | 2,000 |
| 2026-10-06 | 7,986 | 2,000 |
| 2026-10-07 | 7,926 | 2,000 |
| 2026-10-08 | 7,273 | 2,000 |
| 2026-10-09 | 10,156 | 2,000 |
| 2026-10-10 | 7,563 | 2,000 |
| 2026-10-11 | 6,255 | 2,000 |
| 2026-10-12 | 3,875 | 2,000 |
| 2026-10-13 | 8,299 | 2,000 |
| 2026-10-14 | 7,443 | 2,000 |
| 2026-10-15 | 8,326 | 2,000 |
| 2026-10-16 | 15,508 | 2,000 |
| 2026-10-17 | 9,960 | 2,000 |
| 2026-10-18 | 8,692 | 2,000 |
| 2026-10-19 | 5,171 | 2,000 |
| 2026-10-20 | 9,652 | 2,000 |
| 2026-10-21 | 9,589 | 2,000 |
| 2026-10-22 | 10,471 | 2,000 |
| 2026-10-23 | 12,509 | 2,000 |
| 2026-10-24 | 15,182 | 2,000 |
| 2026-10-25 | 11,166 | 2,000 |
| 2026-10-26 | 9,538 | 2,000 |
| 2026-10-27 | 35,469 | 2,000 |
| 2026-10-28 | 11,687 | 2,000 |

> Hinweis: Der Rueckstau von 2,811,967 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-29 | 9,326 |
| 2026-09-30 | 10,139 |
| 2026-10-01 | 16,558 |
| 2026-10-02 | 7,697 |
| 2026-10-03 | 7,309 |
| 2026-10-04 | 12,585 |
| 2026-10-05 | 17,501 |
| 2026-10-06 | 16,076 |
| 2026-10-07 | 15,014 |
| 2026-10-08 | 61,257 |
| 2026-10-09 | 222,080 |
| 2026-10-10 | 53,335 |
| 2026-10-11 | 16,031 |
| 2026-10-12 | 66,557 |
| 2026-10-13 | 1,583,637 |
| 2026-10-14 | 32,915 |
| 2026-10-15 | 41,325 |
| 2026-10-16 | 51,278 |
| 2026-10-17 | 24,258 |
| 2026-10-18 | 14,255 |
| 2026-10-19 | 22,292 |
| 2026-10-20 | 11,131 |
| 2026-10-21 | 11,097 |
| 2026-10-22 | 30,719 |
| 2026-10-23 | 50,402 |
| 2026-10-24 | 41,702 |
| 2026-10-25 | 21,599 |
| 2026-10-26 | 20,322 |
| 2026-10-27 | 20,676 |
| 2026-10-28 | 15,792 |
| 2026-10-29 | 9,674 |
| 2026-10-30 | 61,921 |
| 2026-10-31 | 88,215 |
| 2026-11-01 | 27,865 |
| 2026-11-02 | 28,818 |
| 2026-11-03 | 29,795 |
| 2026-11-04 | 29,639 |
| 2026-11-05 | 25,288 |
| 2026-11-06 | 36,402 |
| 2026-11-07 | 24,481 |
| 2026-11-08 | 26,136 |
| 2026-11-09 | 25,576 |
| 2026-11-10 | 32,756 |
| 2026-11-11 | 22,398 |
| 2026-11-12 | 20,523 |
| 2026-11-13 | 19,675 |
| 2026-11-14 | 22,998 |
| 2026-11-15 | 17,482 |
| 2026-11-16 | 17,989 |
| 2026-11-17 | 15,274 |
| 2026-11-18 | 19,530 |
| 2026-11-19 | 174,010 |
| 2026-11-20 | 26,212 |
| 2026-11-21 | 61,500 |
| 2026-11-22 | 30,499 |
| 2026-11-23 | 25,735 |
| 2026-11-24 | 26,527 |
| 2026-11-25 | 27,612 |
| 2026-11-26 | 28,710 |
| 2026-11-27 | 27,896 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
