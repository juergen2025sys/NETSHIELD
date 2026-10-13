# Seen-DB Expiry Forecast

Lauf: 2026-10-13 03:36 CEST (Europe/Berlin)
Gesamt: 10,731,401 IPs in seen_db.json (7,700,785 aktiv/180-Tage-Pfad, 3,030,616 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 196,695 |
| 8-14 Tage | 195,529 |
| 15-30 Tage | 503,113 |
| 31-60 Tage | 1,060,401 |
| 61-90 Tage | 693,262 |
| 91-180 Tage | 5,051,785 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,650,914 |
| 0-3 Tage | 39,247 |
| 4-7 Tage | 33,160 |
| 8-14 Tage | 102,797 |
| 15-30 Tage | 204,498 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-13 | 8,205 |
| 2026-10-14 | 7,383 |
| 2026-10-15 | 8,251 |
| 2026-10-16 | 15,408 |
| 2026-10-17 | 9,912 |
| 2026-10-18 | 8,615 |
| 2026-10-19 | 5,114 |
| 2026-10-20 | 9,519 |
| 2026-10-21 | 9,479 |
| 2026-10-22 | 10,342 |
| 2026-10-23 | 12,342 |
| 2026-10-24 | 15,009 |
| 2026-10-25 | 11,063 |
| 2026-10-26 | 9,412 |
| 2026-10-27 | 35,150 |
| 2026-10-28 | 11,250 |
| 2026-10-29 | 9,814 |
| 2026-10-30 | 20,068 |
| 2026-10-31 | 16,937 |
| 2026-11-01 | 15,325 |
| 2026-11-02 | 11,889 |
| 2026-11-03 | 16,597 |
| 2026-11-04 | 10,054 |
| 2026-11-05 | 7,240 |
| 2026-11-06 | 12,067 |
| 2026-11-07 | 13,372 |
| 2026-11-08 | 6,277 |
| 2026-11-09 | 11,513 |
| 2026-11-10 | 23,881 |
| 2026-11-11 | 9,942 |
| 2026-11-12 | 8,166 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,650,914** IPs. Brutto faellig in den naechsten 30 Tagen: **379,596**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **2,968,510**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-13 | 8,205 | 2,000 |
| 2026-10-14 | 7,383 | 2,000 |
| 2026-10-15 | 8,251 | 2,000 |
| 2026-10-16 | 15,408 | 2,000 |
| 2026-10-17 | 9,912 | 2,000 |
| 2026-10-18 | 8,615 | 2,000 |
| 2026-10-19 | 5,114 | 2,000 |
| 2026-10-20 | 9,519 | 2,000 |
| 2026-10-21 | 9,479 | 2,000 |
| 2026-10-22 | 10,342 | 2,000 |
| 2026-10-23 | 12,342 | 2,000 |
| 2026-10-24 | 15,009 | 2,000 |
| 2026-10-25 | 11,063 | 2,000 |
| 2026-10-26 | 9,412 | 2,000 |
| 2026-10-27 | 35,150 | 2,000 |
| 2026-10-28 | 11,250 | 2,000 |
| 2026-10-29 | 9,814 | 2,000 |
| 2026-10-30 | 20,068 | 2,000 |
| 2026-10-31 | 16,937 | 2,000 |
| 2026-11-01 | 15,325 | 2,000 |
| 2026-11-02 | 11,889 | 2,000 |
| 2026-11-03 | 16,597 | 2,000 |
| 2026-11-04 | 10,054 | 2,000 |
| 2026-11-05 | 7,240 | 2,000 |
| 2026-11-06 | 12,067 | 2,000 |
| 2026-11-07 | 13,372 | 2,000 |
| 2026-11-08 | 6,277 | 2,000 |
| 2026-11-09 | 11,513 | 2,000 |
| 2026-11-10 | 23,881 | 2,000 |
| 2026-11-11 | 9,942 | 2,000 |
| 2026-11-12 | 8,166 | 2,000 |

> Hinweis: Der Rueckstau von 2,968,510 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-14 | 32,901 |
| 2026-10-15 | 41,270 |
| 2026-10-16 | 51,133 |
| 2026-10-17 | 24,159 |
| 2026-10-18 | 14,166 |
| 2026-10-19 | 22,004 |
| 2026-10-20 | 11,062 |
| 2026-10-21 | 11,027 |
| 2026-10-22 | 30,487 |
| 2026-10-23 | 50,226 |
| 2026-10-24 | 41,581 |
| 2026-10-25 | 21,493 |
| 2026-10-26 | 20,204 |
| 2026-10-27 | 20,511 |
| 2026-10-28 | 15,661 |
| 2026-10-29 | 9,585 |
| 2026-10-30 | 61,613 |
| 2026-10-31 | 88,054 |
| 2026-11-01 | 27,745 |
| 2026-11-02 | 28,691 |
| 2026-11-03 | 29,638 |
| 2026-11-04 | 29,495 |
| 2026-11-05 | 25,169 |
| 2026-11-06 | 36,231 |
| 2026-11-07 | 24,367 |
| 2026-11-08 | 26,032 |
| 2026-11-09 | 25,463 |
| 2026-11-10 | 32,623 |
| 2026-11-11 | 22,292 |
| 2026-11-12 | 20,454 |
| 2026-11-13 | 19,603 |
| 2026-11-14 | 22,903 |
| 2026-11-15 | 17,416 |
| 2026-11-16 | 17,916 |
| 2026-11-17 | 15,202 |
| 2026-11-18 | 19,455 |
| 2026-11-19 | 173,477 |
| 2026-11-20 | 26,092 |
| 2026-11-21 | 61,267 |
| 2026-11-22 | 30,352 |
| 2026-11-23 | 25,611 |
| 2026-11-24 | 26,418 |
| 2026-11-25 | 27,472 |
| 2026-11-26 | 28,616 |
| 2026-11-27 | 27,797 |
| 2026-11-28 | 109,149 |
| 2026-11-29 | 28,133 |
| 2026-11-30 | 25,498 |
| 2026-12-01 | 26,511 |
| 2026-12-02 | 26,166 |
| 2026-12-03 | 25,982 |
| 2026-12-04 | 27,886 |
| 2026-12-05 | 25,931 |
| 2026-12-06 | 30,110 |
| 2026-12-07 | 23,721 |
| 2026-12-08 | 39,354 |
| 2026-12-09 | 55,143 |
| 2026-12-10 | 25,081 |
| 2026-12-11 | 27,751 |
| 2026-12-12 | 24,388 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
