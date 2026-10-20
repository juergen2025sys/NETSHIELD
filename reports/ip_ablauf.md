# Seen-DB Expiry Forecast

Lauf: 2026-10-20 19:28 CEST (Europe/Berlin)
Gesamt: 11,009,379 IPs in seen_db.json (7,908,153 aktiv/180-Tage-Pfad, 3,101,226 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 195,241 |
| 8-14 Tage | 260,621 |
| 15-30 Tage | 527,676 |
| 31-60 Tage | 937,036 |
| 61-90 Tage | 692,697 |
| 91-180 Tage | 5,294,882 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,706,105 |
| 0-3 Tage | 41,620 |
| 4-7 Tage | 70,520 |
| 8-14 Tage | 101,760 |
| 15-30 Tage | 181,221 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-20 | 9,494 |
| 2026-10-21 | 9,467 |
| 2026-10-22 | 10,330 |
| 2026-10-23 | 12,329 |
| 2026-10-24 | 14,995 |
| 2026-10-25 | 11,047 |
| 2026-10-26 | 9,402 |
| 2026-10-27 | 35,076 |
| 2026-10-28 | 11,244 |
| 2026-10-29 | 9,801 |
| 2026-10-30 | 20,047 |
| 2026-10-31 | 16,898 |
| 2026-11-01 | 15,310 |
| 2026-11-02 | 11,877 |
| 2026-11-03 | 16,583 |
| 2026-11-04 | 10,040 |
| 2026-11-05 | 7,219 |
| 2026-11-06 | 12,047 |
| 2026-11-07 | 13,339 |
| 2026-11-08 | 6,253 |
| 2026-11-09 | 11,465 |
| 2026-11-10 | 23,813 |
| 2026-11-11 | 9,882 |
| 2026-11-12 | 8,043 |
| 2026-11-13 | 3,333 |
| 2026-11-14 | 11,619 |
| 2026-11-15 | 14,345 |
| 2026-11-16 | 18,950 |
| 2026-11-17 | 9,350 |
| 2026-11-18 | 3,521 |
| 2026-11-19 | 8,900 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,706,105** IPs. Brutto faellig in den naechsten 30 Tagen: **386,019**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,030,124**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-20 | 9,494 | 2,000 |
| 2026-10-21 | 9,467 | 2,000 |
| 2026-10-22 | 10,330 | 2,000 |
| 2026-10-23 | 12,329 | 2,000 |
| 2026-10-24 | 14,995 | 2,000 |
| 2026-10-25 | 11,047 | 2,000 |
| 2026-10-26 | 9,402 | 2,000 |
| 2026-10-27 | 35,076 | 2,000 |
| 2026-10-28 | 11,244 | 2,000 |
| 2026-10-29 | 9,801 | 2,000 |
| 2026-10-30 | 20,047 | 2,000 |
| 2026-10-31 | 16,898 | 2,000 |
| 2026-11-01 | 15,310 | 2,000 |
| 2026-11-02 | 11,877 | 2,000 |
| 2026-11-03 | 16,583 | 2,000 |
| 2026-11-04 | 10,040 | 2,000 |
| 2026-11-05 | 7,219 | 2,000 |
| 2026-11-06 | 12,047 | 2,000 |
| 2026-11-07 | 13,339 | 2,000 |
| 2026-11-08 | 6,253 | 2,000 |
| 2026-11-09 | 11,465 | 2,000 |
| 2026-11-10 | 23,813 | 2,000 |
| 2026-11-11 | 9,882 | 2,000 |
| 2026-11-12 | 8,043 | 2,000 |
| 2026-11-13 | 3,333 | 2,000 |
| 2026-11-14 | 11,619 | 2,000 |
| 2026-11-15 | 14,345 | 2,000 |
| 2026-11-16 | 18,950 | 2,000 |
| 2026-11-17 | 9,350 | 2,000 |
| 2026-11-18 | 3,521 | 2,000 |
| 2026-11-19 | 8,900 | 2,000 |

> Hinweis: Der Rueckstau von 3,030,124 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-21 | 11,007 |
| 2026-10-22 | 30,442 |
| 2026-10-23 | 50,184 |
| 2026-10-24 | 41,554 |
| 2026-10-25 | 21,469 |
| 2026-10-26 | 20,178 |
| 2026-10-27 | 20,407 |
| 2026-10-28 | 15,534 |
| 2026-10-29 | 9,515 |
| 2026-10-30 | 61,565 |
| 2026-10-31 | 88,024 |
| 2026-11-01 | 27,713 |
| 2026-11-02 | 28,665 |
| 2026-11-03 | 29,605 |
| 2026-11-04 | 29,460 |
| 2026-11-05 | 25,148 |
| 2026-11-06 | 36,194 |
| 2026-11-07 | 24,348 |
| 2026-11-08 | 26,006 |
| 2026-11-09 | 25,437 |
| 2026-11-10 | 32,592 |
| 2026-11-11 | 22,262 |
| 2026-11-12 | 20,434 |
| 2026-11-13 | 19,580 |
| 2026-11-14 | 22,877 |
| 2026-11-15 | 17,399 |
| 2026-11-16 | 17,901 |
| 2026-11-17 | 15,184 |
| 2026-11-18 | 19,439 |
| 2026-11-19 | 173,415 |
| 2026-11-20 | 26,070 |
| 2026-11-21 | 61,227 |
| 2026-11-22 | 30,331 |
| 2026-11-23 | 25,589 |
| 2026-11-24 | 26,396 |
| 2026-11-25 | 27,445 |
| 2026-11-26 | 28,594 |
| 2026-11-27 | 27,781 |
| 2026-11-28 | 109,110 |
| 2026-11-29 | 28,118 |
| 2026-11-30 | 25,475 |
| 2026-12-01 | 26,487 |
| 2026-12-02 | 26,138 |
| 2026-12-03 | 25,960 |
| 2026-12-04 | 27,866 |
| 2026-12-05 | 25,911 |
| 2026-12-06 | 30,085 |
| 2026-12-07 | 23,700 |
| 2026-12-08 | 39,328 |
| 2026-12-09 | 55,040 |
| 2026-12-10 | 25,053 |
| 2026-12-11 | 27,733 |
| 2026-12-12 | 24,359 |
| 2026-12-13 | 23,831 |
| 2026-12-14 | 23,442 |
| 2026-12-15 | 26,222 |
| 2026-12-16 | 16,648 |
| 2026-12-17 | 24,998 |
| 2026-12-18 | 22,502 |
| 2026-12-19 | 25,597 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
