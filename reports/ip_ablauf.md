# Seen-DB Expiry Forecast

Lauf: 2026-10-16 21:41 CEST (Europe/Berlin)
Gesamt: 10,829,161 IPs in seen_db.json (7,758,352 aktiv/180-Tage-Pfad, 3,070,809 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 163,006 |
| 8-14 Tage | 190,391 |
| 15-30 Tage | 475,956 |
| 31-60 Tage | 1,073,637 |
| 61-90 Tage | 687,648 |
| 91-180 Tage | 5,167,714 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,668,222 |
| 0-3 Tage | 39,034 |
| 4-7 Tage | 41,659 |
| 8-14 Tage | 111,674 |
| 15-30 Tage | 210,220 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-16 | 15,405 |
| 2026-10-17 | 9,908 |
| 2026-10-18 | 8,612 |
| 2026-10-19 | 5,109 |
| 2026-10-20 | 9,512 |
| 2026-10-21 | 9,474 |
| 2026-10-22 | 10,337 |
| 2026-10-23 | 12,336 |
| 2026-10-24 | 15,003 |
| 2026-10-25 | 11,053 |
| 2026-10-26 | 9,408 |
| 2026-10-27 | 35,103 |
| 2026-10-28 | 11,250 |
| 2026-10-29 | 9,808 |
| 2026-10-30 | 20,049 |
| 2026-10-31 | 16,909 |
| 2026-11-01 | 15,316 |
| 2026-11-02 | 11,879 |
| 2026-11-03 | 16,586 |
| 2026-11-04 | 10,046 |
| 2026-11-05 | 7,230 |
| 2026-11-06 | 12,053 |
| 2026-11-07 | 13,345 |
| 2026-11-08 | 6,259 |
| 2026-11-09 | 11,474 |
| 2026-11-10 | 23,842 |
| 2026-11-11 | 9,901 |
| 2026-11-12 | 8,064 |
| 2026-11-13 | 3,351 |
| 2026-11-14 | 11,672 |
| 2026-11-15 | 14,410 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,668,222** IPs. Brutto faellig in den naechsten 30 Tagen: **384,704**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **2,990,926**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-16 | 15,405 | 2,000 |
| 2026-10-17 | 9,908 | 2,000 |
| 2026-10-18 | 8,612 | 2,000 |
| 2026-10-19 | 5,109 | 2,000 |
| 2026-10-20 | 9,512 | 2,000 |
| 2026-10-21 | 9,474 | 2,000 |
| 2026-10-22 | 10,337 | 2,000 |
| 2026-10-23 | 12,336 | 2,000 |
| 2026-10-24 | 15,003 | 2,000 |
| 2026-10-25 | 11,053 | 2,000 |
| 2026-10-26 | 9,408 | 2,000 |
| 2026-10-27 | 35,103 | 2,000 |
| 2026-10-28 | 11,250 | 2,000 |
| 2026-10-29 | 9,808 | 2,000 |
| 2026-10-30 | 20,049 | 2,000 |
| 2026-10-31 | 16,909 | 2,000 |
| 2026-11-01 | 15,316 | 2,000 |
| 2026-11-02 | 11,879 | 2,000 |
| 2026-11-03 | 16,586 | 2,000 |
| 2026-11-04 | 10,046 | 2,000 |
| 2026-11-05 | 7,230 | 2,000 |
| 2026-11-06 | 12,053 | 2,000 |
| 2026-11-07 | 13,345 | 2,000 |
| 2026-11-08 | 6,259 | 2,000 |
| 2026-11-09 | 11,474 | 2,000 |
| 2026-11-10 | 23,842 | 2,000 |
| 2026-11-11 | 9,901 | 2,000 |
| 2026-11-12 | 8,064 | 2,000 |
| 2026-11-13 | 3,351 | 2,000 |
| 2026-11-14 | 11,672 | 2,000 |
| 2026-11-15 | 14,410 | 2,000 |

> Hinweis: Der Rueckstau von 2,990,926 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-17 | 24,149 |
| 2026-10-18 | 14,157 |
| 2026-10-19 | 21,962 |
| 2026-10-20 | 11,054 |
| 2026-10-21 | 11,015 |
| 2026-10-22 | 30,466 |
| 2026-10-23 | 50,203 |
| 2026-10-24 | 41,570 |
| 2026-10-25 | 21,475 |
| 2026-10-26 | 20,186 |
| 2026-10-27 | 20,441 |
| 2026-10-28 | 15,587 |
| 2026-10-29 | 9,546 |
| 2026-10-30 | 61,586 |
| 2026-10-31 | 88,037 |
| 2026-11-01 | 27,727 |
| 2026-11-02 | 28,679 |
| 2026-11-03 | 29,624 |
| 2026-11-04 | 29,476 |
| 2026-11-05 | 25,158 |
| 2026-11-06 | 36,214 |
| 2026-11-07 | 24,359 |
| 2026-11-08 | 26,019 |
| 2026-11-09 | 25,448 |
| 2026-11-10 | 32,610 |
| 2026-11-11 | 22,277 |
| 2026-11-12 | 20,443 |
| 2026-11-13 | 19,592 |
| 2026-11-14 | 22,884 |
| 2026-11-15 | 17,409 |
| 2026-11-16 | 17,911 |
| 2026-11-17 | 15,194 |
| 2026-11-18 | 19,448 |
| 2026-11-19 | 173,450 |
| 2026-11-20 | 26,081 |
| 2026-11-21 | 61,244 |
| 2026-11-22 | 30,337 |
| 2026-11-23 | 25,597 |
| 2026-11-24 | 26,409 |
| 2026-11-25 | 27,458 |
| 2026-11-26 | 28,601 |
| 2026-11-27 | 27,788 |
| 2026-11-28 | 109,127 |
| 2026-11-29 | 28,125 |
| 2026-11-30 | 25,485 |
| 2026-12-01 | 26,500 |
| 2026-12-02 | 26,155 |
| 2026-12-03 | 25,970 |
| 2026-12-04 | 27,876 |
| 2026-12-05 | 25,921 |
| 2026-12-06 | 30,095 |
| 2026-12-07 | 23,710 |
| 2026-12-08 | 39,338 |
| 2026-12-09 | 55,088 |
| 2026-12-10 | 25,069 |
| 2026-12-11 | 27,743 |
| 2026-12-12 | 24,374 |
| 2026-12-13 | 23,841 |
| 2026-12-14 | 23,458 |
| 2026-12-15 | 26,244 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
