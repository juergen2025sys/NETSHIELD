# Seen-DB Expiry Forecast

Lauf: 2026-10-13 19:06 CEST (Europe/Berlin)
Gesamt: 10,777,172 IPs in seen_db.json (7,744,282 aktiv/180-Tage-Pfad, 3,032,890 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 196,681 |
| 8-14 Tage | 195,515 |
| 15-30 Tage | 503,081 |
| 31-60 Tage | 1,060,327 |
| 61-90 Tage | 693,184 |
| 91-180 Tage | 5,095,494 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,650,840 |
| 0-3 Tage | 39,245 |
| 4-7 Tage | 33,154 |
| 8-14 Tage | 102,767 |
| 15-30 Tage | 206,884 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-13 | 8,205 |
| 2026-10-14 | 7,382 |
| 2026-10-15 | 8,251 |
| 2026-10-16 | 15,407 |
| 2026-10-17 | 9,911 |
| 2026-10-18 | 8,613 |
| 2026-10-19 | 5,114 |
| 2026-10-20 | 9,516 |
| 2026-10-21 | 9,477 |
| 2026-10-22 | 10,340 |
| 2026-10-23 | 12,341 |
| 2026-10-24 | 15,008 |
| 2026-10-25 | 11,062 |
| 2026-10-26 | 9,412 |
| 2026-10-27 | 35,127 |
| 2026-10-28 | 11,250 |
| 2026-10-29 | 9,812 |
| 2026-10-30 | 20,063 |
| 2026-10-31 | 16,932 |
| 2026-11-01 | 15,325 |
| 2026-11-02 | 11,885 |
| 2026-11-03 | 16,596 |
| 2026-11-04 | 10,053 |
| 2026-11-05 | 7,239 |
| 2026-11-06 | 12,062 |
| 2026-11-07 | 13,369 |
| 2026-11-08 | 6,274 |
| 2026-11-09 | 11,505 |
| 2026-11-10 | 23,877 |
| 2026-11-11 | 9,934 |
| 2026-11-12 | 8,126 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,650,840** IPs. Brutto faellig in den naechsten 30 Tagen: **379,468**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **2,968,308**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-13 | 8,205 | 2,000 |
| 2026-10-14 | 7,382 | 2,000 |
| 2026-10-15 | 8,251 | 2,000 |
| 2026-10-16 | 15,407 | 2,000 |
| 2026-10-17 | 9,911 | 2,000 |
| 2026-10-18 | 8,613 | 2,000 |
| 2026-10-19 | 5,114 | 2,000 |
| 2026-10-20 | 9,516 | 2,000 |
| 2026-10-21 | 9,477 | 2,000 |
| 2026-10-22 | 10,340 | 2,000 |
| 2026-10-23 | 12,341 | 2,000 |
| 2026-10-24 | 15,008 | 2,000 |
| 2026-10-25 | 11,062 | 2,000 |
| 2026-10-26 | 9,412 | 2,000 |
| 2026-10-27 | 35,127 | 2,000 |
| 2026-10-28 | 11,250 | 2,000 |
| 2026-10-29 | 9,812 | 2,000 |
| 2026-10-30 | 20,063 | 2,000 |
| 2026-10-31 | 16,932 | 2,000 |
| 2026-11-01 | 15,325 | 2,000 |
| 2026-11-02 | 11,885 | 2,000 |
| 2026-11-03 | 16,596 | 2,000 |
| 2026-11-04 | 10,053 | 2,000 |
| 2026-11-05 | 7,239 | 2,000 |
| 2026-11-06 | 12,062 | 2,000 |
| 2026-11-07 | 13,369 | 2,000 |
| 2026-11-08 | 6,274 | 2,000 |
| 2026-11-09 | 11,505 | 2,000 |
| 2026-11-10 | 23,877 | 2,000 |
| 2026-11-11 | 9,934 | 2,000 |
| 2026-11-12 | 8,126 | 2,000 |

> Hinweis: Der Rueckstau von 2,968,308 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-14 | 32,901 |
| 2026-10-15 | 41,269 |
| 2026-10-16 | 51,132 |
| 2026-10-17 | 24,159 |
| 2026-10-18 | 14,163 |
| 2026-10-19 | 21,996 |
| 2026-10-20 | 11,061 |
| 2026-10-21 | 11,025 |
| 2026-10-22 | 30,485 |
| 2026-10-23 | 50,224 |
| 2026-10-24 | 41,580 |
| 2026-10-25 | 21,491 |
| 2026-10-26 | 20,203 |
| 2026-10-27 | 20,507 |
| 2026-10-28 | 15,660 |
| 2026-10-29 | 9,585 |
| 2026-10-30 | 61,606 |
| 2026-10-31 | 88,053 |
| 2026-11-01 | 27,744 |
| 2026-11-02 | 28,687 |
| 2026-11-03 | 29,635 |
| 2026-11-04 | 29,494 |
| 2026-11-05 | 25,167 |
| 2026-11-06 | 36,231 |
| 2026-11-07 | 24,367 |
| 2026-11-08 | 26,028 |
| 2026-11-09 | 25,460 |
| 2026-11-10 | 32,621 |
| 2026-11-11 | 22,290 |
| 2026-11-12 | 20,453 |
| 2026-11-13 | 19,602 |
| 2026-11-14 | 22,902 |
| 2026-11-15 | 17,416 |
| 2026-11-16 | 17,916 |
| 2026-11-17 | 15,201 |
| 2026-11-18 | 19,454 |
| 2026-11-19 | 173,472 |
| 2026-11-20 | 26,091 |
| 2026-11-21 | 61,261 |
| 2026-11-22 | 30,350 |
| 2026-11-23 | 25,607 |
| 2026-11-24 | 26,417 |
| 2026-11-25 | 27,469 |
| 2026-11-26 | 28,612 |
| 2026-11-27 | 27,795 |
| 2026-11-28 | 109,147 |
| 2026-11-29 | 28,132 |
| 2026-11-30 | 25,495 |
| 2026-12-01 | 26,511 |
| 2026-12-02 | 26,163 |
| 2026-12-03 | 25,978 |
| 2026-12-04 | 27,884 |
| 2026-12-05 | 25,927 |
| 2026-12-06 | 30,110 |
| 2026-12-07 | 23,719 |
| 2026-12-08 | 39,349 |
| 2026-12-09 | 55,133 |
| 2026-12-10 | 25,079 |
| 2026-12-11 | 27,751 |
| 2026-12-12 | 24,384 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
