# Seen-DB Expiry Forecast

Lauf: 2026-10-09 09:57 CEST (Europe/Berlin)
Gesamt: 12,191,771 IPs in seen_db.json (9,197,388 aktiv/180-Tage-Pfad, 2,994,383 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 1,841,226 |
| 8-14 Tage | 163,260 |
| 15-30 Tage | 506,367 |
| 31-60 Tage | 1,029,385 |
| 61-90 Tage | 729,610 |
| 91-180 Tage | 4,927,540 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,632,077 |
| 0-3 Tage | 27,662 |
| 4-7 Tage | 39,272 |
| 8-14 Tage | 65,398 |
| 15-30 Tage | 229,974 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-09 | 10,098 |
| 2026-10-10 | 7,507 |
| 2026-10-11 | 6,212 |
| 2026-10-12 | 3,845 |
| 2026-10-13 | 8,211 |
| 2026-10-14 | 7,389 |
| 2026-10-15 | 8,255 |
| 2026-10-16 | 15,417 |
| 2026-10-17 | 9,916 |
| 2026-10-18 | 8,625 |
| 2026-10-19 | 5,125 |
| 2026-10-20 | 9,531 |
| 2026-10-21 | 9,492 |
| 2026-10-22 | 10,356 |
| 2026-10-23 | 12,353 |
| 2026-10-24 | 15,031 |
| 2026-10-25 | 11,073 |
| 2026-10-26 | 9,424 |
| 2026-10-27 | 35,204 |
| 2026-10-28 | 11,263 |
| 2026-10-29 | 9,825 |
| 2026-10-30 | 20,095 |
| 2026-10-31 | 17,034 |
| 2026-11-01 | 15,346 |
| 2026-11-02 | 11,906 |
| 2026-11-03 | 16,617 |
| 2026-11-04 | 10,073 |
| 2026-11-05 | 7,259 |
| 2026-11-06 | 12,100 |
| 2026-11-07 | 13,437 |
| 2026-11-08 | 6,375 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,632,077** IPs. Brutto faellig in den naechsten 30 Tagen: **354,394**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **2,924,471**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-09 | 10,098 | 2,000 |
| 2026-10-10 | 7,507 | 2,000 |
| 2026-10-11 | 6,212 | 2,000 |
| 2026-10-12 | 3,845 | 2,000 |
| 2026-10-13 | 8,211 | 2,000 |
| 2026-10-14 | 7,389 | 2,000 |
| 2026-10-15 | 8,255 | 2,000 |
| 2026-10-16 | 15,417 | 2,000 |
| 2026-10-17 | 9,916 | 2,000 |
| 2026-10-18 | 8,625 | 2,000 |
| 2026-10-19 | 5,125 | 2,000 |
| 2026-10-20 | 9,531 | 2,000 |
| 2026-10-21 | 9,492 | 2,000 |
| 2026-10-22 | 10,356 | 2,000 |
| 2026-10-23 | 12,353 | 2,000 |
| 2026-10-24 | 15,031 | 2,000 |
| 2026-10-25 | 11,073 | 2,000 |
| 2026-10-26 | 9,424 | 2,000 |
| 2026-10-27 | 35,204 | 2,000 |
| 2026-10-28 | 11,263 | 2,000 |
| 2026-10-29 | 9,825 | 2,000 |
| 2026-10-30 | 20,095 | 2,000 |
| 2026-10-31 | 17,034 | 2,000 |
| 2026-11-01 | 15,346 | 2,000 |
| 2026-11-02 | 11,906 | 2,000 |
| 2026-11-03 | 16,617 | 2,000 |
| 2026-11-04 | 10,073 | 2,000 |
| 2026-11-05 | 7,259 | 2,000 |
| 2026-11-06 | 12,100 | 2,000 |
| 2026-11-07 | 13,437 | 2,000 |
| 2026-11-08 | 6,375 | 2,000 |

> Hinweis: Der Rueckstau von 2,924,471 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-10 | 53,248 |
| 2026-10-11 | 15,989 |
| 2026-10-12 | 66,493 |
| 2026-10-13 | 1,580,167 |
| 2026-10-14 | 32,903 |
| 2026-10-15 | 41,278 |
| 2026-10-16 | 51,148 |
| 2026-10-17 | 24,167 |
| 2026-10-18 | 14,179 |
| 2026-10-19 | 22,049 |
| 2026-10-20 | 11,074 |
| 2026-10-21 | 11,038 |
| 2026-10-22 | 30,504 |
| 2026-10-23 | 50,249 |
| 2026-10-24 | 41,592 |
| 2026-10-25 | 21,507 |
| 2026-10-26 | 20,226 |
| 2026-10-27 | 20,528 |
| 2026-10-28 | 15,680 |
| 2026-10-29 | 9,594 |
| 2026-10-30 | 61,648 |
| 2026-10-31 | 88,077 |
| 2026-11-01 | 27,761 |
| 2026-11-02 | 28,709 |
| 2026-11-03 | 29,663 |
| 2026-11-04 | 29,521 |
| 2026-11-05 | 25,186 |
| 2026-11-06 | 36,254 |
| 2026-11-07 | 24,374 |
| 2026-11-08 | 26,047 |
| 2026-11-09 | 25,480 |
| 2026-11-10 | 32,635 |
| 2026-11-11 | 22,310 |
| 2026-11-12 | 20,464 |
| 2026-11-13 | 19,613 |
| 2026-11-14 | 22,917 |
| 2026-11-15 | 17,426 |
| 2026-11-16 | 17,923 |
| 2026-11-17 | 15,212 |
| 2026-11-18 | 19,467 |
| 2026-11-19 | 173,552 |
| 2026-11-20 | 26,104 |
| 2026-11-21 | 61,289 |
| 2026-11-22 | 30,371 |
| 2026-11-23 | 25,627 |
| 2026-11-24 | 26,433 |
| 2026-11-25 | 27,492 |
| 2026-11-26 | 28,631 |
| 2026-11-27 | 27,812 |
| 2026-11-28 | 109,166 |
| 2026-11-29 | 28,149 |
| 2026-11-30 | 25,516 |
| 2026-12-01 | 26,533 |
| 2026-12-02 | 26,175 |
| 2026-12-03 | 26,003 |
| 2026-12-04 | 27,898 |
| 2026-12-05 | 25,941 |
| 2026-12-06 | 30,126 |
| 2026-12-07 | 23,742 |
| 2026-12-08 | 39,378 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
