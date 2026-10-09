# Seen-DB Expiry Forecast

Lauf: 2026-10-09 17:14 CEST (Europe/Berlin)
Gesamt: 12,213,457 IPs in seen_db.json (9,218,318 aktiv/180-Tage-Pfad, 2,995,139 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 1,841,087 |
| 8-14 Tage | 163,242 |
| 15-30 Tage | 506,325 |
| 31-60 Tage | 1,029,281 |
| 61-90 Tage | 729,465 |
| 91-180 Tage | 4,948,918 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,631,900 |
| 0-3 Tage | 27,654 |
| 4-7 Tage | 39,267 |
| 8-14 Tage | 65,382 |
| 15-30 Tage | 230,936 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-09 | 10,097 |
| 2026-10-10 | 7,505 |
| 2026-10-11 | 6,208 |
| 2026-10-12 | 3,844 |
| 2026-10-13 | 8,210 |
| 2026-10-14 | 7,387 |
| 2026-10-15 | 8,255 |
| 2026-10-16 | 15,415 |
| 2026-10-17 | 9,916 |
| 2026-10-18 | 8,622 |
| 2026-10-19 | 5,124 |
| 2026-10-20 | 9,529 |
| 2026-10-21 | 9,487 |
| 2026-10-22 | 10,354 |
| 2026-10-23 | 12,350 |
| 2026-10-24 | 15,023 |
| 2026-10-25 | 11,072 |
| 2026-10-26 | 9,419 |
| 2026-10-27 | 35,193 |
| 2026-10-28 | 11,262 |
| 2026-10-29 | 9,823 |
| 2026-10-30 | 20,089 |
| 2026-10-31 | 16,971 |
| 2026-11-01 | 15,343 |
| 2026-11-02 | 11,901 |
| 2026-11-03 | 16,609 |
| 2026-11-04 | 10,067 |
| 2026-11-05 | 7,254 |
| 2026-11-06 | 12,089 |
| 2026-11-07 | 13,402 |
| 2026-11-08 | 6,325 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,631,900** IPs. Brutto faellig in den naechsten 30 Tagen: **354,145**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **2,924,045**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-09 | 10,097 | 2,000 |
| 2026-10-10 | 7,505 | 2,000 |
| 2026-10-11 | 6,208 | 2,000 |
| 2026-10-12 | 3,844 | 2,000 |
| 2026-10-13 | 8,210 | 2,000 |
| 2026-10-14 | 7,387 | 2,000 |
| 2026-10-15 | 8,255 | 2,000 |
| 2026-10-16 | 15,415 | 2,000 |
| 2026-10-17 | 9,916 | 2,000 |
| 2026-10-18 | 8,622 | 2,000 |
| 2026-10-19 | 5,124 | 2,000 |
| 2026-10-20 | 9,529 | 2,000 |
| 2026-10-21 | 9,487 | 2,000 |
| 2026-10-22 | 10,354 | 2,000 |
| 2026-10-23 | 12,350 | 2,000 |
| 2026-10-24 | 15,023 | 2,000 |
| 2026-10-25 | 11,072 | 2,000 |
| 2026-10-26 | 9,419 | 2,000 |
| 2026-10-27 | 35,193 | 2,000 |
| 2026-10-28 | 11,262 | 2,000 |
| 2026-10-29 | 9,823 | 2,000 |
| 2026-10-30 | 20,089 | 2,000 |
| 2026-10-31 | 16,971 | 2,000 |
| 2026-11-01 | 15,343 | 2,000 |
| 2026-11-02 | 11,901 | 2,000 |
| 2026-11-03 | 16,609 | 2,000 |
| 2026-11-04 | 10,067 | 2,000 |
| 2026-11-05 | 7,254 | 2,000 |
| 2026-11-06 | 12,089 | 2,000 |
| 2026-11-07 | 13,402 | 2,000 |
| 2026-11-08 | 6,325 | 2,000 |

> Hinweis: Der Rueckstau von 2,924,045 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-10 | 53,245 |
| 2026-10-11 | 15,989 |
| 2026-10-12 | 66,488 |
| 2026-10-13 | 1,580,040 |
| 2026-10-14 | 32,903 |
| 2026-10-15 | 41,277 |
| 2026-10-16 | 51,145 |
| 2026-10-17 | 24,167 |
| 2026-10-18 | 14,177 |
| 2026-10-19 | 22,043 |
| 2026-10-20 | 11,073 |
| 2026-10-21 | 11,036 |
| 2026-10-22 | 30,500 |
| 2026-10-23 | 50,246 |
| 2026-10-24 | 41,590 |
| 2026-10-25 | 21,506 |
| 2026-10-26 | 20,223 |
| 2026-10-27 | 20,523 |
| 2026-10-28 | 15,679 |
| 2026-10-29 | 9,594 |
| 2026-10-30 | 61,643 |
| 2026-10-31 | 88,073 |
| 2026-11-01 | 27,759 |
| 2026-11-02 | 28,707 |
| 2026-11-03 | 29,662 |
| 2026-11-04 | 29,518 |
| 2026-11-05 | 25,182 |
| 2026-11-06 | 36,249 |
| 2026-11-07 | 24,374 |
| 2026-11-08 | 26,043 |
| 2026-11-09 | 25,478 |
| 2026-11-10 | 32,631 |
| 2026-11-11 | 22,306 |
| 2026-11-12 | 20,462 |
| 2026-11-13 | 19,612 |
| 2026-11-14 | 22,914 |
| 2026-11-15 | 17,423 |
| 2026-11-16 | 17,922 |
| 2026-11-17 | 15,211 |
| 2026-11-18 | 19,466 |
| 2026-11-19 | 173,535 |
| 2026-11-20 | 26,101 |
| 2026-11-21 | 61,281 |
| 2026-11-22 | 30,370 |
| 2026-11-23 | 25,624 |
| 2026-11-24 | 26,429 |
| 2026-11-25 | 27,487 |
| 2026-11-26 | 28,631 |
| 2026-11-27 | 27,808 |
| 2026-11-28 | 109,161 |
| 2026-11-29 | 28,148 |
| 2026-11-30 | 25,513 |
| 2026-12-01 | 26,528 |
| 2026-12-02 | 26,173 |
| 2026-12-03 | 26,000 |
| 2026-12-04 | 27,898 |
| 2026-12-05 | 25,938 |
| 2026-12-06 | 30,123 |
| 2026-12-07 | 23,734 |
| 2026-12-08 | 39,374 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
