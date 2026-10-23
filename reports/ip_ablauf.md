# Seen-DB Expiry Forecast

Lauf: 2026-10-23 17:59 CEST (Europe/Berlin)
Gesamt: 11,114,661 IPs in seen_db.json (7,983,469 aktiv/180-Tage-Pfad, 3,131,192 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 190,031 |
| 8-14 Tage | 264,715 |
| 15-30 Tage | 554,297 |
| 31-60 Tage | 884,835 |
| 61-90 Tage | 718,161 |
| 91-180 Tage | 5,371,430 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,734,740 |
| 0-3 Tage | 47,738 |
| 4-7 Tage | 76,113 |
| 8-14 Tage | 89,918 |
| 15-30 Tage | 182,683 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-23 | 12,317 |
| 2026-10-24 | 14,982 |
| 2026-10-25 | 11,043 |
| 2026-10-26 | 9,396 |
| 2026-10-27 | 35,043 |
| 2026-10-28 | 11,240 |
| 2026-10-29 | 9,796 |
| 2026-10-30 | 20,034 |
| 2026-10-31 | 16,888 |
| 2026-11-01 | 15,307 |
| 2026-11-02 | 11,866 |
| 2026-11-03 | 16,574 |
| 2026-11-04 | 10,034 |
| 2026-11-05 | 7,211 |
| 2026-11-06 | 12,038 |
| 2026-11-07 | 13,326 |
| 2026-11-08 | 6,249 |
| 2026-11-09 | 11,449 |
| 2026-11-10 | 23,786 |
| 2026-11-11 | 9,874 |
| 2026-11-12 | 8,024 |
| 2026-11-13 | 3,323 |
| 2026-11-14 | 11,591 |
| 2026-11-15 | 14,315 |
| 2026-11-16 | 18,900 |
| 2026-11-17 | 9,331 |
| 2026-11-18 | 3,501 |
| 2026-11-19 | 8,850 |
| 2026-11-20 | 10,939 |
| 2026-11-21 | 10,081 |
| 2026-11-22 | 10,094 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,734,740** IPs. Brutto faellig in den naechsten 30 Tagen: **387,402**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,060,142**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-23 | 12,317 | 2,000 |
| 2026-10-24 | 14,982 | 2,000 |
| 2026-10-25 | 11,043 | 2,000 |
| 2026-10-26 | 9,396 | 2,000 |
| 2026-10-27 | 35,043 | 2,000 |
| 2026-10-28 | 11,240 | 2,000 |
| 2026-10-29 | 9,796 | 2,000 |
| 2026-10-30 | 20,034 | 2,000 |
| 2026-10-31 | 16,888 | 2,000 |
| 2026-11-01 | 15,307 | 2,000 |
| 2026-11-02 | 11,866 | 2,000 |
| 2026-11-03 | 16,574 | 2,000 |
| 2026-11-04 | 10,034 | 2,000 |
| 2026-11-05 | 7,211 | 2,000 |
| 2026-11-06 | 12,038 | 2,000 |
| 2026-11-07 | 13,326 | 2,000 |
| 2026-11-08 | 6,249 | 2,000 |
| 2026-11-09 | 11,449 | 2,000 |
| 2026-11-10 | 23,786 | 2,000 |
| 2026-11-11 | 9,874 | 2,000 |
| 2026-11-12 | 8,024 | 2,000 |
| 2026-11-13 | 3,323 | 2,000 |
| 2026-11-14 | 11,591 | 2,000 |
| 2026-11-15 | 14,315 | 2,000 |
| 2026-11-16 | 18,900 | 2,000 |
| 2026-11-17 | 9,331 | 2,000 |
| 2026-11-18 | 3,501 | 2,000 |
| 2026-11-19 | 8,850 | 2,000 |
| 2026-11-20 | 10,939 | 2,000 |
| 2026-11-21 | 10,081 | 2,000 |
| 2026-11-22 | 10,094 | 2,000 |

> Hinweis: Der Rueckstau von 3,060,142 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-24 | 41,539 |
| 2026-10-25 | 21,454 |
| 2026-10-26 | 20,159 |
| 2026-10-27 | 20,378 |
| 2026-10-28 | 15,484 |
| 2026-10-29 | 9,484 |
| 2026-10-30 | 61,533 |
| 2026-10-31 | 88,011 |
| 2026-11-01 | 27,702 |
| 2026-11-02 | 28,647 |
| 2026-11-03 | 29,589 |
| 2026-11-04 | 29,451 |
| 2026-11-05 | 25,134 |
| 2026-11-06 | 36,181 |
| 2026-11-07 | 24,332 |
| 2026-11-08 | 25,999 |
| 2026-11-09 | 25,419 |
| 2026-11-10 | 32,579 |
| 2026-11-11 | 22,249 |
| 2026-11-12 | 20,429 |
| 2026-11-13 | 19,574 |
| 2026-11-14 | 22,865 |
| 2026-11-15 | 17,395 |
| 2026-11-16 | 17,883 |
| 2026-11-17 | 15,177 |
| 2026-11-18 | 19,430 |
| 2026-11-19 | 173,381 |
| 2026-11-20 | 26,054 |
| 2026-11-21 | 61,214 |
| 2026-11-22 | 30,317 |
| 2026-11-23 | 25,576 |
| 2026-11-24 | 26,390 |
| 2026-11-25 | 27,438 |
| 2026-11-26 | 28,586 |
| 2026-11-27 | 27,774 |
| 2026-11-28 | 109,096 |
| 2026-11-29 | 28,106 |
| 2026-11-30 | 25,466 |
| 2026-12-01 | 26,479 |
| 2026-12-02 | 26,124 |
| 2026-12-03 | 25,945 |
| 2026-12-04 | 27,863 |
| 2026-12-05 | 25,904 |
| 2026-12-06 | 30,076 |
| 2026-12-07 | 23,692 |
| 2026-12-08 | 39,316 |
| 2026-12-09 | 54,991 |
| 2026-12-10 | 25,051 |
| 2026-12-11 | 27,727 |
| 2026-12-12 | 24,349 |
| 2026-12-13 | 23,822 |
| 2026-12-14 | 23,438 |
| 2026-12-15 | 26,215 |
| 2026-12-16 | 16,625 |
| 2026-12-17 | 24,985 |
| 2026-12-18 | 22,489 |
| 2026-12-19 | 25,577 |
| 2026-12-20 | 14,306 |
| 2026-12-21 | 27,325 |
| 2026-12-22 | 24,104 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
