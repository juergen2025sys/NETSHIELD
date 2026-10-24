# Seen-DB Expiry Forecast

Lauf: 2026-10-24 03:54 CEST (Europe/Berlin)
Gesamt: 11,091,073 IPs in seen_db.json (7,960,015 aktiv/180-Tage-Pfad, 3,131,058 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 236,492 |
| 8-14 Tage | 201,031 |
| 15-30 Tage | 555,530 |
| 31-60 Tage | 880,343 |
| 61-90 Tage | 725,680 |
| 91-180 Tage | 5,360,939 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,744,990 |
| 0-3 Tage | 70,458 |
| 4-7 Tage | 57,956 |
| 8-14 Tage | 86,352 |
| 15-30 Tage | 171,302 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-24 | 14,980 |
| 2026-10-25 | 11,043 |
| 2026-10-26 | 9,395 |
| 2026-10-27 | 35,040 |
| 2026-10-28 | 11,239 |
| 2026-10-29 | 9,796 |
| 2026-10-30 | 20,033 |
| 2026-10-31 | 16,888 |
| 2026-11-01 | 15,307 |
| 2026-11-02 | 11,866 |
| 2026-11-03 | 16,574 |
| 2026-11-04 | 10,032 |
| 2026-11-05 | 7,210 |
| 2026-11-06 | 12,038 |
| 2026-11-07 | 13,325 |
| 2026-11-08 | 6,248 |
| 2026-11-09 | 11,449 |
| 2026-11-10 | 23,785 |
| 2026-11-11 | 9,871 |
| 2026-11-12 | 8,023 |
| 2026-11-13 | 3,322 |
| 2026-11-14 | 11,589 |
| 2026-11-15 | 14,315 |
| 2026-11-16 | 18,897 |
| 2026-11-17 | 9,330 |
| 2026-11-18 | 3,500 |
| 2026-11-19 | 8,848 |
| 2026-11-20 | 10,936 |
| 2026-11-21 | 10,070 |
| 2026-11-22 | 10,087 |
| 2026-11-23 | 10,155 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,744,990** IPs. Brutto faellig in den naechsten 30 Tagen: **385,191**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,068,181**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-24 | 14,980 | 2,000 |
| 2026-10-25 | 11,043 | 2,000 |
| 2026-10-26 | 9,395 | 2,000 |
| 2026-10-27 | 35,040 | 2,000 |
| 2026-10-28 | 11,239 | 2,000 |
| 2026-10-29 | 9,796 | 2,000 |
| 2026-10-30 | 20,033 | 2,000 |
| 2026-10-31 | 16,888 | 2,000 |
| 2026-11-01 | 15,307 | 2,000 |
| 2026-11-02 | 11,866 | 2,000 |
| 2026-11-03 | 16,574 | 2,000 |
| 2026-11-04 | 10,032 | 2,000 |
| 2026-11-05 | 7,210 | 2,000 |
| 2026-11-06 | 12,038 | 2,000 |
| 2026-11-07 | 13,325 | 2,000 |
| 2026-11-08 | 6,248 | 2,000 |
| 2026-11-09 | 11,449 | 2,000 |
| 2026-11-10 | 23,785 | 2,000 |
| 2026-11-11 | 9,871 | 2,000 |
| 2026-11-12 | 8,023 | 2,000 |
| 2026-11-13 | 3,322 | 2,000 |
| 2026-11-14 | 11,589 | 2,000 |
| 2026-11-15 | 14,315 | 2,000 |
| 2026-11-16 | 18,897 | 2,000 |
| 2026-11-17 | 9,330 | 2,000 |
| 2026-11-18 | 3,500 | 2,000 |
| 2026-11-19 | 8,848 | 2,000 |
| 2026-11-20 | 10,936 | 2,000 |
| 2026-11-21 | 10,070 | 2,000 |
| 2026-11-22 | 10,087 | 2,000 |
| 2026-11-23 | 10,155 | 2,000 |

> Hinweis: Der Rueckstau von 3,068,181 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-25 | 21,454 |
| 2026-10-26 | 20,158 |
| 2026-10-27 | 20,378 |
| 2026-10-28 | 15,482 |
| 2026-10-29 | 9,481 |
| 2026-10-30 | 61,530 |
| 2026-10-31 | 88,009 |
| 2026-11-01 | 27,702 |
| 2026-11-02 | 28,647 |
| 2026-11-03 | 29,588 |
| 2026-11-04 | 29,451 |
| 2026-11-05 | 25,133 |
| 2026-11-06 | 36,179 |
| 2026-11-07 | 24,331 |
| 2026-11-08 | 25,999 |
| 2026-11-09 | 25,419 |
| 2026-11-10 | 32,578 |
| 2026-11-11 | 22,247 |
| 2026-11-12 | 20,429 |
| 2026-11-13 | 19,574 |
| 2026-11-14 | 22,862 |
| 2026-11-15 | 17,395 |
| 2026-11-16 | 17,883 |
| 2026-11-17 | 15,177 |
| 2026-11-18 | 19,429 |
| 2026-11-19 | 173,381 |
| 2026-11-20 | 26,053 |
| 2026-11-21 | 61,212 |
| 2026-11-22 | 30,317 |
| 2026-11-23 | 25,575 |
| 2026-11-24 | 26,388 |
| 2026-11-25 | 27,438 |
| 2026-11-26 | 28,586 |
| 2026-11-27 | 27,774 |
| 2026-11-28 | 109,096 |
| 2026-11-29 | 28,106 |
| 2026-11-30 | 25,466 |
| 2026-12-01 | 26,477 |
| 2026-12-02 | 26,124 |
| 2026-12-03 | 25,945 |
| 2026-12-04 | 27,863 |
| 2026-12-05 | 25,903 |
| 2026-12-06 | 30,076 |
| 2026-12-07 | 23,691 |
| 2026-12-08 | 39,315 |
| 2026-12-09 | 54,987 |
| 2026-12-10 | 25,049 |
| 2026-12-11 | 27,726 |
| 2026-12-12 | 24,347 |
| 2026-12-13 | 23,820 |
| 2026-12-14 | 23,438 |
| 2026-12-15 | 26,215 |
| 2026-12-16 | 16,620 |
| 2026-12-17 | 24,985 |
| 2026-12-18 | 22,488 |
| 2026-12-19 | 25,574 |
| 2026-12-20 | 14,306 |
| 2026-12-21 | 27,325 |
| 2026-12-22 | 24,102 |
| 2026-12-23 | 21,113 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
