# Seen-DB Expiry Forecast

Lauf: 2026-10-22 09:27 CEST (Europe/Berlin)
Gesamt: 11,077,606 IPs in seen_db.json (7,959,213 aktiv/180-Tage-Pfad, 3,118,393 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 178,730 |
| 8-14 Tage | 290,130 |
| 15-30 Tage | 560,257 |
| 31-60 Tage | 891,207 |
| 61-90 Tage | 696,698 |
| 91-180 Tage | 5,342,191 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,724,768 |
| 0-3 Tage | 48,687 |
| 4-7 Tage | 65,505 |
| 8-14 Tage | 97,937 |
| 15-30 Tage | 181,496 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-22 | 10,326 |
| 2026-10-23 | 12,324 |
| 2026-10-24 | 14,991 |
| 2026-10-25 | 11,046 |
| 2026-10-26 | 9,400 |
| 2026-10-27 | 35,065 |
| 2026-10-28 | 11,243 |
| 2026-10-29 | 9,797 |
| 2026-10-30 | 20,038 |
| 2026-10-31 | 16,894 |
| 2026-11-01 | 15,307 |
| 2026-11-02 | 11,868 |
| 2026-11-03 | 16,579 |
| 2026-11-04 | 10,036 |
| 2026-11-05 | 7,215 |
| 2026-11-06 | 12,042 |
| 2026-11-07 | 13,333 |
| 2026-11-08 | 6,252 |
| 2026-11-09 | 11,458 |
| 2026-11-10 | 23,801 |
| 2026-11-11 | 9,878 |
| 2026-11-12 | 8,035 |
| 2026-11-13 | 3,327 |
| 2026-11-14 | 11,600 |
| 2026-11-15 | 14,329 |
| 2026-11-16 | 18,921 |
| 2026-11-17 | 9,339 |
| 2026-11-18 | 3,509 |
| 2026-11-19 | 8,867 |
| 2026-11-20 | 10,972 |
| 2026-11-21 | 10,115 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,724,768** IPs. Brutto faellig in den naechsten 30 Tagen: **387,907**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,050,675**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-22 | 10,326 | 2,000 |
| 2026-10-23 | 12,324 | 2,000 |
| 2026-10-24 | 14,991 | 2,000 |
| 2026-10-25 | 11,046 | 2,000 |
| 2026-10-26 | 9,400 | 2,000 |
| 2026-10-27 | 35,065 | 2,000 |
| 2026-10-28 | 11,243 | 2,000 |
| 2026-10-29 | 9,797 | 2,000 |
| 2026-10-30 | 20,038 | 2,000 |
| 2026-10-31 | 16,894 | 2,000 |
| 2026-11-01 | 15,307 | 2,000 |
| 2026-11-02 | 11,868 | 2,000 |
| 2026-11-03 | 16,579 | 2,000 |
| 2026-11-04 | 10,036 | 2,000 |
| 2026-11-05 | 7,215 | 2,000 |
| 2026-11-06 | 12,042 | 2,000 |
| 2026-11-07 | 13,333 | 2,000 |
| 2026-11-08 | 6,252 | 2,000 |
| 2026-11-09 | 11,458 | 2,000 |
| 2026-11-10 | 23,801 | 2,000 |
| 2026-11-11 | 9,878 | 2,000 |
| 2026-11-12 | 8,035 | 2,000 |
| 2026-11-13 | 3,327 | 2,000 |
| 2026-11-14 | 11,600 | 2,000 |
| 2026-11-15 | 14,329 | 2,000 |
| 2026-11-16 | 18,921 | 2,000 |
| 2026-11-17 | 9,339 | 2,000 |
| 2026-11-18 | 3,509 | 2,000 |
| 2026-11-19 | 8,867 | 2,000 |
| 2026-11-20 | 10,972 | 2,000 |
| 2026-11-21 | 10,115 | 2,000 |

> Hinweis: Der Rueckstau von 3,050,675 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-23 | 50,175 |
| 2026-10-24 | 41,543 |
| 2026-10-25 | 21,462 |
| 2026-10-26 | 20,169 |
| 2026-10-27 | 20,389 |
| 2026-10-28 | 15,500 |
| 2026-10-29 | 9,492 |
| 2026-10-30 | 61,554 |
| 2026-10-31 | 88,019 |
| 2026-11-01 | 27,709 |
| 2026-11-02 | 28,656 |
| 2026-11-03 | 29,596 |
| 2026-11-04 | 29,454 |
| 2026-11-05 | 25,142 |
| 2026-11-06 | 36,189 |
| 2026-11-07 | 24,340 |
| 2026-11-08 | 26,002 |
| 2026-11-09 | 25,429 |
| 2026-11-10 | 32,587 |
| 2026-11-11 | 22,255 |
| 2026-11-12 | 20,430 |
| 2026-11-13 | 19,576 |
| 2026-11-14 | 22,871 |
| 2026-11-15 | 17,396 |
| 2026-11-16 | 17,887 |
| 2026-11-17 | 15,179 |
| 2026-11-18 | 19,437 |
| 2026-11-19 | 173,396 |
| 2026-11-20 | 26,060 |
| 2026-11-21 | 61,223 |
| 2026-11-22 | 30,324 |
| 2026-11-23 | 25,582 |
| 2026-11-24 | 26,393 |
| 2026-11-25 | 27,440 |
| 2026-11-26 | 28,587 |
| 2026-11-27 | 27,776 |
| 2026-11-28 | 109,103 |
| 2026-11-29 | 28,116 |
| 2026-11-30 | 25,468 |
| 2026-12-01 | 26,481 |
| 2026-12-02 | 26,131 |
| 2026-12-03 | 25,952 |
| 2026-12-04 | 27,864 |
| 2026-12-05 | 25,908 |
| 2026-12-06 | 30,079 |
| 2026-12-07 | 23,694 |
| 2026-12-08 | 39,323 |
| 2026-12-09 | 55,012 |
| 2026-12-10 | 25,052 |
| 2026-12-11 | 27,732 |
| 2026-12-12 | 24,354 |
| 2026-12-13 | 23,824 |
| 2026-12-14 | 23,440 |
| 2026-12-15 | 26,221 |
| 2026-12-16 | 16,637 |
| 2026-12-17 | 24,988 |
| 2026-12-18 | 22,492 |
| 2026-12-19 | 25,590 |
| 2026-12-20 | 14,312 |
| 2026-12-21 | 27,332 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
