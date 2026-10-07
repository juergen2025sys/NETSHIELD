# Seen-DB Expiry Forecast

Lauf: 2026-10-07 22:33 CEST (Europe/Berlin)
Gesamt: 12,389,546 IPs in seen_db.json (9,404,176 aktiv/180-Tage-Pfad, 2,985,370 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 2,030,916 |
| 8-14 Tage | 175,044 |
| 15-30 Tage | 536,999 |
| 31-60 Tage | 1,017,142 |
| 61-90 Tage | 733,495 |
| 91-180 Tage | 4,910,580 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,621,992 |
| 0-3 Tage | 32,726 |
| 4-7 Tage | 25,678 |
| 8-14 Tage | 66,424 |
| 15-30 Tage | 238,550 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-07 | 7,870 |
| 2026-10-08 | 7,239 |
| 2026-10-09 | 10,103 |
| 2026-10-10 | 7,514 |
| 2026-10-11 | 6,217 |
| 2026-10-12 | 3,846 |
| 2026-10-13 | 8,218 |
| 2026-10-14 | 7,397 |
| 2026-10-15 | 8,263 |
| 2026-10-16 | 15,428 |
| 2026-10-17 | 9,923 |
| 2026-10-18 | 8,634 |
| 2026-10-19 | 5,130 |
| 2026-10-20 | 9,546 |
| 2026-10-21 | 9,500 |
| 2026-10-22 | 10,370 |
| 2026-10-23 | 12,369 |
| 2026-10-24 | 15,042 |
| 2026-10-25 | 11,086 |
| 2026-10-26 | 9,439 |
| 2026-10-27 | 35,237 |
| 2026-10-28 | 11,274 |
| 2026-10-29 | 9,836 |
| 2026-10-30 | 20,116 |
| 2026-10-31 | 17,053 |
| 2026-11-01 | 15,366 |
| 2026-11-02 | 11,942 |
| 2026-11-03 | 16,644 |
| 2026-11-04 | 10,087 |
| 2026-11-05 | 7,288 |
| 2026-11-06 | 12,183 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,621,992** IPs. Brutto faellig in den naechsten 30 Tagen: **350,160**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **2,910,152**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-07 | 7,870 | 2,000 |
| 2026-10-08 | 7,239 | 2,000 |
| 2026-10-09 | 10,103 | 2,000 |
| 2026-10-10 | 7,514 | 2,000 |
| 2026-10-11 | 6,217 | 2,000 |
| 2026-10-12 | 3,846 | 2,000 |
| 2026-10-13 | 8,218 | 2,000 |
| 2026-10-14 | 7,397 | 2,000 |
| 2026-10-15 | 8,263 | 2,000 |
| 2026-10-16 | 15,428 | 2,000 |
| 2026-10-17 | 9,923 | 2,000 |
| 2026-10-18 | 8,634 | 2,000 |
| 2026-10-19 | 5,130 | 2,000 |
| 2026-10-20 | 9,546 | 2,000 |
| 2026-10-21 | 9,500 | 2,000 |
| 2026-10-22 | 10,370 | 2,000 |
| 2026-10-23 | 12,369 | 2,000 |
| 2026-10-24 | 15,042 | 2,000 |
| 2026-10-25 | 11,086 | 2,000 |
| 2026-10-26 | 9,439 | 2,000 |
| 2026-10-27 | 35,237 | 2,000 |
| 2026-10-28 | 11,274 | 2,000 |
| 2026-10-29 | 9,836 | 2,000 |
| 2026-10-30 | 20,116 | 2,000 |
| 2026-10-31 | 17,053 | 2,000 |
| 2026-11-01 | 15,366 | 2,000 |
| 2026-11-02 | 11,942 | 2,000 |
| 2026-11-03 | 16,644 | 2,000 |
| 2026-11-04 | 10,087 | 2,000 |
| 2026-11-05 | 7,288 | 2,000 |
| 2026-11-06 | 12,183 | 2,000 |

> Hinweis: Der Rueckstau von 2,910,152 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-08 | 60,924 |
| 2026-10-09 | 220,805 |
| 2026-10-10 | 53,260 |
| 2026-10-11 | 15,995 |
| 2026-10-12 | 66,504 |
| 2026-10-13 | 1,580,524 |
| 2026-10-14 | 32,904 |
| 2026-10-15 | 41,285 |
| 2026-10-16 | 51,168 |
| 2026-10-17 | 24,181 |
| 2026-10-18 | 14,191 |
| 2026-10-19 | 22,090 |
| 2026-10-20 | 11,084 |
| 2026-10-21 | 11,045 |
| 2026-10-22 | 30,524 |
| 2026-10-23 | 50,271 |
| 2026-10-24 | 41,614 |
| 2026-10-25 | 21,520 |
| 2026-10-26 | 20,241 |
| 2026-10-27 | 20,556 |
| 2026-10-28 | 15,702 |
| 2026-10-29 | 9,603 |
| 2026-10-30 | 61,695 |
| 2026-10-31 | 88,096 |
| 2026-11-01 | 27,770 |
| 2026-11-02 | 28,722 |
| 2026-11-03 | 29,677 |
| 2026-11-04 | 29,541 |
| 2026-11-05 | 25,203 |
| 2026-11-06 | 36,264 |
| 2026-11-07 | 24,396 |
| 2026-11-08 | 26,061 |
| 2026-11-09 | 25,491 |
| 2026-11-10 | 32,652 |
| 2026-11-11 | 22,319 |
| 2026-11-12 | 20,471 |
| 2026-11-13 | 19,624 |
| 2026-11-14 | 22,928 |
| 2026-11-15 | 17,435 |
| 2026-11-16 | 17,936 |
| 2026-11-17 | 15,221 |
| 2026-11-18 | 19,475 |
| 2026-11-19 | 173,610 |
| 2026-11-20 | 26,116 |
| 2026-11-21 | 61,316 |
| 2026-11-22 | 30,393 |
| 2026-11-23 | 25,641 |
| 2026-11-24 | 26,443 |
| 2026-11-25 | 27,507 |
| 2026-11-26 | 28,639 |
| 2026-11-27 | 27,820 |
| 2026-11-28 | 109,183 |
| 2026-11-29 | 28,169 |
| 2026-11-30 | 25,535 |
| 2026-12-01 | 26,545 |
| 2026-12-02 | 26,190 |
| 2026-12-03 | 26,013 |
| 2026-12-04 | 27,912 |
| 2026-12-05 | 25,951 |
| 2026-12-06 | 30,150 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
