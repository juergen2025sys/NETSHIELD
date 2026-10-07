# Seen-DB Expiry Forecast

Lauf: 2026-10-07 16:43 CEST (Europe/Berlin)
Gesamt: 12,377,303 IPs in seen_db.json (9,393,692 aktiv/180-Tage-Pfad, 2,983,611 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 2,031,001 |
| 8-14 Tage | 175,057 |
| 15-30 Tage | 537,046 |
| 31-60 Tage | 1,017,220 |
| 61-90 Tage | 733,582 |
| 91-180 Tage | 4,899,786 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,622,155 |
| 0-3 Tage | 32,735 |
| 4-7 Tage | 25,682 |
| 8-14 Tage | 66,440 |
| 15-30 Tage | 236,599 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-07 | 7,871 |
| 2026-10-08 | 7,243 |
| 2026-10-09 | 10,107 |
| 2026-10-10 | 7,514 |
| 2026-10-11 | 6,218 |
| 2026-10-12 | 3,846 |
| 2026-10-13 | 8,219 |
| 2026-10-14 | 7,399 |
| 2026-10-15 | 8,266 |
| 2026-10-16 | 15,430 |
| 2026-10-17 | 9,924 |
| 2026-10-18 | 8,638 |
| 2026-10-19 | 5,130 |
| 2026-10-20 | 9,550 |
| 2026-10-21 | 9,502 |
| 2026-10-22 | 10,370 |
| 2026-10-23 | 12,371 |
| 2026-10-24 | 15,045 |
| 2026-10-25 | 11,087 |
| 2026-10-26 | 9,440 |
| 2026-10-27 | 35,240 |
| 2026-10-28 | 11,274 |
| 2026-10-29 | 9,840 |
| 2026-10-30 | 20,120 |
| 2026-10-31 | 17,057 |
| 2026-11-01 | 15,367 |
| 2026-11-02 | 11,946 |
| 2026-11-03 | 16,647 |
| 2026-11-04 | 10,091 |
| 2026-11-05 | 7,294 |
| 2026-11-06 | 12,232 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,622,155** IPs. Brutto faellig in den naechsten 30 Tagen: **350,278**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **2,910,433**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-07 | 7,871 | 2,000 |
| 2026-10-08 | 7,243 | 2,000 |
| 2026-10-09 | 10,107 | 2,000 |
| 2026-10-10 | 7,514 | 2,000 |
| 2026-10-11 | 6,218 | 2,000 |
| 2026-10-12 | 3,846 | 2,000 |
| 2026-10-13 | 8,219 | 2,000 |
| 2026-10-14 | 7,399 | 2,000 |
| 2026-10-15 | 8,266 | 2,000 |
| 2026-10-16 | 15,430 | 2,000 |
| 2026-10-17 | 9,924 | 2,000 |
| 2026-10-18 | 8,638 | 2,000 |
| 2026-10-19 | 5,130 | 2,000 |
| 2026-10-20 | 9,550 | 2,000 |
| 2026-10-21 | 9,502 | 2,000 |
| 2026-10-22 | 10,370 | 2,000 |
| 2026-10-23 | 12,371 | 2,000 |
| 2026-10-24 | 15,045 | 2,000 |
| 2026-10-25 | 11,087 | 2,000 |
| 2026-10-26 | 9,440 | 2,000 |
| 2026-10-27 | 35,240 | 2,000 |
| 2026-10-28 | 11,274 | 2,000 |
| 2026-10-29 | 9,840 | 2,000 |
| 2026-10-30 | 20,120 | 2,000 |
| 2026-10-31 | 17,057 | 2,000 |
| 2026-11-01 | 15,367 | 2,000 |
| 2026-11-02 | 11,946 | 2,000 |
| 2026-11-03 | 16,647 | 2,000 |
| 2026-11-04 | 10,091 | 2,000 |
| 2026-11-05 | 7,294 | 2,000 |
| 2026-11-06 | 12,232 | 2,000 |

> Hinweis: Der Rueckstau von 2,910,433 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-08 | 60,928 |
| 2026-10-09 | 220,826 |
| 2026-10-10 | 53,264 |
| 2026-10-11 | 15,995 |
| 2026-10-12 | 66,505 |
| 2026-10-13 | 1,580,578 |
| 2026-10-14 | 32,905 |
| 2026-10-15 | 41,287 |
| 2026-10-16 | 51,172 |
| 2026-10-17 | 24,182 |
| 2026-10-18 | 14,192 |
| 2026-10-19 | 22,094 |
| 2026-10-20 | 11,084 |
| 2026-10-21 | 11,046 |
| 2026-10-22 | 30,528 |
| 2026-10-23 | 50,274 |
| 2026-10-24 | 41,617 |
| 2026-10-25 | 21,524 |
| 2026-10-26 | 20,243 |
| 2026-10-27 | 20,562 |
| 2026-10-28 | 15,702 |
| 2026-10-29 | 9,604 |
| 2026-10-30 | 61,703 |
| 2026-10-31 | 88,103 |
| 2026-11-01 | 27,771 |
| 2026-11-02 | 28,723 |
| 2026-11-03 | 29,678 |
| 2026-11-04 | 29,543 |
| 2026-11-05 | 25,205 |
| 2026-11-06 | 36,266 |
| 2026-11-07 | 24,401 |
| 2026-11-08 | 26,064 |
| 2026-11-09 | 25,497 |
| 2026-11-10 | 32,655 |
| 2026-11-11 | 22,321 |
| 2026-11-12 | 20,472 |
| 2026-11-13 | 19,625 |
| 2026-11-14 | 22,931 |
| 2026-11-15 | 17,437 |
| 2026-11-16 | 17,936 |
| 2026-11-17 | 15,222 |
| 2026-11-18 | 19,477 |
| 2026-11-19 | 173,621 |
| 2026-11-20 | 26,118 |
| 2026-11-21 | 61,321 |
| 2026-11-22 | 30,397 |
| 2026-11-23 | 25,643 |
| 2026-11-24 | 26,444 |
| 2026-11-25 | 27,509 |
| 2026-11-26 | 28,641 |
| 2026-11-27 | 27,822 |
| 2026-11-28 | 109,187 |
| 2026-11-29 | 28,171 |
| 2026-11-30 | 25,537 |
| 2026-12-01 | 26,546 |
| 2026-12-02 | 26,191 |
| 2026-12-03 | 26,013 |
| 2026-12-04 | 27,913 |
| 2026-12-05 | 25,954 |
| 2026-12-06 | 30,154 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
