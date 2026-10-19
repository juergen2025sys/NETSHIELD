# Seen-DB Expiry Forecast

Lauf: 2026-10-19 07:11 CEST (Europe/Berlin)
Gesamt: 10,916,527 IPs in seen_db.json (7,831,176 aktiv/180-Tage-Pfad, 3,085,351 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 185,915 |
| 8-14 Tage | 251,481 |
| 15-30 Tage | 383,955 |
| 31-60 Tage | 1,085,031 |
| 61-90 Tage | 693,523 |
| 91-180 Tage | 5,231,271 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,701,177 |
| 0-3 Tage | 34,415 |
| 4-7 Tage | 47,783 |
| 8-14 Tage | 120,283 |
| 15-30 Tage | 181,693 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-19 | 5,106 |
| 2026-10-20 | 9,504 |
| 2026-10-21 | 9,470 |
| 2026-10-22 | 10,335 |
| 2026-10-23 | 12,332 |
| 2026-10-24 | 15,000 |
| 2026-10-25 | 11,048 |
| 2026-10-26 | 9,403 |
| 2026-10-27 | 35,088 |
| 2026-10-28 | 11,245 |
| 2026-10-29 | 9,806 |
| 2026-10-30 | 20,048 |
| 2026-10-31 | 16,905 |
| 2026-11-01 | 15,313 |
| 2026-11-02 | 11,878 |
| 2026-11-03 | 16,583 |
| 2026-11-04 | 10,042 |
| 2026-11-05 | 7,228 |
| 2026-11-06 | 12,050 |
| 2026-11-07 | 13,339 |
| 2026-11-08 | 6,253 |
| 2026-11-09 | 11,469 |
| 2026-11-10 | 23,819 |
| 2026-11-11 | 9,887 |
| 2026-11-12 | 8,050 |
| 2026-11-13 | 3,343 |
| 2026-11-14 | 11,632 |
| 2026-11-15 | 14,360 |
| 2026-11-16 | 18,969 |
| 2026-11-17 | 9,376 |
| 2026-11-18 | 3,556 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,701,177** IPs. Brutto faellig in den naechsten 30 Tagen: **382,437**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,021,614**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-19 | 5,106 | 2,000 |
| 2026-10-20 | 9,504 | 2,000 |
| 2026-10-21 | 9,470 | 2,000 |
| 2026-10-22 | 10,335 | 2,000 |
| 2026-10-23 | 12,332 | 2,000 |
| 2026-10-24 | 15,000 | 2,000 |
| 2026-10-25 | 11,048 | 2,000 |
| 2026-10-26 | 9,403 | 2,000 |
| 2026-10-27 | 35,088 | 2,000 |
| 2026-10-28 | 11,245 | 2,000 |
| 2026-10-29 | 9,806 | 2,000 |
| 2026-10-30 | 20,048 | 2,000 |
| 2026-10-31 | 16,905 | 2,000 |
| 2026-11-01 | 15,313 | 2,000 |
| 2026-11-02 | 11,878 | 2,000 |
| 2026-11-03 | 16,583 | 2,000 |
| 2026-11-04 | 10,042 | 2,000 |
| 2026-11-05 | 7,228 | 2,000 |
| 2026-11-06 | 12,050 | 2,000 |
| 2026-11-07 | 13,339 | 2,000 |
| 2026-11-08 | 6,253 | 2,000 |
| 2026-11-09 | 11,469 | 2,000 |
| 2026-11-10 | 23,819 | 2,000 |
| 2026-11-11 | 9,887 | 2,000 |
| 2026-11-12 | 8,050 | 2,000 |
| 2026-11-13 | 3,343 | 2,000 |
| 2026-11-14 | 11,632 | 2,000 |
| 2026-11-15 | 14,360 | 2,000 |
| 2026-11-16 | 18,969 | 2,000 |
| 2026-11-17 | 9,376 | 2,000 |
| 2026-11-18 | 3,556 | 2,000 |

> Hinweis: Der Rueckstau von 3,021,614 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-20 | 11,054 |
| 2026-10-21 | 11,012 |
| 2026-10-22 | 30,448 |
| 2026-10-23 | 50,191 |
| 2026-10-24 | 41,560 |
| 2026-10-25 | 21,470 |
| 2026-10-26 | 20,180 |
| 2026-10-27 | 20,417 |
| 2026-10-28 | 15,550 |
| 2026-10-29 | 9,517 |
| 2026-10-30 | 61,576 |
| 2026-10-31 | 88,031 |
| 2026-11-01 | 27,718 |
| 2026-11-02 | 28,672 |
| 2026-11-03 | 29,615 |
| 2026-11-04 | 29,469 |
| 2026-11-05 | 25,152 |
| 2026-11-06 | 36,203 |
| 2026-11-07 | 24,354 |
| 2026-11-08 | 26,012 |
| 2026-11-09 | 25,437 |
| 2026-11-10 | 32,597 |
| 2026-11-11 | 22,267 |
| 2026-11-12 | 20,437 |
| 2026-11-13 | 19,584 |
| 2026-11-14 | 22,880 |
| 2026-11-15 | 17,405 |
| 2026-11-16 | 17,905 |
| 2026-11-17 | 15,191 |
| 2026-11-18 | 19,447 |
| 2026-11-19 | 173,437 |
| 2026-11-20 | 26,072 |
| 2026-11-21 | 61,235 |
| 2026-11-22 | 30,333 |
| 2026-11-23 | 25,591 |
| 2026-11-24 | 26,397 |
| 2026-11-25 | 27,455 |
| 2026-11-26 | 28,599 |
| 2026-11-27 | 27,784 |
| 2026-11-28 | 109,120 |
| 2026-11-29 | 28,121 |
| 2026-11-30 | 25,480 |
| 2026-12-01 | 26,491 |
| 2026-12-02 | 26,148 |
| 2026-12-03 | 25,966 |
| 2026-12-04 | 27,869 |
| 2026-12-05 | 25,914 |
| 2026-12-06 | 30,089 |
| 2026-12-07 | 23,705 |
| 2026-12-08 | 39,333 |
| 2026-12-09 | 55,058 |
| 2026-12-10 | 25,056 |
| 2026-12-11 | 27,736 |
| 2026-12-12 | 24,365 |
| 2026-12-13 | 23,833 |
| 2026-12-14 | 23,444 |
| 2026-12-15 | 26,230 |
| 2026-12-16 | 16,655 |
| 2026-12-17 | 25,005 |
| 2026-12-18 | 22,510 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
