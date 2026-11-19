# Seen-DB Expiry Forecast

Lauf: 2026-11-19 02:25 CET (Europe/Berlin)
Gesamt: 11,233,056 IPs in seen_db.json (7,966,255 aktiv/180-Tage-Pfad, 3,266,801 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 224,959 |
| 8-14 Tage | 268,471 |
| 15-30 Tage | 440,566 |
| 31-60 Tage | 689,863 |
| 61-90 Tage | 1,438,896 |
| 91-180 Tage | 4,903,500 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 3,054,128 |
| 0-3 Tage | 39,430 |
| 4-7 Tage | 31,004 |
| 8-14 Tage | 42,949 |
| 15-30 Tage | 99,290 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-19 | 8,737 |
| 2026-11-20 | 10,819 |
| 2026-11-21 | 9,909 |
| 2026-11-22 | 9,965 |
| 2026-11-23 | 9,993 |
| 2026-11-24 | 10,082 |
| 2026-11-25 | 7,597 |
| 2026-11-26 | 3,332 |
| 2026-11-27 | 3,851 |
| 2026-11-28 | 3,531 |
| 2026-11-29 | 8,121 |
| 2026-11-30 | 7,100 |
| 2026-12-01 | 8,065 |
| 2026-12-02 | 4,570 |
| 2026-12-03 | 7,711 |
| 2026-12-04 | 5,750 |
| 2026-12-05 | 5,394 |
| 2026-12-06 | 3,088 |
| 2026-12-07 | 7,786 |
| 2026-12-08 | 4,457 |
| 2026-12-09 | 9,013 |
| 2026-12-10 | 6,001 |
| 2026-12-11 | 4,658 |
| 2026-12-12 | 2,591 |
| 2026-12-13 | 3,003 |
| 2026-12-14 | 7,631 |
| 2026-12-15 | 8,121 |
| 2026-12-16 | 7,533 |
| 2026-12-17 | 7,666 |
| 2026-12-18 | 9,407 |
| 2026-12-19 | 1,669 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **3,054,128** IPs. Brutto faellig in den naechsten 30 Tagen: **207,151**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,199,279**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-19 | 8,737 | 2,000 |
| 2026-11-20 | 10,819 | 2,000 |
| 2026-11-21 | 9,909 | 2,000 |
| 2026-11-22 | 9,965 | 2,000 |
| 2026-11-23 | 9,993 | 2,000 |
| 2026-11-24 | 10,082 | 2,000 |
| 2026-11-25 | 7,597 | 2,000 |
| 2026-11-26 | 3,332 | 2,000 |
| 2026-11-27 | 3,851 | 2,000 |
| 2026-11-28 | 3,531 | 2,000 |
| 2026-11-29 | 8,121 | 2,000 |
| 2026-11-30 | 7,100 | 2,000 |
| 2026-12-01 | 8,065 | 2,000 |
| 2026-12-02 | 4,570 | 2,000 |
| 2026-12-03 | 7,711 | 2,000 |
| 2026-12-04 | 5,750 | 2,000 |
| 2026-12-05 | 5,394 | 2,000 |
| 2026-12-06 | 3,088 | 2,000 |
| 2026-12-07 | 7,786 | 2,000 |
| 2026-12-08 | 4,457 | 2,000 |
| 2026-12-09 | 9,013 | 2,000 |
| 2026-12-10 | 6,001 | 2,000 |
| 2026-12-11 | 4,658 | 2,000 |
| 2026-12-12 | 2,591 | 2,000 |
| 2026-12-13 | 3,003 | 2,000 |
| 2026-12-14 | 7,631 | 2,000 |
| 2026-12-15 | 8,121 | 2,000 |
| 2026-12-16 | 7,533 | 2,000 |
| 2026-12-17 | 7,666 | 2,000 |
| 2026-12-18 | 9,407 | 2,000 |
| 2026-12-19 | 1,669 | 2,000 |

> Hinweis: Der Rueckstau von 3,199,279 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-20 | 25,982 |
| 2026-11-21 | 61,075 |
| 2026-11-22 | 30,228 |
| 2026-11-23 | 25,506 |
| 2026-11-24 | 26,311 |
| 2026-11-25 | 27,338 |
| 2026-11-26 | 28,519 |
| 2026-11-27 | 27,710 |
| 2026-11-28 | 108,969 |
| 2026-11-29 | 28,047 |
| 2026-11-30 | 25,400 |
| 2026-12-01 | 26,427 |
| 2026-12-02 | 26,052 |
| 2026-12-03 | 25,866 |
| 2026-12-04 | 27,796 |
| 2026-12-05 | 25,837 |
| 2026-12-06 | 29,993 |
| 2026-12-07 | 23,636 |
| 2026-12-08 | 39,225 |
| 2026-12-09 | 54,665 |
| 2026-12-10 | 24,977 |
| 2026-12-11 | 27,640 |
| 2026-12-12 | 24,271 |
| 2026-12-13 | 23,733 |
| 2026-12-14 | 23,348 |
| 2026-12-15 | 26,125 |
| 2026-12-16 | 16,535 |
| 2026-12-17 | 24,905 |
| 2026-12-18 | 22,408 |
| 2026-12-19 | 25,472 |
| 2026-12-20 | 14,242 |
| 2026-12-21 | 27,221 |
| 2026-12-22 | 23,993 |
| 2026-12-23 | 21,031 |
| 2026-12-24 | 20,327 |
| 2026-12-25 | 21,549 |
| 2026-12-26 | 17,741 |
| 2026-12-27 | 24,563 |
| 2026-12-28 | 21,670 |
| 2026-12-29 | 22,506 |
| 2026-12-30 | 26,451 |
| 2026-12-31 | 20,106 |
| 2027-01-01 | 18,456 |
| 2027-01-02 | 26,056 |
| 2027-01-03 | 14,777 |
| 2027-01-04 | 28,403 |
| 2027-01-05 | 22,329 |
| 2027-01-06 | 35,516 |
| 2027-01-07 | 23,910 |
| 2027-01-08 | 25,810 |
| 2027-01-09 | 21,569 |
| 2027-01-10 | 24,677 |
| 2027-01-11 | 24,083 |
| 2027-01-12 | 22,962 |
| 2027-01-13 | 23,250 |
| 2027-01-14 | 21,858 |
| 2027-01-15 | 22,690 |
| 2027-01-16 | 26,752 |
| 2027-01-17 | 20,525 |
| 2027-01-18 | 24,840 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
