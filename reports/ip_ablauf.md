# Seen-DB Expiry Forecast

Lauf: 2026-11-19 10:23 CET (Europe/Berlin)
Gesamt: 11,247,973 IPs in seen_db.json (7,977,709 aktiv/180-Tage-Pfad, 3,270,264 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 224,956 |
| 8-14 Tage | 268,467 |
| 15-30 Tage | 440,555 |
| 31-60 Tage | 689,836 |
| 61-90 Tage | 1,438,860 |
| 91-180 Tage | 4,915,035 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 3,054,900 |
| 0-3 Tage | 39,428 |
| 4-7 Tage | 31,004 |
| 8-14 Tage | 42,945 |
| 15-30 Tage | 101,987 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-19 | 8,736 |
| 2026-11-20 | 10,818 |
| 2026-11-21 | 9,909 |
| 2026-11-22 | 9,965 |
| 2026-11-23 | 9,993 |
| 2026-11-24 | 10,082 |
| 2026-11-25 | 7,597 |
| 2026-11-26 | 3,332 |
| 2026-11-27 | 3,851 |
| 2026-11-28 | 3,529 |
| 2026-11-29 | 8,121 |
| 2026-11-30 | 7,100 |
| 2026-12-01 | 8,064 |
| 2026-12-02 | 4,569 |
| 2026-12-03 | 7,711 |
| 2026-12-04 | 5,750 |
| 2026-12-05 | 5,394 |
| 2026-12-06 | 3,088 |
| 2026-12-07 | 7,786 |
| 2026-12-08 | 4,454 |
| 2026-12-09 | 9,013 |
| 2026-12-10 | 6,000 |
| 2026-12-11 | 4,657 |
| 2026-12-12 | 2,591 |
| 2026-12-13 | 3,002 |
| 2026-12-14 | 7,631 |
| 2026-12-15 | 8,117 |
| 2026-12-16 | 7,529 |
| 2026-12-17 | 7,663 |
| 2026-12-18 | 9,404 |
| 2026-12-19 | 1,663 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **3,054,900** IPs. Brutto faellig in den naechsten 30 Tagen: **207,119**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,200,019**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-19 | 8,736 | 2,000 |
| 2026-11-20 | 10,818 | 2,000 |
| 2026-11-21 | 9,909 | 2,000 |
| 2026-11-22 | 9,965 | 2,000 |
| 2026-11-23 | 9,993 | 2,000 |
| 2026-11-24 | 10,082 | 2,000 |
| 2026-11-25 | 7,597 | 2,000 |
| 2026-11-26 | 3,332 | 2,000 |
| 2026-11-27 | 3,851 | 2,000 |
| 2026-11-28 | 3,529 | 2,000 |
| 2026-11-29 | 8,121 | 2,000 |
| 2026-11-30 | 7,100 | 2,000 |
| 2026-12-01 | 8,064 | 2,000 |
| 2026-12-02 | 4,569 | 2,000 |
| 2026-12-03 | 7,711 | 2,000 |
| 2026-12-04 | 5,750 | 2,000 |
| 2026-12-05 | 5,394 | 2,000 |
| 2026-12-06 | 3,088 | 2,000 |
| 2026-12-07 | 7,786 | 2,000 |
| 2026-12-08 | 4,454 | 2,000 |
| 2026-12-09 | 9,013 | 2,000 |
| 2026-12-10 | 6,000 | 2,000 |
| 2026-12-11 | 4,657 | 2,000 |
| 2026-12-12 | 2,591 | 2,000 |
| 2026-12-13 | 3,002 | 2,000 |
| 2026-12-14 | 7,631 | 2,000 |
| 2026-12-15 | 8,117 | 2,000 |
| 2026-12-16 | 7,529 | 2,000 |
| 2026-12-17 | 7,663 | 2,000 |
| 2026-12-18 | 9,404 | 2,000 |
| 2026-12-19 | 1,663 | 2,000 |

> Hinweis: Der Rueckstau von 3,200,019 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-20 | 25,982 |
| 2026-11-21 | 61,074 |
| 2026-11-22 | 30,228 |
| 2026-11-23 | 25,506 |
| 2026-11-24 | 26,311 |
| 2026-11-25 | 27,337 |
| 2026-11-26 | 28,518 |
| 2026-11-27 | 27,709 |
| 2026-11-28 | 108,968 |
| 2026-11-29 | 28,047 |
| 2026-11-30 | 25,400 |
| 2026-12-01 | 26,425 |
| 2026-12-02 | 26,052 |
| 2026-12-03 | 25,866 |
| 2026-12-04 | 27,796 |
| 2026-12-05 | 25,837 |
| 2026-12-06 | 29,993 |
| 2026-12-07 | 23,636 |
| 2026-12-08 | 39,225 |
| 2026-12-09 | 54,662 |
| 2026-12-10 | 24,977 |
| 2026-12-11 | 27,639 |
| 2026-12-12 | 24,270 |
| 2026-12-13 | 23,733 |
| 2026-12-14 | 23,347 |
| 2026-12-15 | 26,124 |
| 2026-12-16 | 16,534 |
| 2026-12-17 | 24,905 |
| 2026-12-18 | 22,406 |
| 2026-12-19 | 25,471 |
| 2026-12-20 | 14,242 |
| 2026-12-21 | 27,220 |
| 2026-12-22 | 23,990 |
| 2026-12-23 | 21,031 |
| 2026-12-24 | 20,326 |
| 2026-12-25 | 21,549 |
| 2026-12-26 | 17,738 |
| 2026-12-27 | 24,562 |
| 2026-12-28 | 21,669 |
| 2026-12-29 | 22,505 |
| 2026-12-30 | 26,450 |
| 2026-12-31 | 20,105 |
| 2027-01-01 | 18,456 |
| 2027-01-02 | 26,053 |
| 2027-01-03 | 14,777 |
| 2027-01-04 | 28,403 |
| 2027-01-05 | 22,328 |
| 2027-01-06 | 35,516 |
| 2027-01-07 | 23,909 |
| 2027-01-08 | 25,810 |
| 2027-01-09 | 21,569 |
| 2027-01-10 | 24,675 |
| 2027-01-11 | 24,082 |
| 2027-01-12 | 22,962 |
| 2027-01-13 | 23,248 |
| 2027-01-14 | 21,857 |
| 2027-01-15 | 22,689 |
| 2027-01-16 | 26,751 |
| 2027-01-17 | 20,525 |
| 2027-01-18 | 24,839 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
