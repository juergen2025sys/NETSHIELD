# Seen-DB Expiry Forecast

Lauf: 2026-11-19 19:35 CET (Europe/Berlin)
Gesamt: 11,258,907 IPs in seen_db.json (7,987,535 aktiv/180-Tage-Pfad, 3,271,372 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 224,949 |
| 8-14 Tage | 268,463 |
| 15-30 Tage | 440,528 |
| 31-60 Tage | 689,799 |
| 61-90 Tage | 1,438,779 |
| 91-180 Tage | 4,925,017 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 3,054,809 |
| 0-3 Tage | 39,426 |
| 4-7 Tage | 31,003 |
| 8-14 Tage | 42,942 |
| 15-30 Tage | 103,192 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-19 | 8,736 |
| 2026-11-20 | 10,817 |
| 2026-11-21 | 9,909 |
| 2026-11-22 | 9,964 |
| 2026-11-23 | 9,993 |
| 2026-11-24 | 10,082 |
| 2026-11-25 | 7,597 |
| 2026-11-26 | 3,331 |
| 2026-11-27 | 3,850 |
| 2026-11-28 | 3,528 |
| 2026-11-29 | 8,121 |
| 2026-11-30 | 7,099 |
| 2026-12-01 | 8,064 |
| 2026-12-02 | 4,569 |
| 2026-12-03 | 7,711 |
| 2026-12-04 | 5,749 |
| 2026-12-05 | 5,394 |
| 2026-12-06 | 3,087 |
| 2026-12-07 | 7,786 |
| 2026-12-08 | 4,453 |
| 2026-12-09 | 9,012 |
| 2026-12-10 | 5,999 |
| 2026-12-11 | 4,656 |
| 2026-12-12 | 2,590 |
| 2026-12-13 | 3,001 |
| 2026-12-14 | 7,624 |
| 2026-12-15 | 8,114 |
| 2026-12-16 | 7,522 |
| 2026-12-17 | 7,657 |
| 2026-12-18 | 9,400 |
| 2026-12-19 | 1,661 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **3,054,809** IPs. Brutto faellig in den naechsten 30 Tagen: **207,076**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,199,885**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-19 | 8,736 | 2,000 |
| 2026-11-20 | 10,817 | 2,000 |
| 2026-11-21 | 9,909 | 2,000 |
| 2026-11-22 | 9,964 | 2,000 |
| 2026-11-23 | 9,993 | 2,000 |
| 2026-11-24 | 10,082 | 2,000 |
| 2026-11-25 | 7,597 | 2,000 |
| 2026-11-26 | 3,331 | 2,000 |
| 2026-11-27 | 3,850 | 2,000 |
| 2026-11-28 | 3,528 | 2,000 |
| 2026-11-29 | 8,121 | 2,000 |
| 2026-11-30 | 7,099 | 2,000 |
| 2026-12-01 | 8,064 | 2,000 |
| 2026-12-02 | 4,569 | 2,000 |
| 2026-12-03 | 7,711 | 2,000 |
| 2026-12-04 | 5,749 | 2,000 |
| 2026-12-05 | 5,394 | 2,000 |
| 2026-12-06 | 3,087 | 2,000 |
| 2026-12-07 | 7,786 | 2,000 |
| 2026-12-08 | 4,453 | 2,000 |
| 2026-12-09 | 9,012 | 2,000 |
| 2026-12-10 | 5,999 | 2,000 |
| 2026-12-11 | 4,656 | 2,000 |
| 2026-12-12 | 2,590 | 2,000 |
| 2026-12-13 | 3,001 | 2,000 |
| 2026-12-14 | 7,624 | 2,000 |
| 2026-12-15 | 8,114 | 2,000 |
| 2026-12-16 | 7,522 | 2,000 |
| 2026-12-17 | 7,657 | 2,000 |
| 2026-12-18 | 9,400 | 2,000 |
| 2026-12-19 | 1,661 | 2,000 |

> Hinweis: Der Rueckstau von 3,199,885 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-20 | 25,982 |
| 2026-11-21 | 61,072 |
| 2026-11-22 | 30,227 |
| 2026-11-23 | 25,505 |
| 2026-11-24 | 26,310 |
| 2026-11-25 | 27,335 |
| 2026-11-26 | 28,518 |
| 2026-11-27 | 27,709 |
| 2026-11-28 | 108,967 |
| 2026-11-29 | 28,046 |
| 2026-11-30 | 25,400 |
| 2026-12-01 | 26,425 |
| 2026-12-02 | 26,051 |
| 2026-12-03 | 25,865 |
| 2026-12-04 | 27,796 |
| 2026-12-05 | 25,837 |
| 2026-12-06 | 29,992 |
| 2026-12-07 | 23,636 |
| 2026-12-08 | 39,222 |
| 2026-12-09 | 54,657 |
| 2026-12-10 | 24,977 |
| 2026-12-11 | 27,638 |
| 2026-12-12 | 24,268 |
| 2026-12-13 | 23,731 |
| 2026-12-14 | 23,343 |
| 2026-12-15 | 26,120 |
| 2026-12-16 | 16,532 |
| 2026-12-17 | 24,904 |
| 2026-12-18 | 22,404 |
| 2026-12-19 | 25,471 |
| 2026-12-20 | 14,241 |
| 2026-12-21 | 27,219 |
| 2026-12-22 | 23,988 |
| 2026-12-23 | 21,030 |
| 2026-12-24 | 20,325 |
| 2026-12-25 | 21,548 |
| 2026-12-26 | 17,738 |
| 2026-12-27 | 24,560 |
| 2026-12-28 | 21,667 |
| 2026-12-29 | 22,502 |
| 2026-12-30 | 26,449 |
| 2026-12-31 | 20,104 |
| 2027-01-01 | 18,456 |
| 2027-01-02 | 26,052 |
| 2027-01-03 | 14,777 |
| 2027-01-04 | 28,401 |
| 2027-01-05 | 22,327 |
| 2027-01-06 | 35,513 |
| 2027-01-07 | 23,907 |
| 2027-01-08 | 25,809 |
| 2027-01-09 | 21,567 |
| 2027-01-10 | 24,675 |
| 2027-01-11 | 24,081 |
| 2027-01-12 | 22,959 |
| 2027-01-13 | 23,248 |
| 2027-01-14 | 21,857 |
| 2027-01-15 | 22,689 |
| 2027-01-16 | 26,748 |
| 2027-01-17 | 20,525 |
| 2027-01-18 | 24,837 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
