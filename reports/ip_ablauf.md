# Seen-DB Expiry Forecast

Lauf: 2026-11-20 02:10 CET (Europe/Berlin)
Gesamt: 11,265,263 IPs in seen_db.json (7,993,305 aktiv/180-Tage-Pfad, 3,271,958 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 252,654 |
| 8-14 Tage | 268,547 |
| 15-30 Tage | 426,955 |
| 31-60 Tage | 698,013 |
| 61-90 Tage | 1,449,729 |
| 91-180 Tage | 4,897,407 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 3,063,506 |
| 0-3 Tage | 40,679 |
| 4-7 Tage | 24,859 |
| 8-14 Tage | 44,834 |
| 15-30 Tage | 98,080 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-20 | 10,816 |
| 2026-11-21 | 9,907 |
| 2026-11-22 | 9,963 |
| 2026-11-23 | 9,993 |
| 2026-11-24 | 10,081 |
| 2026-11-25 | 7,597 |
| 2026-11-26 | 3,331 |
| 2026-11-27 | 3,850 |
| 2026-11-28 | 3,528 |
| 2026-11-29 | 8,121 |
| 2026-11-30 | 7,098 |
| 2026-12-01 | 8,063 |
| 2026-12-02 | 4,565 |
| 2026-12-03 | 7,710 |
| 2026-12-04 | 5,749 |
| 2026-12-05 | 5,394 |
| 2026-12-06 | 3,086 |
| 2026-12-07 | 7,786 |
| 2026-12-08 | 4,452 |
| 2026-12-09 | 9,012 |
| 2026-12-10 | 5,999 |
| 2026-12-11 | 4,656 |
| 2026-12-12 | 2,589 |
| 2026-12-13 | 3,000 |
| 2026-12-14 | 7,623 |
| 2026-12-15 | 8,113 |
| 2026-12-16 | 7,519 |
| 2026-12-17 | 7,655 |
| 2026-12-18 | 9,399 |
| 2026-12-19 | 1,659 |
| 2026-12-20 | 10,138 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **3,063,506** IPs. Brutto faellig in den naechsten 30 Tagen: **208,452**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,209,958**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-20 | 10,816 | 2,000 |
| 2026-11-21 | 9,907 | 2,000 |
| 2026-11-22 | 9,963 | 2,000 |
| 2026-11-23 | 9,993 | 2,000 |
| 2026-11-24 | 10,081 | 2,000 |
| 2026-11-25 | 7,597 | 2,000 |
| 2026-11-26 | 3,331 | 2,000 |
| 2026-11-27 | 3,850 | 2,000 |
| 2026-11-28 | 3,528 | 2,000 |
| 2026-11-29 | 8,121 | 2,000 |
| 2026-11-30 | 7,098 | 2,000 |
| 2026-12-01 | 8,063 | 2,000 |
| 2026-12-02 | 4,565 | 2,000 |
| 2026-12-03 | 7,710 | 2,000 |
| 2026-12-04 | 5,749 | 2,000 |
| 2026-12-05 | 5,394 | 2,000 |
| 2026-12-06 | 3,086 | 2,000 |
| 2026-12-07 | 7,786 | 2,000 |
| 2026-12-08 | 4,452 | 2,000 |
| 2026-12-09 | 9,012 | 2,000 |
| 2026-12-10 | 5,999 | 2,000 |
| 2026-12-11 | 4,656 | 2,000 |
| 2026-12-12 | 2,589 | 2,000 |
| 2026-12-13 | 3,000 | 2,000 |
| 2026-12-14 | 7,623 | 2,000 |
| 2026-12-15 | 8,113 | 2,000 |
| 2026-12-16 | 7,519 | 2,000 |
| 2026-12-17 | 7,655 | 2,000 |
| 2026-12-18 | 9,399 | 2,000 |
| 2026-12-19 | 1,659 | 2,000 |
| 2026-12-20 | 10,138 | 2,000 |

> Hinweis: Der Rueckstau von 3,209,958 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-20 | 25,980 |
| 2026-11-21 | 61,071 |
| 2026-11-22 | 30,227 |
| 2026-11-23 | 25,505 |
| 2026-11-24 | 26,309 |
| 2026-11-25 | 27,335 |
| 2026-11-26 | 28,518 |
| 2026-11-27 | 27,709 |
| 2026-11-28 | 108,967 |
| 2026-11-29 | 28,045 |
| 2026-11-30 | 25,399 |
| 2026-12-01 | 26,424 |
| 2026-12-02 | 26,051 |
| 2026-12-03 | 25,865 |
| 2026-12-04 | 27,796 |
| 2026-12-05 | 25,837 |
| 2026-12-06 | 29,991 |
| 2026-12-07 | 23,635 |
| 2026-12-08 | 39,221 |
| 2026-12-09 | 54,651 |
| 2026-12-10 | 24,976 |
| 2026-12-11 | 27,636 |
| 2026-12-12 | 24,268 |
| 2026-12-13 | 23,730 |
| 2026-12-14 | 23,343 |
| 2026-12-15 | 26,119 |
| 2026-12-16 | 16,531 |
| 2026-12-17 | 24,903 |
| 2026-12-18 | 22,402 |
| 2026-12-19 | 25,471 |
| 2026-12-20 | 14,241 |
| 2026-12-21 | 27,218 |
| 2026-12-22 | 23,987 |
| 2026-12-23 | 21,030 |
| 2026-12-24 | 20,325 |
| 2026-12-25 | 21,545 |
| 2026-12-26 | 17,737 |
| 2026-12-27 | 24,559 |
| 2026-12-28 | 21,667 |
| 2026-12-29 | 22,501 |
| 2026-12-30 | 26,447 |
| 2026-12-31 | 20,104 |
| 2027-01-01 | 18,455 |
| 2027-01-02 | 26,052 |
| 2027-01-03 | 14,776 |
| 2027-01-04 | 28,401 |
| 2027-01-05 | 22,326 |
| 2027-01-06 | 35,511 |
| 2027-01-07 | 23,907 |
| 2027-01-08 | 25,809 |
| 2027-01-09 | 21,567 |
| 2027-01-10 | 24,675 |
| 2027-01-11 | 24,080 |
| 2027-01-12 | 22,958 |
| 2027-01-13 | 23,246 |
| 2027-01-14 | 21,857 |
| 2027-01-15 | 22,688 |
| 2027-01-16 | 26,747 |
| 2027-01-17 | 20,525 |
| 2027-01-18 | 24,834 |
| 2027-01-19 | 22,479 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
