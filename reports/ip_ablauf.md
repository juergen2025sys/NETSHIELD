# Seen-DB Expiry Forecast

Lauf: 2026-11-14 11:51 CET (Europe/Berlin)
Gesamt: 11,329,277 IPs in seen_db.json (8,088,132 aktiv/180-Tage-Pfad, 3,241,145 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 329,974 |
| 8-14 Tage | 274,662 |
| 15-30 Tage | 457,197 |
| 31-60 Tage | 689,052 |
| 61-90 Tage | 1,362,730 |
| 91-180 Tage | 4,974,517 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 3,004,464 |
| 0-3 Tage | 53,793 |
| 4-7 Tage | 32,960 |
| 8-14 Tage | 48,402 |
| 15-30 Tage | 101,526 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-14 | 11,524 |
| 2026-11-15 | 14,229 |
| 2026-11-16 | 18,779 |
| 2026-11-17 | 9,261 |
| 2026-11-18 | 3,461 |
| 2026-11-19 | 8,749 |
| 2026-11-20 | 10,827 |
| 2026-11-21 | 9,923 |
| 2026-11-22 | 9,971 |
| 2026-11-23 | 10,008 |
| 2026-11-24 | 10,090 |
| 2026-11-25 | 7,605 |
| 2026-11-26 | 3,337 |
| 2026-11-27 | 3,857 |
| 2026-11-28 | 3,534 |
| 2026-11-29 | 8,125 |
| 2026-11-30 | 7,106 |
| 2026-12-01 | 8,075 |
| 2026-12-02 | 4,576 |
| 2026-12-03 | 7,719 |
| 2026-12-04 | 5,757 |
| 2026-12-05 | 5,407 |
| 2026-12-06 | 3,097 |
| 2026-12-07 | 7,796 |
| 2026-12-08 | 4,480 |
| 2026-12-09 | 9,026 |
| 2026-12-10 | 6,031 |
| 2026-12-11 | 4,683 |
| 2026-12-12 | 2,607 |
| 2026-12-13 | 3,042 |
| 2026-12-14 | 7,720 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **3,004,464** IPs. Brutto faellig in den naechsten 30 Tagen: **230,402**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,172,866**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-14 | 11,524 | 2,000 |
| 2026-11-15 | 14,229 | 2,000 |
| 2026-11-16 | 18,779 | 2,000 |
| 2026-11-17 | 9,261 | 2,000 |
| 2026-11-18 | 3,461 | 2,000 |
| 2026-11-19 | 8,749 | 2,000 |
| 2026-11-20 | 10,827 | 2,000 |
| 2026-11-21 | 9,923 | 2,000 |
| 2026-11-22 | 9,971 | 2,000 |
| 2026-11-23 | 10,008 | 2,000 |
| 2026-11-24 | 10,090 | 2,000 |
| 2026-11-25 | 7,605 | 2,000 |
| 2026-11-26 | 3,337 | 2,000 |
| 2026-11-27 | 3,857 | 2,000 |
| 2026-11-28 | 3,534 | 2,000 |
| 2026-11-29 | 8,125 | 2,000 |
| 2026-11-30 | 7,106 | 2,000 |
| 2026-12-01 | 8,075 | 2,000 |
| 2026-12-02 | 4,576 | 2,000 |
| 2026-12-03 | 7,719 | 2,000 |
| 2026-12-04 | 5,757 | 2,000 |
| 2026-12-05 | 5,407 | 2,000 |
| 2026-12-06 | 3,097 | 2,000 |
| 2026-12-07 | 7,796 | 2,000 |
| 2026-12-08 | 4,480 | 2,000 |
| 2026-12-09 | 9,026 | 2,000 |
| 2026-12-10 | 6,031 | 2,000 |
| 2026-12-11 | 4,683 | 2,000 |
| 2026-12-12 | 2,607 | 2,000 |
| 2026-12-13 | 3,042 | 2,000 |
| 2026-12-14 | 7,720 | 2,000 |

> Hinweis: Der Rueckstau von 3,172,866 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-15 | 17,366 |
| 2026-11-16 | 17,836 |
| 2026-11-17 | 15,147 |
| 2026-11-18 | 19,388 |
| 2026-11-19 | 173,159 |
| 2026-11-20 | 25,989 |
| 2026-11-21 | 61,089 |
| 2026-11-22 | 30,242 |
| 2026-11-23 | 25,517 |
| 2026-11-24 | 26,317 |
| 2026-11-25 | 27,350 |
| 2026-11-26 | 28,527 |
| 2026-11-27 | 27,717 |
| 2026-11-28 | 108,992 |
| 2026-11-29 | 28,059 |
| 2026-11-30 | 25,416 |
| 2026-12-01 | 26,439 |
| 2026-12-02 | 26,066 |
| 2026-12-03 | 25,882 |
| 2026-12-04 | 27,809 |
| 2026-12-05 | 25,855 |
| 2026-12-06 | 30,010 |
| 2026-12-07 | 23,649 |
| 2026-12-08 | 39,234 |
| 2026-12-09 | 54,723 |
| 2026-12-10 | 24,996 |
| 2026-12-11 | 27,663 |
| 2026-12-12 | 24,288 |
| 2026-12-13 | 23,747 |
| 2026-12-14 | 23,361 |
| 2026-12-15 | 26,135 |
| 2026-12-16 | 16,556 |
| 2026-12-17 | 24,925 |
| 2026-12-18 | 22,417 |
| 2026-12-19 | 25,487 |
| 2026-12-20 | 14,254 |
| 2026-12-21 | 27,237 |
| 2026-12-22 | 24,004 |
| 2026-12-23 | 21,044 |
| 2026-12-24 | 20,341 |
| 2026-12-25 | 21,557 |
| 2026-12-26 | 17,761 |
| 2026-12-27 | 24,580 |
| 2026-12-28 | 21,684 |
| 2026-12-29 | 22,517 |
| 2026-12-30 | 26,467 |
| 2026-12-31 | 20,113 |
| 2027-01-01 | 18,468 |
| 2027-01-02 | 26,068 |
| 2027-01-03 | 14,788 |
| 2027-01-04 | 28,413 |
| 2027-01-05 | 22,347 |
| 2027-01-06 | 35,534 |
| 2027-01-07 | 23,924 |
| 2027-01-08 | 25,825 |
| 2027-01-09 | 21,582 |
| 2027-01-10 | 24,689 |
| 2027-01-11 | 24,099 |
| 2027-01-12 | 22,975 |
| 2027-01-13 | 23,261 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
