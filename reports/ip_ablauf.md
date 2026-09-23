# Seen-DB Expiry Forecast

Lauf: 2026-09-23 11:31 CEST (Europe/Berlin)
Gesamt: 11,545,976 IPs in seen_db.json (8,744,086 aktiv/180-Tage-Pfad, 2,801,890 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 101,129 |
| 8-14 Tage | 92,956 |
| 15-30 Tage | 2,295,425 |
| 31-60 Tage | 1,016,476 |
| 61-90 Tage | 891,756 |
| 91-180 Tage | 4,346,344 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 595,258 |
| 0-3 Tage | 645,707 |
| 4-7 Tage | 66,719 |
| 8-14 Tage | 1,343,505 |
| 15-30 Tage | 150,701 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-23 | 5,107 |
| 2026-09-24 | 11,381 |
| 2026-09-25 | 5,451 |
| 2026-09-26 | 623,768 |
| 2026-09-27 | 6,278 |
| 2026-09-28 | 774 |
| 2026-09-30 | 59,667 |
| 2026-10-01 | 7,646 |
| 2026-10-02 | 1,307,053 |
| 2026-10-03 | 2,971 |
| 2026-10-04 | 6,923 |
| 2026-10-05 | 2,904 |
| 2026-10-06 | 8,047 |
| 2026-10-07 | 7,961 |
| 2026-10-08 | 7,298 |
| 2026-10-09 | 10,186 |
| 2026-10-10 | 7,588 |
| 2026-10-11 | 6,279 |
| 2026-10-12 | 3,888 |
| 2026-10-13 | 8,332 |
| 2026-10-14 | 7,482 |
| 2026-10-15 | 8,359 |
| 2026-10-16 | 15,546 |
| 2026-10-17 | 9,986 |
| 2026-10-18 | 8,743 |
| 2026-10-19 | 5,192 |
| 2026-10-20 | 9,717 |
| 2026-10-21 | 9,665 |
| 2026-10-22 | 10,622 |
| 2026-10-23 | 13,402 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **595,258** IPs. Brutto faellig in den naechsten 30 Tagen: **2,198,216**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,733,474**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-23 | 5,107 | 2,000 |
| 2026-09-24 | 11,381 | 2,000 |
| 2026-09-25 | 5,451 | 2,000 |
| 2026-09-26 | 623,768 | 2,000 |
| 2026-09-27 | 6,278 | 2,000 |
| 2026-09-28 | 774 | 2,000 |
| 2026-09-30 | 59,667 | 2,000 |
| 2026-10-01 | 7,646 | 2,000 |
| 2026-10-02 | 1,307,053 | 2,000 |
| 2026-10-03 | 2,971 | 2,000 |
| 2026-10-04 | 6,923 | 2,000 |
| 2026-10-05 | 2,904 | 2,000 |
| 2026-10-06 | 8,047 | 2,000 |
| 2026-10-07 | 7,961 | 2,000 |
| 2026-10-08 | 7,298 | 2,000 |
| 2026-10-09 | 10,186 | 2,000 |
| 2026-10-10 | 7,588 | 2,000 |
| 2026-10-11 | 6,279 | 2,000 |
| 2026-10-12 | 3,888 | 2,000 |
| 2026-10-13 | 8,332 | 2,000 |
| 2026-10-14 | 7,482 | 2,000 |
| 2026-10-15 | 8,359 | 2,000 |
| 2026-10-16 | 15,546 | 2,000 |
| 2026-10-17 | 9,986 | 2,000 |
| 2026-10-18 | 8,743 | 2,000 |
| 2026-10-19 | 5,192 | 2,000 |
| 2026-10-20 | 9,717 | 2,000 |
| 2026-10-21 | 9,665 | 2,000 |
| 2026-10-22 | 10,622 | 2,000 |
| 2026-10-23 | 13,402 | 2,000 |

> Hinweis: Der Rueckstau von 2,733,474 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-24 | 16,638 |
| 2026-09-25 | 20,913 |
| 2026-09-26 | 17,433 |
| 2026-09-27 | 15,024 |
| 2026-09-28 | 11,603 |
| 2026-09-29 | 9,350 |
| 2026-09-30 | 10,168 |
| 2026-10-01 | 16,593 |
| 2026-10-02 | 7,716 |
| 2026-10-03 | 7,324 |
| 2026-10-04 | 12,618 |
| 2026-10-05 | 17,534 |
| 2026-10-06 | 16,122 |
| 2026-10-07 | 15,049 |
| 2026-10-08 | 61,386 |
| 2026-10-09 | 222,834 |
| 2026-10-10 | 53,373 |
| 2026-10-11 | 16,051 |
| 2026-10-12 | 66,583 |
| 2026-10-13 | 1,585,221 |
| 2026-10-14 | 32,921 |
| 2026-10-15 | 41,341 |
| 2026-10-16 | 51,312 |
| 2026-10-17 | 24,300 |
| 2026-10-18 | 14,276 |
| 2026-10-19 | 22,360 |
| 2026-10-20 | 11,146 |
| 2026-10-21 | 11,125 |
| 2026-10-22 | 30,757 |
| 2026-10-23 | 50,439 |
| 2026-10-24 | 41,750 |
| 2026-10-25 | 21,637 |
| 2026-10-26 | 20,360 |
| 2026-10-27 | 20,715 |
| 2026-10-28 | 15,820 |
| 2026-10-29 | 9,695 |
| 2026-10-30 | 62,000 |
| 2026-10-31 | 88,265 |
| 2026-11-01 | 27,898 |
| 2026-11-02 | 28,863 |
| 2026-11-03 | 29,873 |
| 2026-11-04 | 29,689 |
| 2026-11-05 | 25,327 |
| 2026-11-06 | 36,741 |
| 2026-11-07 | 24,517 |
| 2026-11-08 | 26,181 |
| 2026-11-09 | 25,608 |
| 2026-11-10 | 32,803 |
| 2026-11-11 | 22,434 |
| 2026-11-12 | 20,548 |
| 2026-11-13 | 19,696 |
| 2026-11-14 | 23,026 |
| 2026-11-15 | 17,505 |
| 2026-11-16 | 18,022 |
| 2026-11-17 | 15,281 |
| 2026-11-18 | 19,549 |
| 2026-11-19 | 174,261 |
| 2026-11-20 | 26,267 |
| 2026-11-21 | 61,606 |
| 2026-11-22 | 30,539 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
