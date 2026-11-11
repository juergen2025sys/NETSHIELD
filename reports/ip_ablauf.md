# Seen-DB Expiry Forecast

Lauf: 2026-11-11 17:02 CET (Europe/Berlin)
Gesamt: 11,260,037 IPs in seen_db.json (8,032,426 aktiv/180-Tage-Pfad, 3,227,611 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 132,466 |
| 8-14 Tage | 369,742 |
| 15-30 Tage | 551,203 |
| 31-60 Tage | 690,366 |
| 61-90 Tage | 1,168,498 |
| 91-180 Tage | 5,120,151 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,987,314 |
| 0-3 Tage | 32,616 |
| 4-7 Tage | 45,759 |
| 8-14 Tage | 67,214 |
| 15-30 Tage | 94,708 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-11 | 9,819 |
| 2026-11-12 | 7,968 |
| 2026-11-13 | 3,301 |
| 2026-11-14 | 11,528 |
| 2026-11-15 | 14,240 |
| 2026-11-16 | 18,787 |
| 2026-11-17 | 9,271 |
| 2026-11-18 | 3,461 |
| 2026-11-19 | 8,755 |
| 2026-11-20 | 10,832 |
| 2026-11-21 | 9,929 |
| 2026-11-22 | 9,975 |
| 2026-11-23 | 10,020 |
| 2026-11-24 | 10,096 |
| 2026-11-25 | 7,607 |
| 2026-11-26 | 3,338 |
| 2026-11-27 | 3,861 |
| 2026-11-28 | 3,542 |
| 2026-11-29 | 8,130 |
| 2026-11-30 | 7,115 |
| 2026-12-01 | 8,081 |
| 2026-12-02 | 4,583 |
| 2026-12-03 | 7,727 |
| 2026-12-04 | 5,766 |
| 2026-12-05 | 5,418 |
| 2026-12-06 | 3,103 |
| 2026-12-07 | 7,808 |
| 2026-12-08 | 4,509 |
| 2026-12-09 | 9,052 |
| 2026-12-10 | 6,059 |
| 2026-12-11 | 4,738 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,987,314** IPs. Brutto faellig in den naechsten 30 Tagen: **238,419**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,163,733**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-11 | 9,819 | 2,000 |
| 2026-11-12 | 7,968 | 2,000 |
| 2026-11-13 | 3,301 | 2,000 |
| 2026-11-14 | 11,528 | 2,000 |
| 2026-11-15 | 14,240 | 2,000 |
| 2026-11-16 | 18,787 | 2,000 |
| 2026-11-17 | 9,271 | 2,000 |
| 2026-11-18 | 3,461 | 2,000 |
| 2026-11-19 | 8,755 | 2,000 |
| 2026-11-20 | 10,832 | 2,000 |
| 2026-11-21 | 9,929 | 2,000 |
| 2026-11-22 | 9,975 | 2,000 |
| 2026-11-23 | 10,020 | 2,000 |
| 2026-11-24 | 10,096 | 2,000 |
| 2026-11-25 | 7,607 | 2,000 |
| 2026-11-26 | 3,338 | 2,000 |
| 2026-11-27 | 3,861 | 2,000 |
| 2026-11-28 | 3,542 | 2,000 |
| 2026-11-29 | 8,130 | 2,000 |
| 2026-11-30 | 7,115 | 2,000 |
| 2026-12-01 | 8,081 | 2,000 |
| 2026-12-02 | 4,583 | 2,000 |
| 2026-12-03 | 7,727 | 2,000 |
| 2026-12-04 | 5,766 | 2,000 |
| 2026-12-05 | 5,418 | 2,000 |
| 2026-12-06 | 3,103 | 2,000 |
| 2026-12-07 | 7,808 | 2,000 |
| 2026-12-08 | 4,509 | 2,000 |
| 2026-12-09 | 9,052 | 2,000 |
| 2026-12-10 | 6,059 | 2,000 |
| 2026-12-11 | 4,738 | 2,000 |

> Hinweis: Der Rueckstau von 3,163,733 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-12 | 20,378 |
| 2026-11-13 | 19,526 |
| 2026-11-14 | 22,805 |
| 2026-11-15 | 17,370 |
| 2026-11-16 | 17,841 |
| 2026-11-17 | 15,152 |
| 2026-11-18 | 19,394 |
| 2026-11-19 | 173,191 |
| 2026-11-20 | 25,995 |
| 2026-11-21 | 61,099 |
| 2026-11-22 | 30,249 |
| 2026-11-23 | 25,520 |
| 2026-11-24 | 26,324 |
| 2026-11-25 | 27,364 |
| 2026-11-26 | 28,534 |
| 2026-11-27 | 27,730 |
| 2026-11-28 | 109,005 |
| 2026-11-29 | 28,066 |
| 2026-11-30 | 25,428 |
| 2026-12-01 | 26,442 |
| 2026-12-02 | 26,082 |
| 2026-12-03 | 25,887 |
| 2026-12-04 | 27,815 |
| 2026-12-05 | 25,858 |
| 2026-12-06 | 30,016 |
| 2026-12-07 | 23,654 |
| 2026-12-08 | 39,247 |
| 2026-12-09 | 54,764 |
| 2026-12-10 | 25,005 |
| 2026-12-11 | 27,670 |
| 2026-12-12 | 24,293 |
| 2026-12-13 | 23,757 |
| 2026-12-14 | 23,367 |
| 2026-12-15 | 26,143 |
| 2026-12-16 | 16,562 |
| 2026-12-17 | 24,933 |
| 2026-12-18 | 22,426 |
| 2026-12-19 | 25,499 |
| 2026-12-20 | 14,261 |
| 2026-12-21 | 27,245 |
| 2026-12-22 | 24,017 |
| 2026-12-23 | 21,062 |
| 2026-12-24 | 20,347 |
| 2026-12-25 | 21,562 |
| 2026-12-26 | 17,769 |
| 2026-12-27 | 24,592 |
| 2026-12-28 | 21,691 |
| 2026-12-29 | 22,528 |
| 2026-12-30 | 26,473 |
| 2026-12-31 | 20,120 |
| 2027-01-01 | 18,474 |
| 2027-01-02 | 26,079 |
| 2027-01-03 | 14,796 |
| 2027-01-04 | 28,418 |
| 2027-01-05 | 22,355 |
| 2027-01-06 | 35,542 |
| 2027-01-07 | 23,935 |
| 2027-01-08 | 25,836 |
| 2027-01-09 | 21,591 |
| 2027-01-10 | 24,693 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
