# Seen-DB Expiry Forecast

Lauf: 2026-11-28 12:36 CET (Europe/Berlin)
Gesamt: 11,316,589 IPs in seen_db.json (7,807,978 aktiv/180-Tage-Pfad, 3,508,611 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 185,300 |
| 8-14 Tage | 224,197 |
| 15-30 Tage | 354,418 |
| 31-60 Tage | 819,505 |
| 61-90 Tage | 1,493,830 |
| 91-180 Tage | 4,730,728 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 3,118,281 |
| 0-3 Tage | 26,769 |
| 4-7 Tage | 23,370 |
| 8-14 Tage | 37,479 |
| 15-30 Tage | 302,712 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-28 | 3,521 |
| 2026-11-29 | 8,108 |
| 2026-11-30 | 7,086 |
| 2026-12-01 | 8,054 |
| 2026-12-02 | 4,553 |
| 2026-12-03 | 7,699 |
| 2026-12-04 | 5,740 |
| 2026-12-05 | 5,378 |
| 2026-12-06 | 3,079 |
| 2026-12-07 | 7,769 |
| 2026-12-08 | 4,438 |
| 2026-12-09 | 8,994 |
| 2026-12-10 | 5,993 |
| 2026-12-11 | 4,634 |
| 2026-12-12 | 2,572 |
| 2026-12-13 | 2,985 |
| 2026-12-14 | 7,582 |
| 2026-12-15 | 8,074 |
| 2026-12-16 | 7,479 |
| 2026-12-17 | 7,616 |
| 2026-12-18 | 9,336 |
| 2026-12-19 | 1,625 |
| 2026-12-20 | 10,060 |
| 2026-12-21 | 8,988 |
| 2026-12-22 | 31,678 |
| 2026-12-23 | 14,712 |
| 2026-12-24 | 19,435 |
| 2026-12-25 | 15,203 |
| 2026-12-26 | 18,550 |
| 2026-12-27 | 28,706 |
| 2026-12-28 | 81,386 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **3,118,281** IPs. Brutto faellig in den naechsten 30 Tagen: **361,033**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,417,314**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-28 | 3,521 | 2,000 |
| 2026-11-29 | 8,108 | 2,000 |
| 2026-11-30 | 7,086 | 2,000 |
| 2026-12-01 | 8,054 | 2,000 |
| 2026-12-02 | 4,553 | 2,000 |
| 2026-12-03 | 7,699 | 2,000 |
| 2026-12-04 | 5,740 | 2,000 |
| 2026-12-05 | 5,378 | 2,000 |
| 2026-12-06 | 3,079 | 2,000 |
| 2026-12-07 | 7,769 | 2,000 |
| 2026-12-08 | 4,438 | 2,000 |
| 2026-12-09 | 8,994 | 2,000 |
| 2026-12-10 | 5,993 | 2,000 |
| 2026-12-11 | 4,634 | 2,000 |
| 2026-12-12 | 2,572 | 2,000 |
| 2026-12-13 | 2,985 | 2,000 |
| 2026-12-14 | 7,582 | 2,000 |
| 2026-12-15 | 8,074 | 2,000 |
| 2026-12-16 | 7,479 | 2,000 |
| 2026-12-17 | 7,616 | 2,000 |
| 2026-12-18 | 9,336 | 2,000 |
| 2026-12-19 | 1,625 | 2,000 |
| 2026-12-20 | 10,060 | 2,000 |
| 2026-12-21 | 8,988 | 2,000 |
| 2026-12-22 | 31,678 | 2,000 |
| 2026-12-23 | 14,712 | 2,000 |
| 2026-12-24 | 19,435 | 2,000 |
| 2026-12-25 | 15,203 | 2,000 |
| 2026-12-26 | 18,550 | 2,000 |
| 2026-12-27 | 28,706 | 2,000 |
| 2026-12-28 | 81,386 | 2,000 |

> Hinweis: Der Rueckstau von 3,417,314 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-29 | 28,028 |
| 2026-11-30 | 25,385 |
| 2026-12-01 | 26,411 |
| 2026-12-02 | 26,028 |
| 2026-12-03 | 25,843 |
| 2026-12-04 | 27,782 |
| 2026-12-05 | 25,823 |
| 2026-12-06 | 29,969 |
| 2026-12-07 | 23,625 |
| 2026-12-08 | 39,209 |
| 2026-12-09 | 54,567 |
| 2026-12-10 | 24,956 |
| 2026-12-11 | 27,618 |
| 2026-12-12 | 24,253 |
| 2026-12-13 | 23,696 |
| 2026-12-14 | 23,323 |
| 2026-12-15 | 26,095 |
| 2026-12-16 | 16,510 |
| 2026-12-17 | 24,867 |
| 2026-12-18 | 22,388 |
| 2026-12-19 | 25,440 |
| 2026-12-20 | 14,219 |
| 2026-12-21 | 27,198 |
| 2026-12-22 | 23,960 |
| 2026-12-23 | 21,003 |
| 2026-12-24 | 20,309 |
| 2026-12-25 | 21,524 |
| 2026-12-26 | 17,711 |
| 2026-12-27 | 24,534 |
| 2026-12-28 | 21,641 |
| 2026-12-29 | 22,481 |
| 2026-12-30 | 26,420 |
| 2026-12-31 | 20,080 |
| 2027-01-01 | 18,431 |
| 2027-01-02 | 26,024 |
| 2027-01-03 | 14,747 |
| 2027-01-04 | 28,374 |
| 2027-01-05 | 22,294 |
| 2027-01-06 | 35,474 |
| 2027-01-07 | 23,880 |
| 2027-01-08 | 25,773 |
| 2027-01-09 | 21,528 |
| 2027-01-10 | 24,653 |
| 2027-01-11 | 24,058 |
| 2027-01-12 | 22,937 |
| 2027-01-13 | 23,224 |
| 2027-01-14 | 21,833 |
| 2027-01-15 | 22,669 |
| 2027-01-16 | 26,721 |
| 2027-01-17 | 20,498 |
| 2027-01-18 | 24,817 |
| 2027-01-19 | 22,467 |
| 2027-01-20 | 23,146 |
| 2027-01-21 | 45,446 |
| 2027-01-22 | 28,516 |
| 2027-01-23 | 25,810 |
| 2027-01-24 | 25,110 |
| 2027-01-25 | 41,844 |
| 2027-01-26 | 63,384 |
| 2027-01-27 | 46,866 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
