# Seen-DB Expiry Forecast

Lauf: 2026-10-28 01:25 CET (Europe/Berlin)
Gesamt: 11,196,808 IPs in seen_db.json (8,041,103 aktiv/180-Tage-Pfad, 3,155,705 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 289,745 |
| 8-14 Tage | 191,787 |
| 15-30 Tage | 559,210 |
| 31-60 Tage | 854,133 |
| 61-90 Tage | 797,483 |
| 91-180 Tage | 5,348,745 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,816,495 |
| 0-3 Tage | 57,909 |
| 4-7 Tage | 53,749 |
| 8-14 Tage | 83,695 |
| 15-30 Tage | 143,857 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-28 | 11,231 |
| 2026-10-29 | 9,786 |
| 2026-10-30 | 20,014 |
| 2026-10-31 | 16,878 |
| 2026-11-01 | 15,300 |
| 2026-11-02 | 11,861 |
| 2026-11-03 | 16,563 |
| 2026-11-04 | 10,025 |
| 2026-11-05 | 7,204 |
| 2026-11-06 | 12,027 |
| 2026-11-07 | 13,314 |
| 2026-11-08 | 6,237 |
| 2026-11-09 | 11,436 |
| 2026-11-10 | 23,616 |
| 2026-11-11 | 9,861 |
| 2026-11-12 | 8,011 |
| 2026-11-13 | 3,314 |
| 2026-11-14 | 11,571 |
| 2026-11-15 | 14,298 |
| 2026-11-16 | 18,867 |
| 2026-11-17 | 9,311 |
| 2026-11-18 | 3,484 |
| 2026-11-19 | 8,812 |
| 2026-11-20 | 10,892 |
| 2026-11-21 | 10,001 |
| 2026-11-22 | 10,031 |
| 2026-11-23 | 10,076 |
| 2026-11-24 | 10,173 |
| 2026-11-25 | 7,659 |
| 2026-11-26 | 3,386 |
| 2026-11-27 | 3,971 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,816,495** IPs. Brutto faellig in den naechsten 30 Tagen: **339,210**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,093,705**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-28 | 11,231 | 2,000 |
| 2026-10-29 | 9,786 | 2,000 |
| 2026-10-30 | 20,014 | 2,000 |
| 2026-10-31 | 16,878 | 2,000 |
| 2026-11-01 | 15,300 | 2,000 |
| 2026-11-02 | 11,861 | 2,000 |
| 2026-11-03 | 16,563 | 2,000 |
| 2026-11-04 | 10,025 | 2,000 |
| 2026-11-05 | 7,204 | 2,000 |
| 2026-11-06 | 12,027 | 2,000 |
| 2026-11-07 | 13,314 | 2,000 |
| 2026-11-08 | 6,237 | 2,000 |
| 2026-11-09 | 11,436 | 2,000 |
| 2026-11-10 | 23,616 | 2,000 |
| 2026-11-11 | 9,861 | 2,000 |
| 2026-11-12 | 8,011 | 2,000 |
| 2026-11-13 | 3,314 | 2,000 |
| 2026-11-14 | 11,571 | 2,000 |
| 2026-11-15 | 14,298 | 2,000 |
| 2026-11-16 | 18,867 | 2,000 |
| 2026-11-17 | 9,311 | 2,000 |
| 2026-11-18 | 3,484 | 2,000 |
| 2026-11-19 | 8,812 | 2,000 |
| 2026-11-20 | 10,892 | 2,000 |
| 2026-11-21 | 10,001 | 2,000 |
| 2026-11-22 | 10,031 | 2,000 |
| 2026-11-23 | 10,076 | 2,000 |
| 2026-11-24 | 10,173 | 2,000 |
| 2026-11-25 | 7,659 | 2,000 |
| 2026-11-26 | 3,386 | 2,000 |
| 2026-11-27 | 3,971 | 2,000 |

> Hinweis: Der Rueckstau von 3,093,705 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-28 | 15,457 |
| 2026-10-29 | 9,472 |
| 2026-10-30 | 61,494 |
| 2026-10-31 | 87,993 |
| 2026-11-01 | 27,690 |
| 2026-11-02 | 28,633 |
| 2026-11-03 | 29,572 |
| 2026-11-04 | 29,434 |
| 2026-11-05 | 25,120 |
| 2026-11-06 | 36,154 |
| 2026-11-07 | 24,317 |
| 2026-11-08 | 25,990 |
| 2026-11-09 | 25,409 |
| 2026-11-10 | 32,564 |
| 2026-11-11 | 22,233 |
| 2026-11-12 | 20,416 |
| 2026-11-13 | 19,559 |
| 2026-11-14 | 22,856 |
| 2026-11-15 | 17,387 |
| 2026-11-16 | 17,871 |
| 2026-11-17 | 15,173 |
| 2026-11-18 | 19,420 |
| 2026-11-19 | 173,342 |
| 2026-11-20 | 26,036 |
| 2026-11-21 | 61,189 |
| 2026-11-22 | 30,294 |
| 2026-11-23 | 25,553 |
| 2026-11-24 | 26,370 |
| 2026-11-25 | 27,410 |
| 2026-11-26 | 28,573 |
| 2026-11-27 | 27,761 |
| 2026-11-28 | 109,076 |
| 2026-11-29 | 28,098 |
| 2026-11-30 | 25,449 |
| 2026-12-01 | 26,470 |
| 2026-12-02 | 26,111 |
| 2026-12-03 | 25,932 |
| 2026-12-04 | 27,853 |
| 2026-12-05 | 25,888 |
| 2026-12-06 | 30,062 |
| 2026-12-07 | 23,683 |
| 2026-12-08 | 39,299 |
| 2026-12-09 | 54,931 |
| 2026-12-10 | 25,035 |
| 2026-12-11 | 27,708 |
| 2026-12-12 | 24,330 |
| 2026-12-13 | 23,799 |
| 2026-12-14 | 23,418 |
| 2026-12-15 | 26,189 |
| 2026-12-16 | 16,600 |
| 2026-12-17 | 24,965 |
| 2026-12-18 | 22,463 |
| 2026-12-19 | 25,556 |
| 2026-12-20 | 14,292 |
| 2026-12-21 | 27,309 |
| 2026-12-22 | 24,073 |
| 2026-12-23 | 21,103 |
| 2026-12-24 | 20,388 |
| 2026-12-25 | 21,595 |
| 2026-12-26 | 17,810 |
| 2026-12-27 | 24,648 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
