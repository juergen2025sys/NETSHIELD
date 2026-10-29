# Seen-DB Expiry Forecast

Lauf: 2026-10-29 22:44 CET (Europe/Berlin)
Gesamt: 11,237,937 IPs in seen_db.json (8,072,018 aktiv/180-Tage-Pfad, 3,165,919 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 289,879 |
| 8-14 Tage | 187,036 |
| 15-30 Tage | 647,762 |
| 31-60 Tage | 766,605 |
| 61-90 Tage | 822,552 |
| 91-180 Tage | 5,358,184 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,827,315 |
| 0-3 Tage | 61,963 |
| 4-7 Tage | 45,635 |
| 8-14 Tage | 84,464 |
| 15-30 Tage | 146,542 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-29 | 9,786 |
| 2026-10-30 | 20,008 |
| 2026-10-31 | 16,873 |
| 2026-11-01 | 15,296 |
| 2026-11-02 | 11,854 |
| 2026-11-03 | 16,558 |
| 2026-11-04 | 10,021 |
| 2026-11-05 | 7,202 |
| 2026-11-06 | 12,024 |
| 2026-11-07 | 13,310 |
| 2026-11-08 | 6,233 |
| 2026-11-09 | 11,430 |
| 2026-11-10 | 23,612 |
| 2026-11-11 | 9,856 |
| 2026-11-12 | 7,999 |
| 2026-11-13 | 3,313 |
| 2026-11-14 | 11,563 |
| 2026-11-15 | 14,290 |
| 2026-11-16 | 18,845 |
| 2026-11-17 | 9,307 |
| 2026-11-18 | 3,482 |
| 2026-11-19 | 8,802 |
| 2026-11-20 | 10,884 |
| 2026-11-21 | 9,985 |
| 2026-11-22 | 10,019 |
| 2026-11-23 | 10,061 |
| 2026-11-24 | 10,146 |
| 2026-11-25 | 7,646 |
| 2026-11-26 | 3,371 |
| 2026-11-27 | 3,920 |
| 2026-11-28 | 3,590 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,827,315** IPs. Brutto faellig in den naechsten 30 Tagen: **331,286**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,096,601**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-29 | 9,786 | 2,000 |
| 2026-10-30 | 20,008 | 2,000 |
| 2026-10-31 | 16,873 | 2,000 |
| 2026-11-01 | 15,296 | 2,000 |
| 2026-11-02 | 11,854 | 2,000 |
| 2026-11-03 | 16,558 | 2,000 |
| 2026-11-04 | 10,021 | 2,000 |
| 2026-11-05 | 7,202 | 2,000 |
| 2026-11-06 | 12,024 | 2,000 |
| 2026-11-07 | 13,310 | 2,000 |
| 2026-11-08 | 6,233 | 2,000 |
| 2026-11-09 | 11,430 | 2,000 |
| 2026-11-10 | 23,612 | 2,000 |
| 2026-11-11 | 9,856 | 2,000 |
| 2026-11-12 | 7,999 | 2,000 |
| 2026-11-13 | 3,313 | 2,000 |
| 2026-11-14 | 11,563 | 2,000 |
| 2026-11-15 | 14,290 | 2,000 |
| 2026-11-16 | 18,845 | 2,000 |
| 2026-11-17 | 9,307 | 2,000 |
| 2026-11-18 | 3,482 | 2,000 |
| 2026-11-19 | 8,802 | 2,000 |
| 2026-11-20 | 10,884 | 2,000 |
| 2026-11-21 | 9,985 | 2,000 |
| 2026-11-22 | 10,019 | 2,000 |
| 2026-11-23 | 10,061 | 2,000 |
| 2026-11-24 | 10,146 | 2,000 |
| 2026-11-25 | 7,646 | 2,000 |
| 2026-11-26 | 3,371 | 2,000 |
| 2026-11-27 | 3,920 | 2,000 |
| 2026-11-28 | 3,590 | 2,000 |

> Hinweis: Der Rueckstau von 3,096,601 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-30 | 61,481 |
| 2026-10-31 | 87,985 |
| 2026-11-01 | 27,685 |
| 2026-11-02 | 28,624 |
| 2026-11-03 | 29,565 |
| 2026-11-04 | 29,423 |
| 2026-11-05 | 25,116 |
| 2026-11-06 | 36,143 |
| 2026-11-07 | 24,315 |
| 2026-11-08 | 25,986 |
| 2026-11-09 | 25,402 |
| 2026-11-10 | 32,554 |
| 2026-11-11 | 22,228 |
| 2026-11-12 | 20,408 |
| 2026-11-13 | 19,548 |
| 2026-11-14 | 22,849 |
| 2026-11-15 | 17,386 |
| 2026-11-16 | 17,868 |
| 2026-11-17 | 15,166 |
| 2026-11-18 | 19,416 |
| 2026-11-19 | 173,323 |
| 2026-11-20 | 26,031 |
| 2026-11-21 | 61,180 |
| 2026-11-22 | 30,288 |
| 2026-11-23 | 25,550 |
| 2026-11-24 | 26,367 |
| 2026-11-25 | 27,408 |
| 2026-11-26 | 28,568 |
| 2026-11-27 | 27,751 |
| 2026-11-28 | 109,063 |
| 2026-11-29 | 28,093 |
| 2026-11-30 | 25,448 |
| 2026-12-01 | 26,466 |
| 2026-12-02 | 26,110 |
| 2026-12-03 | 25,927 |
| 2026-12-04 | 27,846 |
| 2026-12-05 | 25,882 |
| 2026-12-06 | 30,056 |
| 2026-12-07 | 23,679 |
| 2026-12-08 | 39,295 |
| 2026-12-09 | 54,900 |
| 2026-12-10 | 25,029 |
| 2026-12-11 | 27,705 |
| 2026-12-12 | 24,324 |
| 2026-12-13 | 23,794 |
| 2026-12-14 | 23,410 |
| 2026-12-15 | 26,184 |
| 2026-12-16 | 16,592 |
| 2026-12-17 | 24,962 |
| 2026-12-18 | 22,458 |
| 2026-12-19 | 25,554 |
| 2026-12-20 | 14,288 |
| 2026-12-21 | 27,300 |
| 2026-12-22 | 24,065 |
| 2026-12-23 | 21,095 |
| 2026-12-24 | 20,380 |
| 2026-12-25 | 21,592 |
| 2026-12-26 | 17,801 |
| 2026-12-27 | 24,639 |
| 2026-12-28 | 21,731 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
