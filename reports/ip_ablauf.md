# Seen-DB Expiry Forecast

Lauf: 2026-11-08 08:29 CET (Europe/Berlin)
Gesamt: 11,181,721 IPs in seen_db.json (7,964,785 aktiv/180-Tage-Pfad, 3,216,936 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 160,212 |
| 8-14 Tage | 343,037 |
| 15-30 Tage | 523,140 |
| 31-60 Tage | 726,042 |
| 61-90 Tage | 1,137,840 |
| 91-180 Tage | 5,074,514 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,950,242 |
| 0-3 Tage | 51,027 |
| 4-7 Tage | 37,074 |
| 8-14 Tage | 71,088 |
| 15-30 Tage | 107,505 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-08 | 6,216 |
| 2026-11-09 | 11,403 |
| 2026-11-10 | 23,576 |
| 2026-11-11 | 9,832 |
| 2026-11-12 | 7,977 |
| 2026-11-13 | 3,302 |
| 2026-11-14 | 11,537 |
| 2026-11-15 | 14,258 |
| 2026-11-16 | 18,799 |
| 2026-11-17 | 9,282 |
| 2026-11-18 | 3,465 |
| 2026-11-19 | 8,766 |
| 2026-11-20 | 10,849 |
| 2026-11-21 | 9,942 |
| 2026-11-22 | 9,985 |
| 2026-11-23 | 10,030 |
| 2026-11-24 | 10,107 |
| 2026-11-25 | 7,617 |
| 2026-11-26 | 3,342 |
| 2026-11-27 | 3,864 |
| 2026-11-28 | 3,547 |
| 2026-11-29 | 8,143 |
| 2026-11-30 | 7,133 |
| 2026-12-01 | 8,088 |
| 2026-12-02 | 4,607 |
| 2026-12-03 | 7,739 |
| 2026-12-04 | 5,775 |
| 2026-12-05 | 5,429 |
| 2026-12-06 | 3,122 |
| 2026-12-07 | 7,845 |
| 2026-12-08 | 4,577 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,950,242** IPs. Brutto faellig in den naechsten 30 Tagen: **260,154**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,148,396**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-08 | 6,216 | 2,000 |
| 2026-11-09 | 11,403 | 2,000 |
| 2026-11-10 | 23,576 | 2,000 |
| 2026-11-11 | 9,832 | 2,000 |
| 2026-11-12 | 7,977 | 2,000 |
| 2026-11-13 | 3,302 | 2,000 |
| 2026-11-14 | 11,537 | 2,000 |
| 2026-11-15 | 14,258 | 2,000 |
| 2026-11-16 | 18,799 | 2,000 |
| 2026-11-17 | 9,282 | 2,000 |
| 2026-11-18 | 3,465 | 2,000 |
| 2026-11-19 | 8,766 | 2,000 |
| 2026-11-20 | 10,849 | 2,000 |
| 2026-11-21 | 9,942 | 2,000 |
| 2026-11-22 | 9,985 | 2,000 |
| 2026-11-23 | 10,030 | 2,000 |
| 2026-11-24 | 10,107 | 2,000 |
| 2026-11-25 | 7,617 | 2,000 |
| 2026-11-26 | 3,342 | 2,000 |
| 2026-11-27 | 3,864 | 2,000 |
| 2026-11-28 | 3,547 | 2,000 |
| 2026-11-29 | 8,143 | 2,000 |
| 2026-11-30 | 7,133 | 2,000 |
| 2026-12-01 | 8,088 | 2,000 |
| 2026-12-02 | 4,607 | 2,000 |
| 2026-12-03 | 7,739 | 2,000 |
| 2026-12-04 | 5,775 | 2,000 |
| 2026-12-05 | 5,429 | 2,000 |
| 2026-12-06 | 3,122 | 2,000 |
| 2026-12-07 | 7,845 | 2,000 |
| 2026-12-08 | 4,577 | 2,000 |

> Hinweis: Der Rueckstau von 3,148,396 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-09 | 25,367 |
| 2026-11-10 | 32,523 |
| 2026-11-11 | 22,204 |
| 2026-11-12 | 20,393 |
| 2026-11-13 | 19,534 |
| 2026-11-14 | 22,818 |
| 2026-11-15 | 17,373 |
| 2026-11-16 | 17,848 |
| 2026-11-17 | 15,154 |
| 2026-11-18 | 19,399 |
| 2026-11-19 | 173,251 |
| 2026-11-20 | 26,002 |
| 2026-11-21 | 61,122 |
| 2026-11-22 | 30,261 |
| 2026-11-23 | 25,523 |
| 2026-11-24 | 26,347 |
| 2026-11-25 | 27,380 |
| 2026-11-26 | 28,549 |
| 2026-11-27 | 27,737 |
| 2026-11-28 | 109,023 |
| 2026-11-29 | 28,079 |
| 2026-11-30 | 25,431 |
| 2026-12-01 | 26,454 |
| 2026-12-02 | 26,087 |
| 2026-12-03 | 25,898 |
| 2026-12-04 | 27,824 |
| 2026-12-05 | 25,864 |
| 2026-12-06 | 30,024 |
| 2026-12-07 | 23,662 |
| 2026-12-08 | 39,258 |
| 2026-12-09 | 54,803 |
| 2026-12-10 | 25,014 |
| 2026-12-11 | 27,681 |
| 2026-12-12 | 24,302 |
| 2026-12-13 | 23,767 |
| 2026-12-14 | 23,372 |
| 2026-12-15 | 26,155 |
| 2026-12-16 | 16,573 |
| 2026-12-17 | 24,942 |
| 2026-12-18 | 22,434 |
| 2026-12-19 | 25,520 |
| 2026-12-20 | 14,269 |
| 2026-12-21 | 27,258 |
| 2026-12-22 | 24,033 |
| 2026-12-23 | 21,068 |
| 2026-12-24 | 20,363 |
| 2026-12-25 | 21,574 |
| 2026-12-26 | 17,782 |
| 2026-12-27 | 24,601 |
| 2026-12-28 | 21,703 |
| 2026-12-29 | 22,534 |
| 2026-12-30 | 26,485 |
| 2026-12-31 | 20,131 |
| 2027-01-01 | 18,488 |
| 2027-01-02 | 26,085 |
| 2027-01-03 | 14,800 |
| 2027-01-04 | 28,429 |
| 2027-01-05 | 22,367 |
| 2027-01-06 | 35,563 |
| 2027-01-07 | 23,946 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
