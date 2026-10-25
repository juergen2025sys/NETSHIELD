# Seen-DB Expiry Forecast

Lauf: 2026-10-25 14:53 CET (Europe/Berlin)
Gesamt: 11,137,806 IPs in seen_db.json (7,989,794 aktiv/180-Tage-Pfad, 3,148,012 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 242,693 |
| 8-14 Tage | 199,300 |
| 15-30 Tage | 555,847 |
| 31-60 Tage | 874,185 |
| 61-90 Tage | 731,084 |
| 91-180 Tage | 5,386,685 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,761,686 |
| 0-3 Tage | 66,702 |
| 4-7 Tage | 62,008 |
| 8-14 Tage | 77,274 |
| 15-30 Tage | 180,342 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-25 | 11,041 |
| 2026-10-26 | 9,394 |
| 2026-10-27 | 35,030 |
| 2026-10-28 | 11,237 |
| 2026-10-29 | 9,793 |
| 2026-10-30 | 20,024 |
| 2026-10-31 | 16,887 |
| 2026-11-01 | 15,304 |
| 2026-11-02 | 11,863 |
| 2026-11-03 | 16,570 |
| 2026-11-04 | 10,030 |
| 2026-11-05 | 7,208 |
| 2026-11-06 | 12,036 |
| 2026-11-07 | 13,322 |
| 2026-11-08 | 6,245 |
| 2026-11-09 | 11,443 |
| 2026-11-10 | 23,628 |
| 2026-11-11 | 9,868 |
| 2026-11-12 | 8,020 |
| 2026-11-13 | 3,320 |
| 2026-11-14 | 11,583 |
| 2026-11-15 | 14,307 |
| 2026-11-16 | 18,887 |
| 2026-11-17 | 9,321 |
| 2026-11-18 | 3,492 |
| 2026-11-19 | 8,830 |
| 2026-11-20 | 10,917 |
| 2026-11-21 | 10,032 |
| 2026-11-22 | 10,062 |
| 2026-11-23 | 10,117 |
| 2026-11-24 | 10,200 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,761,686** IPs. Brutto faellig in den naechsten 30 Tagen: **380,011**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,079,697**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-25 | 11,041 | 2,000 |
| 2026-10-26 | 9,394 | 2,000 |
| 2026-10-27 | 35,030 | 2,000 |
| 2026-10-28 | 11,237 | 2,000 |
| 2026-10-29 | 9,793 | 2,000 |
| 2026-10-30 | 20,024 | 2,000 |
| 2026-10-31 | 16,887 | 2,000 |
| 2026-11-01 | 15,304 | 2,000 |
| 2026-11-02 | 11,863 | 2,000 |
| 2026-11-03 | 16,570 | 2,000 |
| 2026-11-04 | 10,030 | 2,000 |
| 2026-11-05 | 7,208 | 2,000 |
| 2026-11-06 | 12,036 | 2,000 |
| 2026-11-07 | 13,322 | 2,000 |
| 2026-11-08 | 6,245 | 2,000 |
| 2026-11-09 | 11,443 | 2,000 |
| 2026-11-10 | 23,628 | 2,000 |
| 2026-11-11 | 9,868 | 2,000 |
| 2026-11-12 | 8,020 | 2,000 |
| 2026-11-13 | 3,320 | 2,000 |
| 2026-11-14 | 11,583 | 2,000 |
| 2026-11-15 | 14,307 | 2,000 |
| 2026-11-16 | 18,887 | 2,000 |
| 2026-11-17 | 9,321 | 2,000 |
| 2026-11-18 | 3,492 | 2,000 |
| 2026-11-19 | 8,830 | 2,000 |
| 2026-11-20 | 10,917 | 2,000 |
| 2026-11-21 | 10,032 | 2,000 |
| 2026-11-22 | 10,062 | 2,000 |
| 2026-11-23 | 10,117 | 2,000 |
| 2026-11-24 | 10,200 | 2,000 |

> Hinweis: Der Rueckstau von 3,079,697 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-26 | 20,154 |
| 2026-10-27 | 20,372 |
| 2026-10-28 | 15,473 |
| 2026-10-29 | 9,478 |
| 2026-10-30 | 61,515 |
| 2026-10-31 | 88,003 |
| 2026-11-01 | 27,698 |
| 2026-11-02 | 28,640 |
| 2026-11-03 | 29,586 |
| 2026-11-04 | 29,445 |
| 2026-11-05 | 25,131 |
| 2026-11-06 | 36,175 |
| 2026-11-07 | 24,329 |
| 2026-11-08 | 25,994 |
| 2026-11-09 | 25,416 |
| 2026-11-10 | 32,574 |
| 2026-11-11 | 22,244 |
| 2026-11-12 | 20,426 |
| 2026-11-13 | 19,569 |
| 2026-11-14 | 22,860 |
| 2026-11-15 | 17,392 |
| 2026-11-16 | 17,876 |
| 2026-11-17 | 15,177 |
| 2026-11-18 | 19,426 |
| 2026-11-19 | 173,374 |
| 2026-11-20 | 26,050 |
| 2026-11-21 | 61,205 |
| 2026-11-22 | 30,309 |
| 2026-11-23 | 25,572 |
| 2026-11-24 | 26,377 |
| 2026-11-25 | 27,434 |
| 2026-11-26 | 28,582 |
| 2026-11-27 | 27,769 |
| 2026-11-28 | 109,091 |
| 2026-11-29 | 28,101 |
| 2026-11-30 | 25,461 |
| 2026-12-01 | 26,475 |
| 2026-12-02 | 26,119 |
| 2026-12-03 | 25,939 |
| 2026-12-04 | 27,858 |
| 2026-12-05 | 25,901 |
| 2026-12-06 | 30,070 |
| 2026-12-07 | 23,689 |
| 2026-12-08 | 39,311 |
| 2026-12-09 | 54,971 |
| 2026-12-10 | 25,045 |
| 2026-12-11 | 27,718 |
| 2026-12-12 | 24,339 |
| 2026-12-13 | 23,817 |
| 2026-12-14 | 23,434 |
| 2026-12-15 | 26,206 |
| 2026-12-16 | 16,612 |
| 2026-12-17 | 24,979 |
| 2026-12-18 | 22,482 |
| 2026-12-19 | 25,570 |
| 2026-12-20 | 14,298 |
| 2026-12-21 | 27,318 |
| 2026-12-22 | 24,093 |
| 2026-12-23 | 21,109 |
| 2026-12-24 | 20,394 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
