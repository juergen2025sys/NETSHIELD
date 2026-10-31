# Seen-DB Expiry Forecast

Lauf: 2026-10-31 01:00 CET (Europe/Berlin)
Gesamt: 11,231,656 IPs in seen_db.json (8,057,861 aktiv/180-Tage-Pfad, 3,173,795 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 288,839 |
| 8-14 Tage | 168,954 |
| 15-30 Tage | 658,858 |
| 31-60 Tage | 762,034 |
| 61-90 Tage | 870,303 |
| 91-180 Tage | 5,308,873 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,856,918 |
| 0-3 Tage | 60,569 |
| 4-7 Tage | 42,550 |
| 8-14 Tage | 73,982 |
| 15-30 Tage | 139,776 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-31 | 16,870 |
| 2026-11-01 | 15,294 |
| 2026-11-02 | 11,852 |
| 2026-11-03 | 16,553 |
| 2026-11-04 | 10,019 |
| 2026-11-05 | 7,201 |
| 2026-11-06 | 12,022 |
| 2026-11-07 | 13,308 |
| 2026-11-08 | 6,230 |
| 2026-11-09 | 11,426 |
| 2026-11-10 | 23,607 |
| 2026-11-11 | 9,852 |
| 2026-11-12 | 7,996 |
| 2026-11-13 | 3,311 |
| 2026-11-14 | 11,560 |
| 2026-11-15 | 14,284 |
| 2026-11-16 | 18,842 |
| 2026-11-17 | 9,304 |
| 2026-11-18 | 3,482 |
| 2026-11-19 | 8,799 |
| 2026-11-20 | 10,879 |
| 2026-11-21 | 9,982 |
| 2026-11-22 | 10,013 |
| 2026-11-23 | 10,058 |
| 2026-11-24 | 10,142 |
| 2026-11-25 | 7,639 |
| 2026-11-26 | 3,364 |
| 2026-11-27 | 3,906 |
| 2026-11-28 | 3,575 |
| 2026-11-29 | 8,185 |
| 2026-11-30 | 7,322 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,856,918** IPs. Brutto faellig in den naechsten 30 Tagen: **316,877**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,111,795**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-31 | 16,870 | 2,000 |
| 2026-11-01 | 15,294 | 2,000 |
| 2026-11-02 | 11,852 | 2,000 |
| 2026-11-03 | 16,553 | 2,000 |
| 2026-11-04 | 10,019 | 2,000 |
| 2026-11-05 | 7,201 | 2,000 |
| 2026-11-06 | 12,022 | 2,000 |
| 2026-11-07 | 13,308 | 2,000 |
| 2026-11-08 | 6,230 | 2,000 |
| 2026-11-09 | 11,426 | 2,000 |
| 2026-11-10 | 23,607 | 2,000 |
| 2026-11-11 | 9,852 | 2,000 |
| 2026-11-12 | 7,996 | 2,000 |
| 2026-11-13 | 3,311 | 2,000 |
| 2026-11-14 | 11,560 | 2,000 |
| 2026-11-15 | 14,284 | 2,000 |
| 2026-11-16 | 18,842 | 2,000 |
| 2026-11-17 | 9,304 | 2,000 |
| 2026-11-18 | 3,482 | 2,000 |
| 2026-11-19 | 8,799 | 2,000 |
| 2026-11-20 | 10,879 | 2,000 |
| 2026-11-21 | 9,982 | 2,000 |
| 2026-11-22 | 10,013 | 2,000 |
| 2026-11-23 | 10,058 | 2,000 |
| 2026-11-24 | 10,142 | 2,000 |
| 2026-11-25 | 7,639 | 2,000 |
| 2026-11-26 | 3,364 | 2,000 |
| 2026-11-27 | 3,906 | 2,000 |
| 2026-11-28 | 3,575 | 2,000 |
| 2026-11-29 | 8,185 | 2,000 |
| 2026-11-30 | 7,322 | 2,000 |

> Hinweis: Der Rueckstau von 3,111,795 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-31 | 87,983 |
| 2026-11-01 | 27,683 |
| 2026-11-02 | 28,623 |
| 2026-11-03 | 29,563 |
| 2026-11-04 | 29,421 |
| 2026-11-05 | 25,114 |
| 2026-11-06 | 36,140 |
| 2026-11-07 | 24,312 |
| 2026-11-08 | 25,983 |
| 2026-11-09 | 25,397 |
| 2026-11-10 | 32,547 |
| 2026-11-11 | 22,224 |
| 2026-11-12 | 20,408 |
| 2026-11-13 | 19,548 |
| 2026-11-14 | 22,847 |
| 2026-11-15 | 17,385 |
| 2026-11-16 | 17,867 |
| 2026-11-17 | 15,166 |
| 2026-11-18 | 19,412 |
| 2026-11-19 | 173,310 |
| 2026-11-20 | 26,026 |
| 2026-11-21 | 61,179 |
| 2026-11-22 | 30,286 |
| 2026-11-23 | 25,547 |
| 2026-11-24 | 26,366 |
| 2026-11-25 | 27,402 |
| 2026-11-26 | 28,568 |
| 2026-11-27 | 27,749 |
| 2026-11-28 | 109,058 |
| 2026-11-29 | 28,092 |
| 2026-11-30 | 25,445 |
| 2026-12-01 | 26,463 |
| 2026-12-02 | 26,108 |
| 2026-12-03 | 25,926 |
| 2026-12-04 | 27,844 |
| 2026-12-05 | 25,877 |
| 2026-12-06 | 30,054 |
| 2026-12-07 | 23,676 |
| 2026-12-08 | 39,292 |
| 2026-12-09 | 54,890 |
| 2026-12-10 | 25,028 |
| 2026-12-11 | 27,704 |
| 2026-12-12 | 24,321 |
| 2026-12-13 | 23,789 |
| 2026-12-14 | 23,407 |
| 2026-12-15 | 26,181 |
| 2026-12-16 | 16,588 |
| 2026-12-17 | 24,961 |
| 2026-12-18 | 22,453 |
| 2026-12-19 | 25,553 |
| 2026-12-20 | 14,285 |
| 2026-12-21 | 27,294 |
| 2026-12-22 | 24,063 |
| 2026-12-23 | 21,091 |
| 2026-12-24 | 20,380 |
| 2026-12-25 | 21,589 |
| 2026-12-26 | 17,801 |
| 2026-12-27 | 24,632 |
| 2026-12-28 | 21,726 |
| 2026-12-29 | 22,550 |
| 2026-12-30 | 26,508 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
