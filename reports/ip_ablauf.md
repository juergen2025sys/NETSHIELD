# Seen-DB Expiry Forecast

Lauf: 2026-11-03 19:21 CET (Europe/Berlin)
Gesamt: 11,182,041 IPs in seen_db.json (7,985,868 aktiv/180-Tage-Pfad, 3,196,173 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 198,843 |
| 8-14 Tage | 135,389 |
| 15-30 Tage | 686,787 |
| 31-60 Tage | 747,982 |
| 61-90 Tage | 876,355 |
| 91-180 Tage | 5,340,512 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,897,840 |
| 0-3 Tage | 45,776 |
| 4-7 Tage | 54,539 |
| 8-14 Tage | 75,087 |
| 15-30 Tage | 122,931 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-03 | 16,547 |
| 2026-11-04 | 10,016 |
| 2026-11-05 | 7,195 |
| 2026-11-06 | 12,018 |
| 2026-11-07 | 13,303 |
| 2026-11-08 | 6,224 |
| 2026-11-09 | 11,415 |
| 2026-11-10 | 23,597 |
| 2026-11-11 | 9,847 |
| 2026-11-12 | 7,991 |
| 2026-11-13 | 3,304 |
| 2026-11-14 | 11,551 |
| 2026-11-15 | 14,271 |
| 2026-11-16 | 18,825 |
| 2026-11-17 | 9,298 |
| 2026-11-18 | 3,476 |
| 2026-11-19 | 8,786 |
| 2026-11-20 | 10,867 |
| 2026-11-21 | 9,960 |
| 2026-11-22 | 10,000 |
| 2026-11-23 | 10,047 |
| 2026-11-24 | 10,119 |
| 2026-11-25 | 7,627 |
| 2026-11-26 | 3,351 |
| 2026-11-27 | 3,877 |
| 2026-11-28 | 3,556 |
| 2026-11-29 | 8,152 |
| 2026-11-30 | 7,167 |
| 2026-12-01 | 8,109 |
| 2026-12-02 | 4,671 |
| 2026-12-03 | 7,769 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,897,840** IPs. Brutto faellig in den naechsten 30 Tagen: **292,936**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,128,776**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-03 | 16,547 | 2,000 |
| 2026-11-04 | 10,016 | 2,000 |
| 2026-11-05 | 7,195 | 2,000 |
| 2026-11-06 | 12,018 | 2,000 |
| 2026-11-07 | 13,303 | 2,000 |
| 2026-11-08 | 6,224 | 2,000 |
| 2026-11-09 | 11,415 | 2,000 |
| 2026-11-10 | 23,597 | 2,000 |
| 2026-11-11 | 9,847 | 2,000 |
| 2026-11-12 | 7,991 | 2,000 |
| 2026-11-13 | 3,304 | 2,000 |
| 2026-11-14 | 11,551 | 2,000 |
| 2026-11-15 | 14,271 | 2,000 |
| 2026-11-16 | 18,825 | 2,000 |
| 2026-11-17 | 9,298 | 2,000 |
| 2026-11-18 | 3,476 | 2,000 |
| 2026-11-19 | 8,786 | 2,000 |
| 2026-11-20 | 10,867 | 2,000 |
| 2026-11-21 | 9,960 | 2,000 |
| 2026-11-22 | 10,000 | 2,000 |
| 2026-11-23 | 10,047 | 2,000 |
| 2026-11-24 | 10,119 | 2,000 |
| 2026-11-25 | 7,627 | 2,000 |
| 2026-11-26 | 3,351 | 2,000 |
| 2026-11-27 | 3,877 | 2,000 |
| 2026-11-28 | 3,556 | 2,000 |
| 2026-11-29 | 8,152 | 2,000 |
| 2026-11-30 | 7,167 | 2,000 |
| 2026-12-01 | 8,109 | 2,000 |
| 2026-12-02 | 4,671 | 2,000 |
| 2026-12-03 | 7,769 | 2,000 |

> Hinweis: Der Rueckstau von 3,128,776 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-04 | 29,406 |
| 2026-11-05 | 25,095 |
| 2026-11-06 | 36,129 |
| 2026-11-07 | 24,304 |
| 2026-11-08 | 25,980 |
| 2026-11-09 | 25,387 |
| 2026-11-10 | 32,542 |
| 2026-11-11 | 22,214 |
| 2026-11-12 | 20,402 |
| 2026-11-13 | 19,543 |
| 2026-11-14 | 22,837 |
| 2026-11-15 | 17,379 |
| 2026-11-16 | 17,856 |
| 2026-11-17 | 15,158 |
| 2026-11-18 | 19,407 |
| 2026-11-19 | 173,296 |
| 2026-11-20 | 26,014 |
| 2026-11-21 | 61,163 |
| 2026-11-22 | 30,273 |
| 2026-11-23 | 25,529 |
| 2026-11-24 | 26,360 |
| 2026-11-25 | 27,396 |
| 2026-11-26 | 28,557 |
| 2026-11-27 | 27,747 |
| 2026-11-28 | 109,043 |
| 2026-11-29 | 28,088 |
| 2026-11-30 | 25,440 |
| 2026-12-01 | 26,460 |
| 2026-12-02 | 26,099 |
| 2026-12-03 | 25,915 |
| 2026-12-04 | 27,838 |
| 2026-12-05 | 25,871 |
| 2026-12-06 | 30,043 |
| 2026-12-07 | 23,670 |
| 2026-12-08 | 39,281 |
| 2026-12-09 | 54,847 |
| 2026-12-10 | 25,022 |
| 2026-12-11 | 27,693 |
| 2026-12-12 | 24,314 |
| 2026-12-13 | 23,781 |
| 2026-12-14 | 23,399 |
| 2026-12-15 | 26,171 |
| 2026-12-16 | 16,580 |
| 2026-12-17 | 24,951 |
| 2026-12-18 | 22,445 |
| 2026-12-19 | 25,537 |
| 2026-12-20 | 14,275 |
| 2026-12-21 | 27,275 |
| 2026-12-22 | 24,046 |
| 2026-12-23 | 21,078 |
| 2026-12-24 | 20,372 |
| 2026-12-25 | 21,583 |
| 2026-12-26 | 17,792 |
| 2026-12-27 | 24,620 |
| 2026-12-28 | 21,720 |
| 2026-12-29 | 22,544 |
| 2026-12-30 | 26,496 |
| 2026-12-31 | 20,138 |
| 2027-01-01 | 18,500 |
| 2027-01-02 | 26,100 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
