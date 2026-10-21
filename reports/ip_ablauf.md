# Seen-DB Expiry Forecast

Lauf: 2026-10-21 17:02 CEST (Europe/Berlin)
Gesamt: 11,061,349 IPs in seen_db.json (7,951,162 aktiv/180-Tage-Pfad, 3,110,187 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 199,712 |
| 8-14 Tage | 274,500 |
| 15-30 Tage | 524,216 |
| 31-60 Tage | 925,167 |
| 61-90 Tage | 700,843 |
| 91-180 Tage | 5,326,724 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,715,410 |
| 0-3 Tage | 47,114 |
| 4-7 Tage | 66,765 |
| 8-14 Tage | 100,538 |
| 15-30 Tage | 180,360 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-21 | 9,466 |
| 2026-10-22 | 10,327 |
| 2026-10-23 | 12,327 |
| 2026-10-24 | 14,994 |
| 2026-10-25 | 11,047 |
| 2026-10-26 | 9,401 |
| 2026-10-27 | 35,074 |
| 2026-10-28 | 11,243 |
| 2026-10-29 | 9,799 |
| 2026-10-30 | 20,044 |
| 2026-10-31 | 16,896 |
| 2026-11-01 | 15,307 |
| 2026-11-02 | 11,872 |
| 2026-11-03 | 16,581 |
| 2026-11-04 | 10,039 |
| 2026-11-05 | 7,216 |
| 2026-11-06 | 12,043 |
| 2026-11-07 | 13,334 |
| 2026-11-08 | 6,253 |
| 2026-11-09 | 11,462 |
| 2026-11-10 | 23,807 |
| 2026-11-11 | 9,879 |
| 2026-11-12 | 8,038 |
| 2026-11-13 | 3,329 |
| 2026-11-14 | 11,602 |
| 2026-11-15 | 14,336 |
| 2026-11-16 | 18,934 |
| 2026-11-17 | 9,342 |
| 2026-11-18 | 3,514 |
| 2026-11-19 | 8,878 |
| 2026-11-20 | 11,002 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,715,410** IPs. Brutto faellig in den naechsten 30 Tagen: **387,386**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,040,796**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-21 | 9,466 | 2,000 |
| 2026-10-22 | 10,327 | 2,000 |
| 2026-10-23 | 12,327 | 2,000 |
| 2026-10-24 | 14,994 | 2,000 |
| 2026-10-25 | 11,047 | 2,000 |
| 2026-10-26 | 9,401 | 2,000 |
| 2026-10-27 | 35,074 | 2,000 |
| 2026-10-28 | 11,243 | 2,000 |
| 2026-10-29 | 9,799 | 2,000 |
| 2026-10-30 | 20,044 | 2,000 |
| 2026-10-31 | 16,896 | 2,000 |
| 2026-11-01 | 15,307 | 2,000 |
| 2026-11-02 | 11,872 | 2,000 |
| 2026-11-03 | 16,581 | 2,000 |
| 2026-11-04 | 10,039 | 2,000 |
| 2026-11-05 | 7,216 | 2,000 |
| 2026-11-06 | 12,043 | 2,000 |
| 2026-11-07 | 13,334 | 2,000 |
| 2026-11-08 | 6,253 | 2,000 |
| 2026-11-09 | 11,462 | 2,000 |
| 2026-11-10 | 23,807 | 2,000 |
| 2026-11-11 | 9,879 | 2,000 |
| 2026-11-12 | 8,038 | 2,000 |
| 2026-11-13 | 3,329 | 2,000 |
| 2026-11-14 | 11,602 | 2,000 |
| 2026-11-15 | 14,336 | 2,000 |
| 2026-11-16 | 18,934 | 2,000 |
| 2026-11-17 | 9,342 | 2,000 |
| 2026-11-18 | 3,514 | 2,000 |
| 2026-11-19 | 8,878 | 2,000 |
| 2026-11-20 | 11,002 | 2,000 |

> Hinweis: Der Rueckstau von 3,040,796 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-22 | 30,438 |
| 2026-10-23 | 50,180 |
| 2026-10-24 | 41,548 |
| 2026-10-25 | 21,465 |
| 2026-10-26 | 20,174 |
| 2026-10-27 | 20,393 |
| 2026-10-28 | 15,514 |
| 2026-10-29 | 9,500 |
| 2026-10-30 | 61,556 |
| 2026-10-31 | 88,022 |
| 2026-11-01 | 27,710 |
| 2026-11-02 | 28,659 |
| 2026-11-03 | 29,597 |
| 2026-11-04 | 29,456 |
| 2026-11-05 | 25,143 |
| 2026-11-06 | 36,189 |
| 2026-11-07 | 24,342 |
| 2026-11-08 | 26,004 |
| 2026-11-09 | 25,431 |
| 2026-11-10 | 32,590 |
| 2026-11-11 | 22,258 |
| 2026-11-12 | 20,433 |
| 2026-11-13 | 19,579 |
| 2026-11-14 | 22,875 |
| 2026-11-15 | 17,397 |
| 2026-11-16 | 17,889 |
| 2026-11-17 | 15,182 |
| 2026-11-18 | 19,438 |
| 2026-11-19 | 173,403 |
| 2026-11-20 | 26,063 |
| 2026-11-21 | 61,225 |
| 2026-11-22 | 30,327 |
| 2026-11-23 | 25,584 |
| 2026-11-24 | 26,395 |
| 2026-11-25 | 27,440 |
| 2026-11-26 | 28,590 |
| 2026-11-27 | 27,777 |
| 2026-11-28 | 109,108 |
| 2026-11-29 | 28,118 |
| 2026-11-30 | 25,472 |
| 2026-12-01 | 26,483 |
| 2026-12-02 | 26,134 |
| 2026-12-03 | 25,955 |
| 2026-12-04 | 27,865 |
| 2026-12-05 | 25,909 |
| 2026-12-06 | 30,081 |
| 2026-12-07 | 23,695 |
| 2026-12-08 | 39,323 |
| 2026-12-09 | 55,023 |
| 2026-12-10 | 25,053 |
| 2026-12-11 | 27,732 |
| 2026-12-12 | 24,357 |
| 2026-12-13 | 23,826 |
| 2026-12-14 | 23,440 |
| 2026-12-15 | 26,221 |
| 2026-12-16 | 16,644 |
| 2026-12-17 | 24,991 |
| 2026-12-18 | 22,495 |
| 2026-12-19 | 25,591 |
| 2026-12-20 | 14,313 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
