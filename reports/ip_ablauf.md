# Seen-DB Expiry Forecast

Lauf: 2026-10-02 11:38 CEST (Europe/Berlin)
Gesamt: 12,067,620 IPs in seen_db.json (9,128,308 aktiv/180-Tage-Pfad, 2,939,312 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 350,986 |
| 8-14 Tage | 1,843,790 |
| 15-30 Tage | 471,222 |
| 31-60 Tage | 1,032,055 |
| 61-90 Tage | 760,845 |
| 91-180 Tage | 4,669,410 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 1,311,689 |
| 0-3 Tage | 1,316,043 |
| 4-7 Tage | 33,234 |
| 8-14 Tage | 57,112 |
| 15-30 Tage | 221,234 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-02 | 1,303,400 |
| 2026-10-03 | 2,946 |
| 2026-10-04 | 6,836 |
| 2026-10-05 | 2,861 |
| 2026-10-06 | 7,942 |
| 2026-10-07 | 7,901 |
| 2026-10-08 | 7,256 |
| 2026-10-09 | 10,135 |
| 2026-10-10 | 7,536 |
| 2026-10-11 | 6,243 |
| 2026-10-12 | 3,866 |
| 2026-10-13 | 8,265 |
| 2026-10-14 | 7,424 |
| 2026-10-15 | 8,305 |
| 2026-10-16 | 15,473 |
| 2026-10-17 | 9,942 |
| 2026-10-18 | 8,660 |
| 2026-10-19 | 5,153 |
| 2026-10-20 | 9,605 |
| 2026-10-21 | 9,557 |
| 2026-10-22 | 10,406 |
| 2026-10-23 | 12,434 |
| 2026-10-24 | 15,096 |
| 2026-10-25 | 11,127 |
| 2026-10-26 | 9,486 |
| 2026-10-27 | 35,337 |
| 2026-10-28 | 11,327 |
| 2026-10-29 | 9,891 |
| 2026-10-30 | 20,229 |
| 2026-10-31 | 17,202 |
| 2026-11-01 | 15,891 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **1,311,689** IPs. Brutto faellig in den naechsten 30 Tagen: **1,617,732**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **2,867,421**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-02 | 1,303,400 | 2,000 |
| 2026-10-03 | 2,946 | 2,000 |
| 2026-10-04 | 6,836 | 2,000 |
| 2026-10-05 | 2,861 | 2,000 |
| 2026-10-06 | 7,942 | 2,000 |
| 2026-10-07 | 7,901 | 2,000 |
| 2026-10-08 | 7,256 | 2,000 |
| 2026-10-09 | 10,135 | 2,000 |
| 2026-10-10 | 7,536 | 2,000 |
| 2026-10-11 | 6,243 | 2,000 |
| 2026-10-12 | 3,866 | 2,000 |
| 2026-10-13 | 8,265 | 2,000 |
| 2026-10-14 | 7,424 | 2,000 |
| 2026-10-15 | 8,305 | 2,000 |
| 2026-10-16 | 15,473 | 2,000 |
| 2026-10-17 | 9,942 | 2,000 |
| 2026-10-18 | 8,660 | 2,000 |
| 2026-10-19 | 5,153 | 2,000 |
| 2026-10-20 | 9,605 | 2,000 |
| 2026-10-21 | 9,557 | 2,000 |
| 2026-10-22 | 10,406 | 2,000 |
| 2026-10-23 | 12,434 | 2,000 |
| 2026-10-24 | 15,096 | 2,000 |
| 2026-10-25 | 11,127 | 2,000 |
| 2026-10-26 | 9,486 | 2,000 |
| 2026-10-27 | 35,337 | 2,000 |
| 2026-10-28 | 11,327 | 2,000 |
| 2026-10-29 | 9,891 | 2,000 |
| 2026-10-30 | 20,229 | 2,000 |
| 2026-10-31 | 17,202 | 2,000 |
| 2026-11-01 | 15,891 | 2,000 |

> Hinweis: Der Rueckstau von 2,867,421 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-03 | 7,294 |
| 2026-10-04 | 12,545 |
| 2026-10-05 | 17,473 |
| 2026-10-06 | 16,043 |
| 2026-10-07 | 14,980 |
| 2026-10-08 | 61,109 |
| 2026-10-09 | 221,542 |
| 2026-10-10 | 53,299 |
| 2026-10-11 | 16,015 |
| 2026-10-12 | 66,530 |
| 2026-10-13 | 1,582,503 |
| 2026-10-14 | 32,912 |
| 2026-10-15 | 41,302 |
| 2026-10-16 | 51,229 |
| 2026-10-17 | 24,225 |
| 2026-10-18 | 14,232 |
| 2026-10-19 | 22,202 |
| 2026-10-20 | 11,115 |
| 2026-10-21 | 11,078 |
| 2026-10-22 | 30,683 |
| 2026-10-23 | 50,346 |
| 2026-10-24 | 41,662 |
| 2026-10-25 | 21,569 |
| 2026-10-26 | 20,286 |
| 2026-10-27 | 20,617 |
| 2026-10-28 | 15,750 |
| 2026-10-29 | 9,645 |
| 2026-10-30 | 61,825 |
| 2026-10-31 | 88,165 |
| 2026-11-01 | 27,822 |
| 2026-11-02 | 28,781 |
| 2026-11-03 | 29,752 |
| 2026-11-04 | 29,591 |
| 2026-11-05 | 25,248 |
| 2026-11-06 | 36,349 |
| 2026-11-07 | 24,452 |
| 2026-11-08 | 26,108 |
| 2026-11-09 | 25,549 |
| 2026-11-10 | 32,712 |
| 2026-11-11 | 22,359 |
| 2026-11-12 | 20,502 |
| 2026-11-13 | 19,651 |
| 2026-11-14 | 22,968 |
| 2026-11-15 | 17,456 |
| 2026-11-16 | 17,970 |
| 2026-11-17 | 15,258 |
| 2026-11-18 | 19,506 |
| 2026-11-19 | 173,853 |
| 2026-11-20 | 26,175 |
| 2026-11-21 | 61,425 |
| 2026-11-22 | 30,445 |
| 2026-11-23 | 25,701 |
| 2026-11-24 | 26,493 |
| 2026-11-25 | 27,575 |
| 2026-11-26 | 28,685 |
| 2026-11-27 | 27,865 |
| 2026-11-28 | 109,246 |
| 2026-11-29 | 28,211 |
| 2026-11-30 | 25,579 |
| 2026-12-01 | 26,590 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
