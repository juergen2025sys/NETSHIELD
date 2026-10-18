# Seen-DB Expiry Forecast

Lauf: 2026-10-18 15:55 CEST (Europe/Berlin)
Gesamt: 10,906,031 IPs in seen_db.json (7,822,982 aktiv/180-Tage-Pfad, 3,083,049 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 187,707 |
| 8-14 Tage | 243,017 |
| 15-30 Tage | 393,212 |
| 31-60 Tage | 1,082,052 |
| 61-90 Tage | 695,487 |
| 91-180 Tage | 5,221,507 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,692,696 |
| 0-3 Tage | 32,695 |
| 4-7 Tage | 48,719 |
| 8-14 Tage | 117,812 |
| 15-30 Tage | 191,127 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-18 | 8,612 |
| 2026-10-19 | 5,107 |
| 2026-10-20 | 9,505 |
| 2026-10-21 | 9,471 |
| 2026-10-22 | 10,336 |
| 2026-10-23 | 12,333 |
| 2026-10-24 | 15,000 |
| 2026-10-25 | 11,050 |
| 2026-10-26 | 9,405 |
| 2026-10-27 | 35,089 |
| 2026-10-28 | 11,245 |
| 2026-10-29 | 9,806 |
| 2026-10-30 | 20,048 |
| 2026-10-31 | 16,906 |
| 2026-11-01 | 15,313 |
| 2026-11-02 | 11,878 |
| 2026-11-03 | 16,584 |
| 2026-11-04 | 10,045 |
| 2026-11-05 | 7,228 |
| 2026-11-06 | 12,052 |
| 2026-11-07 | 13,343 |
| 2026-11-08 | 6,256 |
| 2026-11-09 | 11,473 |
| 2026-11-10 | 23,828 |
| 2026-11-11 | 9,892 |
| 2026-11-12 | 8,054 |
| 2026-11-13 | 3,345 |
| 2026-11-14 | 11,641 |
| 2026-11-15 | 14,372 |
| 2026-11-16 | 18,983 |
| 2026-11-17 | 9,409 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,692,696** IPs. Brutto faellig in den naechsten 30 Tagen: **387,609**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,018,305**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-18 | 8,612 | 2,000 |
| 2026-10-19 | 5,107 | 2,000 |
| 2026-10-20 | 9,505 | 2,000 |
| 2026-10-21 | 9,471 | 2,000 |
| 2026-10-22 | 10,336 | 2,000 |
| 2026-10-23 | 12,333 | 2,000 |
| 2026-10-24 | 15,000 | 2,000 |
| 2026-10-25 | 11,050 | 2,000 |
| 2026-10-26 | 9,405 | 2,000 |
| 2026-10-27 | 35,089 | 2,000 |
| 2026-10-28 | 11,245 | 2,000 |
| 2026-10-29 | 9,806 | 2,000 |
| 2026-10-30 | 20,048 | 2,000 |
| 2026-10-31 | 16,906 | 2,000 |
| 2026-11-01 | 15,313 | 2,000 |
| 2026-11-02 | 11,878 | 2,000 |
| 2026-11-03 | 16,584 | 2,000 |
| 2026-11-04 | 10,045 | 2,000 |
| 2026-11-05 | 7,228 | 2,000 |
| 2026-11-06 | 12,052 | 2,000 |
| 2026-11-07 | 13,343 | 2,000 |
| 2026-11-08 | 6,256 | 2,000 |
| 2026-11-09 | 11,473 | 2,000 |
| 2026-11-10 | 23,828 | 2,000 |
| 2026-11-11 | 9,892 | 2,000 |
| 2026-11-12 | 8,054 | 2,000 |
| 2026-11-13 | 3,345 | 2,000 |
| 2026-11-14 | 11,641 | 2,000 |
| 2026-11-15 | 14,372 | 2,000 |
| 2026-11-16 | 18,983 | 2,000 |
| 2026-11-17 | 9,409 | 2,000 |

> Hinweis: Der Rueckstau von 3,018,305 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-19 | 21,955 |
| 2026-10-20 | 11,054 |
| 2026-10-21 | 11,014 |
| 2026-10-22 | 30,454 |
| 2026-10-23 | 50,195 |
| 2026-10-24 | 41,562 |
| 2026-10-25 | 21,473 |
| 2026-10-26 | 20,182 |
| 2026-10-27 | 20,422 |
| 2026-10-28 | 15,556 |
| 2026-10-29 | 9,523 |
| 2026-10-30 | 61,579 |
| 2026-10-31 | 88,034 |
| 2026-11-01 | 27,721 |
| 2026-11-02 | 28,675 |
| 2026-11-03 | 29,618 |
| 2026-11-04 | 29,472 |
| 2026-11-05 | 25,153 |
| 2026-11-06 | 36,208 |
| 2026-11-07 | 24,355 |
| 2026-11-08 | 26,014 |
| 2026-11-09 | 25,439 |
| 2026-11-10 | 32,598 |
| 2026-11-11 | 22,270 |
| 2026-11-12 | 20,440 |
| 2026-11-13 | 19,586 |
| 2026-11-14 | 22,880 |
| 2026-11-15 | 17,406 |
| 2026-11-16 | 17,905 |
| 2026-11-17 | 15,193 |
| 2026-11-18 | 19,448 |
| 2026-11-19 | 173,440 |
| 2026-11-20 | 26,075 |
| 2026-11-21 | 61,240 |
| 2026-11-22 | 30,334 |
| 2026-11-23 | 25,592 |
| 2026-11-24 | 26,399 |
| 2026-11-25 | 27,457 |
| 2026-11-26 | 28,600 |
| 2026-11-27 | 27,785 |
| 2026-11-28 | 109,122 |
| 2026-11-29 | 28,124 |
| 2026-11-30 | 25,481 |
| 2026-12-01 | 26,495 |
| 2026-12-02 | 26,151 |
| 2026-12-03 | 25,967 |
| 2026-12-04 | 27,871 |
| 2026-12-05 | 25,918 |
| 2026-12-06 | 30,090 |
| 2026-12-07 | 23,706 |
| 2026-12-08 | 39,336 |
| 2026-12-09 | 55,067 |
| 2026-12-10 | 25,060 |
| 2026-12-11 | 27,738 |
| 2026-12-12 | 24,365 |
| 2026-12-13 | 23,835 |
| 2026-12-14 | 23,448 |
| 2026-12-15 | 26,235 |
| 2026-12-16 | 16,665 |
| 2026-12-17 | 25,008 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
