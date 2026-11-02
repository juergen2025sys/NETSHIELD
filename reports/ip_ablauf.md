# Seen-DB Expiry Forecast

Lauf: 2026-11-02 03:18 CET (Europe/Berlin)
Gesamt: 11,156,872 IPs in seen_db.json (7,972,267 aktiv/180-Tage-Pfad, 3,184,605 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 195,892 |
| 8-14 Tage | 152,794 |
| 15-30 Tage | 676,094 |
| 31-60 Tage | 747,935 |
| 61-90 Tage | 879,375 |
| 91-180 Tage | 5,320,177 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,886,733 |
| 0-3 Tage | 45,612 |
| 4-7 Tage | 42,971 |
| 8-14 Tage | 89,412 |
| 15-30 Tage | 119,877 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-02 | 11,850 |
| 2026-11-03 | 16,548 |
| 2026-11-04 | 10,017 |
| 2026-11-05 | 7,197 |
| 2026-11-06 | 12,020 |
| 2026-11-07 | 13,304 |
| 2026-11-08 | 6,226 |
| 2026-11-09 | 11,421 |
| 2026-11-10 | 23,600 |
| 2026-11-11 | 9,850 |
| 2026-11-12 | 7,992 |
| 2026-11-13 | 3,307 |
| 2026-11-14 | 11,556 |
| 2026-11-15 | 14,275 |
| 2026-11-16 | 18,832 |
| 2026-11-17 | 9,301 |
| 2026-11-18 | 3,479 |
| 2026-11-19 | 8,790 |
| 2026-11-20 | 10,870 |
| 2026-11-21 | 9,974 |
| 2026-11-22 | 10,007 |
| 2026-11-23 | 10,051 |
| 2026-11-24 | 10,131 |
| 2026-11-25 | 7,632 |
| 2026-11-26 | 3,357 |
| 2026-11-27 | 3,881 |
| 2026-11-28 | 3,563 |
| 2026-11-29 | 8,163 |
| 2026-11-30 | 7,205 |
| 2026-12-01 | 8,119 |
| 2026-12-02 | 4,720 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,886,733** IPs. Brutto faellig in den naechsten 30 Tagen: **297,238**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,121,971**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-02 | 11,850 | 2,000 |
| 2026-11-03 | 16,548 | 2,000 |
| 2026-11-04 | 10,017 | 2,000 |
| 2026-11-05 | 7,197 | 2,000 |
| 2026-11-06 | 12,020 | 2,000 |
| 2026-11-07 | 13,304 | 2,000 |
| 2026-11-08 | 6,226 | 2,000 |
| 2026-11-09 | 11,421 | 2,000 |
| 2026-11-10 | 23,600 | 2,000 |
| 2026-11-11 | 9,850 | 2,000 |
| 2026-11-12 | 7,992 | 2,000 |
| 2026-11-13 | 3,307 | 2,000 |
| 2026-11-14 | 11,556 | 2,000 |
| 2026-11-15 | 14,275 | 2,000 |
| 2026-11-16 | 18,832 | 2,000 |
| 2026-11-17 | 9,301 | 2,000 |
| 2026-11-18 | 3,479 | 2,000 |
| 2026-11-19 | 8,790 | 2,000 |
| 2026-11-20 | 10,870 | 2,000 |
| 2026-11-21 | 9,974 | 2,000 |
| 2026-11-22 | 10,007 | 2,000 |
| 2026-11-23 | 10,051 | 2,000 |
| 2026-11-24 | 10,131 | 2,000 |
| 2026-11-25 | 7,632 | 2,000 |
| 2026-11-26 | 3,357 | 2,000 |
| 2026-11-27 | 3,881 | 2,000 |
| 2026-11-28 | 3,563 | 2,000 |
| 2026-11-29 | 8,163 | 2,000 |
| 2026-11-30 | 7,205 | 2,000 |
| 2026-12-01 | 8,119 | 2,000 |
| 2026-12-02 | 4,720 | 2,000 |

> Hinweis: Der Rueckstau von 3,121,971 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-03 | 29,561 |
| 2026-11-04 | 29,413 |
| 2026-11-05 | 25,103 |
| 2026-11-06 | 36,133 |
| 2026-11-07 | 24,308 |
| 2026-11-08 | 25,982 |
| 2026-11-09 | 25,392 |
| 2026-11-10 | 32,544 |
| 2026-11-11 | 22,217 |
| 2026-11-12 | 20,404 |
| 2026-11-13 | 19,543 |
| 2026-11-14 | 22,841 |
| 2026-11-15 | 17,383 |
| 2026-11-16 | 17,862 |
| 2026-11-17 | 15,160 |
| 2026-11-18 | 19,409 |
| 2026-11-19 | 173,304 |
| 2026-11-20 | 26,021 |
| 2026-11-21 | 61,169 |
| 2026-11-22 | 30,278 |
| 2026-11-23 | 25,539 |
| 2026-11-24 | 26,362 |
| 2026-11-25 | 27,398 |
| 2026-11-26 | 28,561 |
| 2026-11-27 | 27,749 |
| 2026-11-28 | 109,048 |
| 2026-11-29 | 28,090 |
| 2026-11-30 | 25,441 |
| 2026-12-01 | 26,461 |
| 2026-12-02 | 26,104 |
| 2026-12-03 | 25,920 |
| 2026-12-04 | 27,841 |
| 2026-12-05 | 25,874 |
| 2026-12-06 | 30,046 |
| 2026-12-07 | 23,672 |
| 2026-12-08 | 39,286 |
| 2026-12-09 | 54,869 |
| 2026-12-10 | 25,024 |
| 2026-12-11 | 27,700 |
| 2026-12-12 | 24,315 |
| 2026-12-13 | 23,784 |
| 2026-12-14 | 23,403 |
| 2026-12-15 | 26,175 |
| 2026-12-16 | 16,581 |
| 2026-12-17 | 24,957 |
| 2026-12-18 | 22,449 |
| 2026-12-19 | 25,542 |
| 2026-12-20 | 14,280 |
| 2026-12-21 | 27,283 |
| 2026-12-22 | 24,056 |
| 2026-12-23 | 21,085 |
| 2026-12-24 | 20,376 |
| 2026-12-25 | 21,587 |
| 2026-12-26 | 17,794 |
| 2026-12-27 | 24,625 |
| 2026-12-28 | 21,723 |
| 2026-12-29 | 22,547 |
| 2026-12-30 | 26,499 |
| 2026-12-31 | 20,140 |
| 2027-01-01 | 18,502 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
