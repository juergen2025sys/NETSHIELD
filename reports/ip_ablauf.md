# Seen-DB Expiry Forecast

Lauf: 2026-11-02 17:29 CET (Europe/Berlin)
Gesamt: 11,180,358 IPs in seen_db.json (7,989,668 aktiv/180-Tage-Pfad, 3,190,690 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 195,885 |
| 8-14 Tage | 152,787 |
| 15-30 Tage | 676,076 |
| 31-60 Tage | 747,892 |
| 61-90 Tage | 879,289 |
| 91-180 Tage | 5,337,739 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,887,342 |
| 0-3 Tage | 45,609 |
| 4-7 Tage | 42,969 |
| 8-14 Tage | 89,402 |
| 15-30 Tage | 125,368 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-11-02 | 11,849 |
| 2026-11-03 | 16,547 |
| 2026-11-04 | 10,017 |
| 2026-11-05 | 7,196 |
| 2026-11-06 | 12,020 |
| 2026-11-07 | 13,303 |
| 2026-11-08 | 6,225 |
| 2026-11-09 | 11,421 |
| 2026-11-10 | 23,600 |
| 2026-11-11 | 9,848 |
| 2026-11-12 | 7,992 |
| 2026-11-13 | 3,307 |
| 2026-11-14 | 11,553 |
| 2026-11-15 | 14,274 |
| 2026-11-16 | 18,828 |
| 2026-11-17 | 9,300 |
| 2026-11-18 | 3,478 |
| 2026-11-19 | 8,788 |
| 2026-11-20 | 10,868 |
| 2026-11-21 | 9,972 |
| 2026-11-22 | 10,003 |
| 2026-11-23 | 10,051 |
| 2026-11-24 | 10,124 |
| 2026-11-25 | 7,630 |
| 2026-11-26 | 3,355 |
| 2026-11-27 | 3,880 |
| 2026-11-28 | 3,560 |
| 2026-11-29 | 8,161 |
| 2026-11-30 | 7,195 |
| 2026-12-01 | 8,113 |
| 2026-12-02 | 4,695 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,887,342** IPs. Brutto faellig in den naechsten 30 Tagen: **297,153**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,122,495**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-11-02 | 11,849 | 2,000 |
| 2026-11-03 | 16,547 | 2,000 |
| 2026-11-04 | 10,017 | 2,000 |
| 2026-11-05 | 7,196 | 2,000 |
| 2026-11-06 | 12,020 | 2,000 |
| 2026-11-07 | 13,303 | 2,000 |
| 2026-11-08 | 6,225 | 2,000 |
| 2026-11-09 | 11,421 | 2,000 |
| 2026-11-10 | 23,600 | 2,000 |
| 2026-11-11 | 9,848 | 2,000 |
| 2026-11-12 | 7,992 | 2,000 |
| 2026-11-13 | 3,307 | 2,000 |
| 2026-11-14 | 11,553 | 2,000 |
| 2026-11-15 | 14,274 | 2,000 |
| 2026-11-16 | 18,828 | 2,000 |
| 2026-11-17 | 9,300 | 2,000 |
| 2026-11-18 | 3,478 | 2,000 |
| 2026-11-19 | 8,788 | 2,000 |
| 2026-11-20 | 10,868 | 2,000 |
| 2026-11-21 | 9,972 | 2,000 |
| 2026-11-22 | 10,003 | 2,000 |
| 2026-11-23 | 10,051 | 2,000 |
| 2026-11-24 | 10,124 | 2,000 |
| 2026-11-25 | 7,630 | 2,000 |
| 2026-11-26 | 3,355 | 2,000 |
| 2026-11-27 | 3,880 | 2,000 |
| 2026-11-28 | 3,560 | 2,000 |
| 2026-11-29 | 8,161 | 2,000 |
| 2026-11-30 | 7,195 | 2,000 |
| 2026-12-01 | 8,113 | 2,000 |
| 2026-12-02 | 4,695 | 2,000 |

> Hinweis: Der Rueckstau von 3,122,495 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-03 | 29,561 |
| 2026-11-04 | 29,413 |
| 2026-11-05 | 25,101 |
| 2026-11-06 | 36,132 |
| 2026-11-07 | 24,306 |
| 2026-11-08 | 25,981 |
| 2026-11-09 | 25,391 |
| 2026-11-10 | 32,543 |
| 2026-11-11 | 22,216 |
| 2026-11-12 | 20,404 |
| 2026-11-13 | 19,543 |
| 2026-11-14 | 22,840 |
| 2026-11-15 | 17,381 |
| 2026-11-16 | 17,860 |
| 2026-11-17 | 15,158 |
| 2026-11-18 | 19,408 |
| 2026-11-19 | 173,304 |
| 2026-11-20 | 26,019 |
| 2026-11-21 | 61,168 |
| 2026-11-22 | 30,277 |
| 2026-11-23 | 25,536 |
| 2026-11-24 | 26,362 |
| 2026-11-25 | 27,397 |
| 2026-11-26 | 28,560 |
| 2026-11-27 | 27,747 |
| 2026-11-28 | 109,047 |
| 2026-11-29 | 28,089 |
| 2026-11-30 | 25,441 |
| 2026-12-01 | 26,461 |
| 2026-12-02 | 26,102 |
| 2026-12-03 | 25,920 |
| 2026-12-04 | 27,839 |
| 2026-12-05 | 25,873 |
| 2026-12-06 | 30,045 |
| 2026-12-07 | 23,671 |
| 2026-12-08 | 39,285 |
| 2026-12-09 | 54,859 |
| 2026-12-10 | 25,024 |
| 2026-12-11 | 27,698 |
| 2026-12-12 | 24,314 |
| 2026-12-13 | 23,784 |
| 2026-12-14 | 23,402 |
| 2026-12-15 | 26,173 |
| 2026-12-16 | 16,581 |
| 2026-12-17 | 24,955 |
| 2026-12-18 | 22,449 |
| 2026-12-19 | 25,541 |
| 2026-12-20 | 14,276 |
| 2026-12-21 | 27,279 |
| 2026-12-22 | 24,053 |
| 2026-12-23 | 21,084 |
| 2026-12-24 | 20,375 |
| 2026-12-25 | 21,587 |
| 2026-12-26 | 17,794 |
| 2026-12-27 | 24,624 |
| 2026-12-28 | 21,721 |
| 2026-12-29 | 22,545 |
| 2026-12-30 | 26,499 |
| 2026-12-31 | 20,140 |
| 2027-01-01 | 18,502 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
