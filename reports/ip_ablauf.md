# Seen-DB Expiry Forecast

Lauf: 2026-10-15 07:04 CEST (Europe/Berlin)
Gesamt: 10,793,337 IPs in seen_db.json (7,745,914 aktiv/180-Tage-Pfad, 3,047,423 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 163,976 |
| 8-14 Tage | 179,103 |
| 15-30 Tage | 520,243 |
| 31-60 Tage | 1,064,996 |
| 61-90 Tage | 692,132 |
| 91-180 Tage | 5,125,464 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,662,207 |
| 0-3 Tage | 42,174 |
| 4-7 Tage | 34,441 |
| 8-14 Tage | 103,983 |
| 15-30 Tage | 204,618 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-15 | 8,248 |
| 2026-10-16 | 15,406 |
| 2026-10-17 | 9,908 |
| 2026-10-18 | 8,612 |
| 2026-10-19 | 5,113 |
| 2026-10-20 | 9,515 |
| 2026-10-21 | 9,475 |
| 2026-10-22 | 10,338 |
| 2026-10-23 | 12,338 |
| 2026-10-24 | 15,007 |
| 2026-10-25 | 11,058 |
| 2026-10-26 | 9,409 |
| 2026-10-27 | 35,113 |
| 2026-10-28 | 11,250 |
| 2026-10-29 | 9,808 |
| 2026-10-30 | 20,055 |
| 2026-10-31 | 16,916 |
| 2026-11-01 | 15,319 |
| 2026-11-02 | 11,881 |
| 2026-11-03 | 16,592 |
| 2026-11-04 | 10,050 |
| 2026-11-05 | 7,233 |
| 2026-11-06 | 12,057 |
| 2026-11-07 | 13,358 |
| 2026-11-08 | 6,267 |
| 2026-11-09 | 11,487 |
| 2026-11-10 | 23,859 |
| 2026-11-11 | 9,915 |
| 2026-11-12 | 8,077 |
| 2026-11-13 | 3,367 |
| 2026-11-14 | 11,720 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,662,207** IPs. Brutto faellig in den naechsten 30 Tagen: **378,751**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **2,978,958**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-15 | 8,248 | 2,000 |
| 2026-10-16 | 15,406 | 2,000 |
| 2026-10-17 | 9,908 | 2,000 |
| 2026-10-18 | 8,612 | 2,000 |
| 2026-10-19 | 5,113 | 2,000 |
| 2026-10-20 | 9,515 | 2,000 |
| 2026-10-21 | 9,475 | 2,000 |
| 2026-10-22 | 10,338 | 2,000 |
| 2026-10-23 | 12,338 | 2,000 |
| 2026-10-24 | 15,007 | 2,000 |
| 2026-10-25 | 11,058 | 2,000 |
| 2026-10-26 | 9,409 | 2,000 |
| 2026-10-27 | 35,113 | 2,000 |
| 2026-10-28 | 11,250 | 2,000 |
| 2026-10-29 | 9,808 | 2,000 |
| 2026-10-30 | 20,055 | 2,000 |
| 2026-10-31 | 16,916 | 2,000 |
| 2026-11-01 | 15,319 | 2,000 |
| 2026-11-02 | 11,881 | 2,000 |
| 2026-11-03 | 16,592 | 2,000 |
| 2026-11-04 | 10,050 | 2,000 |
| 2026-11-05 | 7,233 | 2,000 |
| 2026-11-06 | 12,057 | 2,000 |
| 2026-11-07 | 13,358 | 2,000 |
| 2026-11-08 | 6,267 | 2,000 |
| 2026-11-09 | 11,487 | 2,000 |
| 2026-11-10 | 23,859 | 2,000 |
| 2026-11-11 | 9,915 | 2,000 |
| 2026-11-12 | 8,077 | 2,000 |
| 2026-11-13 | 3,367 | 2,000 |
| 2026-11-14 | 11,720 | 2,000 |

> Hinweis: Der Rueckstau von 2,978,958 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-16 | 51,129 |
| 2026-10-17 | 24,155 |
| 2026-10-18 | 14,161 |
| 2026-10-19 | 21,980 |
| 2026-10-20 | 11,056 |
| 2026-10-21 | 11,020 |
| 2026-10-22 | 30,475 |
| 2026-10-23 | 50,218 |
| 2026-10-24 | 41,574 |
| 2026-10-25 | 21,483 |
| 2026-10-26 | 20,193 |
| 2026-10-27 | 20,461 |
| 2026-10-28 | 15,612 |
| 2026-10-29 | 9,562 |
| 2026-10-30 | 61,597 |
| 2026-10-31 | 88,048 |
| 2026-11-01 | 27,738 |
| 2026-11-02 | 28,684 |
| 2026-11-03 | 29,627 |
| 2026-11-04 | 29,483 |
| 2026-11-05 | 25,162 |
| 2026-11-06 | 36,219 |
| 2026-11-07 | 24,364 |
| 2026-11-08 | 26,023 |
| 2026-11-09 | 25,454 |
| 2026-11-10 | 32,616 |
| 2026-11-11 | 22,285 |
| 2026-11-12 | 20,449 |
| 2026-11-13 | 19,598 |
| 2026-11-14 | 22,896 |
| 2026-11-15 | 17,413 |
| 2026-11-16 | 17,913 |
| 2026-11-17 | 15,196 |
| 2026-11-18 | 19,450 |
| 2026-11-19 | 173,465 |
| 2026-11-20 | 26,085 |
| 2026-11-21 | 61,254 |
| 2026-11-22 | 30,346 |
| 2026-11-23 | 25,605 |
| 2026-11-24 | 26,415 |
| 2026-11-25 | 27,463 |
| 2026-11-26 | 28,604 |
| 2026-11-27 | 27,792 |
| 2026-11-28 | 109,140 |
| 2026-11-29 | 28,128 |
| 2026-11-30 | 25,490 |
| 2026-12-01 | 26,505 |
| 2026-12-02 | 26,159 |
| 2026-12-03 | 25,972 |
| 2026-12-04 | 27,879 |
| 2026-12-05 | 25,925 |
| 2026-12-06 | 30,103 |
| 2026-12-07 | 23,718 |
| 2026-12-08 | 39,345 |
| 2026-12-09 | 55,116 |
| 2026-12-10 | 25,076 |
| 2026-12-11 | 27,748 |
| 2026-12-12 | 24,379 |
| 2026-12-13 | 23,846 |
| 2026-12-14 | 23,466 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
