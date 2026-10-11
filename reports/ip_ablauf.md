# Seen-DB Expiry Forecast

Lauf: 2026-10-11 15:23 CEST (Europe/Berlin)
Gesamt: 12,295,511 IPs in seen_db.json (9,269,930 aktiv/180-Tage-Pfad, 3,025,581 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 1,809,947 |
| 8-14 Tage | 187,929 |
| 15-30 Tage | 501,183 |
| 31-60 Tage | 1,051,201 |
| 61-90 Tage | 696,601 |
| 91-180 Tage | 5,023,069 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,645,101 |
| 0-3 Tage | 25,638 |
| 4-7 Tage | 42,196 |
| 8-14 Tage | 72,889 |
| 15-30 Tage | 239,757 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-11 | 6,206 |
| 2026-10-12 | 3,842 |
| 2026-10-13 | 8,207 |
| 2026-10-14 | 7,383 |
| 2026-10-15 | 8,252 |
| 2026-10-16 | 15,412 |
| 2026-10-17 | 9,913 |
| 2026-10-18 | 8,619 |
| 2026-10-19 | 5,118 |
| 2026-10-20 | 9,523 |
| 2026-10-21 | 9,480 |
| 2026-10-22 | 10,344 |
| 2026-10-23 | 12,346 |
| 2026-10-24 | 15,012 |
| 2026-10-25 | 11,066 |
| 2026-10-26 | 9,416 |
| 2026-10-27 | 35,174 |
| 2026-10-28 | 11,255 |
| 2026-10-29 | 9,817 |
| 2026-10-30 | 20,078 |
| 2026-10-31 | 16,950 |
| 2026-11-01 | 15,332 |
| 2026-11-02 | 11,892 |
| 2026-11-03 | 16,598 |
| 2026-11-04 | 10,060 |
| 2026-11-05 | 7,245 |
| 2026-11-06 | 12,074 |
| 2026-11-07 | 13,388 |
| 2026-11-08 | 6,287 |
| 2026-11-09 | 11,528 |
| 2026-11-10 | 23,914 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,645,101** IPs. Brutto faellig in den naechsten 30 Tagen: **371,731**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **2,954,832**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-11 | 6,206 | 2,000 |
| 2026-10-12 | 3,842 | 2,000 |
| 2026-10-13 | 8,207 | 2,000 |
| 2026-10-14 | 7,383 | 2,000 |
| 2026-10-15 | 8,252 | 2,000 |
| 2026-10-16 | 15,412 | 2,000 |
| 2026-10-17 | 9,913 | 2,000 |
| 2026-10-18 | 8,619 | 2,000 |
| 2026-10-19 | 5,118 | 2,000 |
| 2026-10-20 | 9,523 | 2,000 |
| 2026-10-21 | 9,480 | 2,000 |
| 2026-10-22 | 10,344 | 2,000 |
| 2026-10-23 | 12,346 | 2,000 |
| 2026-10-24 | 15,012 | 2,000 |
| 2026-10-25 | 11,066 | 2,000 |
| 2026-10-26 | 9,416 | 2,000 |
| 2026-10-27 | 35,174 | 2,000 |
| 2026-10-28 | 11,255 | 2,000 |
| 2026-10-29 | 9,817 | 2,000 |
| 2026-10-30 | 20,078 | 2,000 |
| 2026-10-31 | 16,950 | 2,000 |
| 2026-11-01 | 15,332 | 2,000 |
| 2026-11-02 | 11,892 | 2,000 |
| 2026-11-03 | 16,598 | 2,000 |
| 2026-11-04 | 10,060 | 2,000 |
| 2026-11-05 | 7,245 | 2,000 |
| 2026-11-06 | 12,074 | 2,000 |
| 2026-11-07 | 13,388 | 2,000 |
| 2026-11-08 | 6,287 | 2,000 |
| 2026-11-09 | 11,528 | 2,000 |
| 2026-11-10 | 23,914 | 2,000 |

> Hinweis: Der Rueckstau von 2,954,832 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-12 | 66,481 |
| 2026-10-13 | 1,579,826 |
| 2026-10-14 | 32,901 |
| 2026-10-15 | 41,271 |
| 2026-10-16 | 51,137 |
| 2026-10-17 | 24,161 |
| 2026-10-18 | 14,170 |
| 2026-10-19 | 22,026 |
| 2026-10-20 | 11,066 |
| 2026-10-21 | 11,030 |
| 2026-10-22 | 30,492 |
| 2026-10-23 | 50,236 |
| 2026-10-24 | 41,581 |
| 2026-10-25 | 21,498 |
| 2026-10-26 | 20,211 |
| 2026-10-27 | 20,515 |
| 2026-10-28 | 15,671 |
| 2026-10-29 | 9,590 |
| 2026-10-30 | 61,618 |
| 2026-10-31 | 88,061 |
| 2026-11-01 | 27,750 |
| 2026-11-02 | 28,698 |
| 2026-11-03 | 29,647 |
| 2026-11-04 | 29,506 |
| 2026-11-05 | 25,174 |
| 2026-11-06 | 36,239 |
| 2026-11-07 | 24,369 |
| 2026-11-08 | 26,037 |
| 2026-11-09 | 25,467 |
| 2026-11-10 | 32,630 |
| 2026-11-11 | 22,297 |
| 2026-11-12 | 20,457 |
| 2026-11-13 | 19,606 |
| 2026-11-14 | 22,906 |
| 2026-11-15 | 17,419 |
| 2026-11-16 | 17,920 |
| 2026-11-17 | 15,208 |
| 2026-11-18 | 19,463 |
| 2026-11-19 | 173,499 |
| 2026-11-20 | 26,095 |
| 2026-11-21 | 61,275 |
| 2026-11-22 | 30,359 |
| 2026-11-23 | 25,621 |
| 2026-11-24 | 26,424 |
| 2026-11-25 | 27,481 |
| 2026-11-26 | 28,623 |
| 2026-11-27 | 27,800 |
| 2026-11-28 | 109,154 |
| 2026-11-29 | 28,135 |
| 2026-11-30 | 25,502 |
| 2026-12-01 | 26,516 |
| 2026-12-02 | 26,169 |
| 2026-12-03 | 25,990 |
| 2026-12-04 | 27,893 |
| 2026-12-05 | 25,937 |
| 2026-12-06 | 30,115 |
| 2026-12-07 | 23,729 |
| 2026-12-08 | 39,362 |
| 2026-12-09 | 55,162 |
| 2026-12-10 | 25,084 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
