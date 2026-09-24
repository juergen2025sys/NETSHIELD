# Seen-DB Expiry Forecast

Lauf: 2026-09-24 22:45 CEST (Europe/Berlin)
Gesamt: 11,647,495 IPs in seen_db.json (8,830,124 aktiv/180-Tage-Pfad, 2,817,371 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 101,006 |
| 8-14 Tage | 137,636 |
| 15-30 Tage | 2,274,648 |
| 31-60 Tage | 999,715 |
| 61-90 Tage | 886,743 |
| 91-180 Tage | 4,430,376 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 599,935 |
| 0-3 Tage | 646,769 |
| 4-7 Tage | 68,038 |
| 8-14 Tage | 1,342,802 |
| 15-30 Tage | 159,827 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-24 | 11,368 |
| 2026-09-25 | 5,441 |
| 2026-09-26 | 623,699 |
| 2026-09-27 | 6,261 |
| 2026-09-28 | 771 |
| 2026-09-30 | 59,635 |
| 2026-10-01 | 7,632 |
| 2026-10-02 | 1,306,751 |
| 2026-10-03 | 2,965 |
| 2026-10-04 | 6,912 |
| 2026-10-05 | 2,900 |
| 2026-10-06 | 8,041 |
| 2026-10-07 | 7,949 |
| 2026-10-08 | 7,284 |
| 2026-10-09 | 10,176 |
| 2026-10-10 | 7,577 |
| 2026-10-11 | 6,272 |
| 2026-10-12 | 3,880 |
| 2026-10-13 | 8,321 |
| 2026-10-14 | 7,466 |
| 2026-10-15 | 8,345 |
| 2026-10-16 | 15,528 |
| 2026-10-17 | 9,975 |
| 2026-10-18 | 8,715 |
| 2026-10-19 | 5,187 |
| 2026-10-20 | 9,689 |
| 2026-10-21 | 9,631 |
| 2026-10-22 | 10,527 |
| 2026-10-23 | 12,595 |
| 2026-10-24 | 15,351 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **599,935** IPs. Brutto faellig in den naechsten 30 Tagen: **2,206,844**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,746,779**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-24 | 11,368 | 2,000 |
| 2026-09-25 | 5,441 | 2,000 |
| 2026-09-26 | 623,699 | 2,000 |
| 2026-09-27 | 6,261 | 2,000 |
| 2026-09-28 | 771 | 2,000 |
| 2026-09-30 | 59,635 | 2,000 |
| 2026-10-01 | 7,632 | 2,000 |
| 2026-10-02 | 1,306,751 | 2,000 |
| 2026-10-03 | 2,965 | 2,000 |
| 2026-10-04 | 6,912 | 2,000 |
| 2026-10-05 | 2,900 | 2,000 |
| 2026-10-06 | 8,041 | 2,000 |
| 2026-10-07 | 7,949 | 2,000 |
| 2026-10-08 | 7,284 | 2,000 |
| 2026-10-09 | 10,176 | 2,000 |
| 2026-10-10 | 7,577 | 2,000 |
| 2026-10-11 | 6,272 | 2,000 |
| 2026-10-12 | 3,880 | 2,000 |
| 2026-10-13 | 8,321 | 2,000 |
| 2026-10-14 | 7,466 | 2,000 |
| 2026-10-15 | 8,345 | 2,000 |
| 2026-10-16 | 15,528 | 2,000 |
| 2026-10-17 | 9,975 | 2,000 |
| 2026-10-18 | 8,715 | 2,000 |
| 2026-10-19 | 5,187 | 2,000 |
| 2026-10-20 | 9,689 | 2,000 |
| 2026-10-21 | 9,631 | 2,000 |
| 2026-10-22 | 10,527 | 2,000 |
| 2026-10-23 | 12,595 | 2,000 |
| 2026-10-24 | 15,351 | 2,000 |

> Hinweis: Der Rueckstau von 2,746,779 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-25 | 20,902 |
| 2026-09-26 | 17,419 |
| 2026-09-27 | 15,010 |
| 2026-09-28 | 11,593 |
| 2026-09-29 | 9,342 |
| 2026-09-30 | 10,160 |
| 2026-10-01 | 16,580 |
| 2026-10-02 | 7,712 |
| 2026-10-03 | 7,322 |
| 2026-10-04 | 12,602 |
| 2026-10-05 | 17,520 |
| 2026-10-06 | 16,104 |
| 2026-10-07 | 15,032 |
| 2026-10-08 | 61,344 |
| 2026-10-09 | 222,516 |
| 2026-10-10 | 53,359 |
| 2026-10-11 | 16,044 |
| 2026-10-12 | 66,574 |
| 2026-10-13 | 1,584,554 |
| 2026-10-14 | 32,919 |
| 2026-10-15 | 41,337 |
| 2026-10-16 | 51,296 |
| 2026-10-17 | 24,282 |
| 2026-10-18 | 14,272 |
| 2026-10-19 | 22,345 |
| 2026-10-20 | 11,140 |
| 2026-10-21 | 11,115 |
| 2026-10-22 | 30,745 |
| 2026-10-23 | 50,419 |
| 2026-10-24 | 41,731 |
| 2026-10-25 | 21,624 |
| 2026-10-26 | 20,348 |
| 2026-10-27 | 20,703 |
| 2026-10-28 | 15,810 |
| 2026-10-29 | 9,690 |
| 2026-10-30 | 61,969 |
| 2026-10-31 | 88,250 |
| 2026-11-01 | 27,885 |
| 2026-11-02 | 28,846 |
| 2026-11-03 | 29,849 |
| 2026-11-04 | 29,667 |
| 2026-11-05 | 25,310 |
| 2026-11-06 | 36,445 |
| 2026-11-07 | 24,501 |
| 2026-11-08 | 26,165 |
| 2026-11-09 | 25,599 |
| 2026-11-10 | 32,792 |
| 2026-11-11 | 22,423 |
| 2026-11-12 | 20,542 |
| 2026-11-13 | 19,692 |
| 2026-11-14 | 23,013 |
| 2026-11-15 | 17,493 |
| 2026-11-16 | 18,011 |
| 2026-11-17 | 15,277 |
| 2026-11-18 | 19,542 |
| 2026-11-19 | 174,163 |
| 2026-11-20 | 26,245 |
| 2026-11-21 | 61,569 |
| 2026-11-22 | 30,528 |
| 2026-11-23 | 25,764 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
