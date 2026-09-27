# Seen-DB Expiry Forecast

Lauf: 2026-09-28 01:55 CEST (Europe/Berlin)
Gesamt: 11,802,966 IPs in seen_db.json (8,930,453 aktiv/180-Tage-Pfad, 2,872,513 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 75,224 |
| 8-14 Tage | 401,385 |
| 15-30 Tage | 2,044,362 |
| 31-60 Tage | 1,019,142 |
| 61-90 Tage | 863,404 |
| 91-180 Tage | 4,526,936 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 1,239,360 |
| 0-3 Tage | 66,587 |
| 4-7 Tage | 1,323,772 |
| 8-14 Tage | 50,061 |
| 15-30 Tage | 192,733 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-27 | 6,250 |
| 2026-09-28 | 770 |
| 2026-09-30 | 59,567 |
| 2026-10-01 | 7,618 |
| 2026-10-02 | 1,306,291 |
| 2026-10-03 | 2,962 |
| 2026-10-04 | 6,901 |
| 2026-10-05 | 2,888 |
| 2026-10-06 | 7,990 |
| 2026-10-07 | 7,929 |
| 2026-10-08 | 7,274 |
| 2026-10-09 | 10,159 |
| 2026-10-10 | 7,564 |
| 2026-10-11 | 6,257 |
| 2026-10-12 | 3,875 |
| 2026-10-13 | 8,303 |
| 2026-10-14 | 7,446 |
| 2026-10-15 | 8,327 |
| 2026-10-16 | 15,508 |
| 2026-10-17 | 9,963 |
| 2026-10-18 | 8,695 |
| 2026-10-19 | 5,173 |
| 2026-10-20 | 9,659 |
| 2026-10-21 | 9,596 |
| 2026-10-22 | 10,476 |
| 2026-10-23 | 12,517 |
| 2026-10-24 | 15,199 |
| 2026-10-25 | 11,169 |
| 2026-10-26 | 9,550 |
| 2026-10-27 | 35,511 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **1,239,360** IPs. Brutto faellig in den naechsten 30 Tagen: **1,621,387**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,800,747**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-27 | 6,250 | 2,000 |
| 2026-09-28 | 770 | 2,000 |
| 2026-09-30 | 59,567 | 2,000 |
| 2026-10-01 | 7,618 | 2,000 |
| 2026-10-02 | 1,306,291 | 2,000 |
| 2026-10-03 | 2,962 | 2,000 |
| 2026-10-04 | 6,901 | 2,000 |
| 2026-10-05 | 2,888 | 2,000 |
| 2026-10-06 | 7,990 | 2,000 |
| 2026-10-07 | 7,929 | 2,000 |
| 2026-10-08 | 7,274 | 2,000 |
| 2026-10-09 | 10,159 | 2,000 |
| 2026-10-10 | 7,564 | 2,000 |
| 2026-10-11 | 6,257 | 2,000 |
| 2026-10-12 | 3,875 | 2,000 |
| 2026-10-13 | 8,303 | 2,000 |
| 2026-10-14 | 7,446 | 2,000 |
| 2026-10-15 | 8,327 | 2,000 |
| 2026-10-16 | 15,508 | 2,000 |
| 2026-10-17 | 9,963 | 2,000 |
| 2026-10-18 | 8,695 | 2,000 |
| 2026-10-19 | 5,173 | 2,000 |
| 2026-10-20 | 9,659 | 2,000 |
| 2026-10-21 | 9,596 | 2,000 |
| 2026-10-22 | 10,476 | 2,000 |
| 2026-10-23 | 12,517 | 2,000 |
| 2026-10-24 | 15,199 | 2,000 |
| 2026-10-25 | 11,169 | 2,000 |
| 2026-10-26 | 9,550 | 2,000 |
| 2026-10-27 | 35,511 | 2,000 |

> Hinweis: Der Rueckstau von 2,800,747 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-28 | 11,588 |
| 2026-09-29 | 9,329 |
| 2026-09-30 | 10,142 |
| 2026-10-01 | 16,565 |
| 2026-10-02 | 7,701 |
| 2026-10-03 | 7,312 |
| 2026-10-04 | 12,587 |
| 2026-10-05 | 17,505 |
| 2026-10-06 | 16,081 |
| 2026-10-07 | 15,017 |
| 2026-10-08 | 61,267 |
| 2026-10-09 | 222,143 |
| 2026-10-10 | 53,339 |
| 2026-10-11 | 16,033 |
| 2026-10-12 | 66,562 |
| 2026-10-13 | 1,583,783 |
| 2026-10-14 | 32,916 |
| 2026-10-15 | 41,327 |
| 2026-10-16 | 51,280 |
| 2026-10-17 | 24,260 |
| 2026-10-18 | 14,257 |
| 2026-10-19 | 22,302 |
| 2026-10-20 | 11,133 |
| 2026-10-21 | 11,102 |
| 2026-10-22 | 30,725 |
| 2026-10-23 | 50,404 |
| 2026-10-24 | 41,707 |
| 2026-10-25 | 21,602 |
| 2026-10-26 | 20,324 |
| 2026-10-27 | 20,678 |
| 2026-10-28 | 15,797 |
| 2026-10-29 | 9,675 |
| 2026-10-30 | 61,925 |
| 2026-10-31 | 88,220 |
| 2026-11-01 | 27,866 |
| 2026-11-02 | 28,824 |
| 2026-11-03 | 29,797 |
| 2026-11-04 | 29,640 |
| 2026-11-05 | 25,292 |
| 2026-11-06 | 36,407 |
| 2026-11-07 | 24,481 |
| 2026-11-08 | 26,141 |
| 2026-11-09 | 25,579 |
| 2026-11-10 | 32,763 |
| 2026-11-11 | 22,401 |
| 2026-11-12 | 20,524 |
| 2026-11-13 | 19,677 |
| 2026-11-14 | 22,999 |
| 2026-11-15 | 17,484 |
| 2026-11-16 | 17,991 |
| 2026-11-17 | 15,275 |
| 2026-11-18 | 19,531 |
| 2026-11-19 | 174,028 |
| 2026-11-20 | 26,216 |
| 2026-11-21 | 61,510 |
| 2026-11-22 | 30,503 |
| 2026-11-23 | 25,739 |
| 2026-11-24 | 26,530 |
| 2026-11-25 | 27,616 |
| 2026-11-26 | 28,711 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
