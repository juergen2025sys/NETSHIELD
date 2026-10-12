# Seen-DB Expiry Forecast

Lauf: 2026-10-12 03:41 CEST (Europe/Berlin)
Gesamt: 12,250,518 IPs in seen_db.json (9,224,792 aktiv/180-Tage-Pfad, 3,025,726 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 1,765,405 |
| 8-14 Tage | 186,097 |
| 15-30 Tage | 503,224 |
| 31-60 Tage | 1,056,583 |
| 61-90 Tage | 693,556 |
| 91-180 Tage | 5,019,927 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,649,223 |
| 0-3 Tage | 27,682 |
| 4-7 Tage | 39,061 |
| 8-14 Tage | 77,184 |
| 15-30 Tage | 232,576 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-12 | 3,840 |
| 2026-10-13 | 8,207 |
| 2026-10-14 | 7,383 |
| 2026-10-15 | 8,252 |
| 2026-10-16 | 15,412 |
| 2026-10-17 | 9,913 |
| 2026-10-18 | 8,618 |
| 2026-10-19 | 5,118 |
| 2026-10-20 | 9,521 |
| 2026-10-21 | 9,480 |
| 2026-10-22 | 10,344 |
| 2026-10-23 | 12,345 |
| 2026-10-24 | 15,012 |
| 2026-10-25 | 11,066 |
| 2026-10-26 | 9,416 |
| 2026-10-27 | 35,174 |
| 2026-10-28 | 11,254 |
| 2026-10-29 | 9,816 |
| 2026-10-30 | 20,075 |
| 2026-10-31 | 16,948 |
| 2026-11-01 | 15,329 |
| 2026-11-02 | 11,892 |
| 2026-11-03 | 16,598 |
| 2026-11-04 | 10,058 |
| 2026-11-05 | 7,242 |
| 2026-11-06 | 12,070 |
| 2026-11-07 | 13,383 |
| 2026-11-08 | 6,282 |
| 2026-11-09 | 11,522 |
| 2026-11-10 | 23,898 |
| 2026-11-11 | 9,977 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,649,223** IPs. Brutto faellig in den naechsten 30 Tagen: **375,445**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **2,962,668**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-12 | 3,840 | 2,000 |
| 2026-10-13 | 8,207 | 2,000 |
| 2026-10-14 | 7,383 | 2,000 |
| 2026-10-15 | 8,252 | 2,000 |
| 2026-10-16 | 15,412 | 2,000 |
| 2026-10-17 | 9,913 | 2,000 |
| 2026-10-18 | 8,618 | 2,000 |
| 2026-10-19 | 5,118 | 2,000 |
| 2026-10-20 | 9,521 | 2,000 |
| 2026-10-21 | 9,480 | 2,000 |
| 2026-10-22 | 10,344 | 2,000 |
| 2026-10-23 | 12,345 | 2,000 |
| 2026-10-24 | 15,012 | 2,000 |
| 2026-10-25 | 11,066 | 2,000 |
| 2026-10-26 | 9,416 | 2,000 |
| 2026-10-27 | 35,174 | 2,000 |
| 2026-10-28 | 11,254 | 2,000 |
| 2026-10-29 | 9,816 | 2,000 |
| 2026-10-30 | 20,075 | 2,000 |
| 2026-10-31 | 16,948 | 2,000 |
| 2026-11-01 | 15,329 | 2,000 |
| 2026-11-02 | 11,892 | 2,000 |
| 2026-11-03 | 16,598 | 2,000 |
| 2026-11-04 | 10,058 | 2,000 |
| 2026-11-05 | 7,242 | 2,000 |
| 2026-11-06 | 12,070 | 2,000 |
| 2026-11-07 | 13,383 | 2,000 |
| 2026-11-08 | 6,282 | 2,000 |
| 2026-11-09 | 11,522 | 2,000 |
| 2026-11-10 | 23,898 | 2,000 |
| 2026-11-11 | 9,977 | 2,000 |

> Hinweis: Der Rueckstau von 2,962,668 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-13 | 1,579,746 |
| 2026-10-14 | 32,901 |
| 2026-10-15 | 41,271 |
| 2026-10-16 | 51,136 |
| 2026-10-17 | 24,160 |
| 2026-10-18 | 14,170 |
| 2026-10-19 | 22,021 |
| 2026-10-20 | 11,064 |
| 2026-10-21 | 11,028 |
| 2026-10-22 | 30,490 |
| 2026-10-23 | 50,230 |
| 2026-10-24 | 41,581 |
| 2026-10-25 | 21,496 |
| 2026-10-26 | 20,208 |
| 2026-10-27 | 20,512 |
| 2026-10-28 | 15,667 |
| 2026-10-29 | 9,588 |
| 2026-10-30 | 61,616 |
| 2026-10-31 | 88,058 |
| 2026-11-01 | 27,748 |
| 2026-11-02 | 28,695 |
| 2026-11-03 | 29,643 |
| 2026-11-04 | 29,501 |
| 2026-11-05 | 25,171 |
| 2026-11-06 | 36,234 |
| 2026-11-07 | 24,368 |
| 2026-11-08 | 26,035 |
| 2026-11-09 | 25,465 |
| 2026-11-10 | 32,627 |
| 2026-11-11 | 22,296 |
| 2026-11-12 | 20,455 |
| 2026-11-13 | 19,606 |
| 2026-11-14 | 22,905 |
| 2026-11-15 | 17,419 |
| 2026-11-16 | 17,918 |
| 2026-11-17 | 15,206 |
| 2026-11-18 | 19,462 |
| 2026-11-19 | 173,490 |
| 2026-11-20 | 26,094 |
| 2026-11-21 | 61,272 |
| 2026-11-22 | 30,355 |
| 2026-11-23 | 25,615 |
| 2026-11-24 | 26,422 |
| 2026-11-25 | 27,479 |
| 2026-11-26 | 28,619 |
| 2026-11-27 | 27,800 |
| 2026-11-28 | 109,152 |
| 2026-11-29 | 28,135 |
| 2026-11-30 | 25,500 |
| 2026-12-01 | 26,515 |
| 2026-12-02 | 26,167 |
| 2026-12-03 | 25,988 |
| 2026-12-04 | 27,890 |
| 2026-12-05 | 25,933 |
| 2026-12-06 | 30,112 |
| 2026-12-07 | 23,726 |
| 2026-12-08 | 39,358 |
| 2026-12-09 | 55,152 |
| 2026-12-10 | 25,084 |
| 2026-12-11 | 27,754 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
