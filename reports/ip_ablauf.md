# Seen-DB Expiry Forecast

Lauf: 2026-10-08 02:55 CEST (Europe/Berlin)
Gesamt: 12,400,991 IPs in seen_db.json (9,415,555 aktiv/180-Tage-Pfad, 2,985,436 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 2,072,098 |
| 8-14 Tage | 164,260 |
| 15-30 Tage | 530,829 |
| 31-60 Tage | 1,016,398 |
| 61-90 Tage | 745,394 |
| 91-180 Tage | 4,886,576 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,629,587 |
| 0-3 Tage | 31,070 |
| 4-7 Tage | 27,721 |
| 8-14 Tage | 68,523 |
| 15-30 Tage | 228,535 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-08 | 7,239 |
| 2026-10-09 | 10,103 |
| 2026-10-10 | 7,513 |
| 2026-10-11 | 6,215 |
| 2026-10-12 | 3,846 |
| 2026-10-13 | 8,216 |
| 2026-10-14 | 7,396 |
| 2026-10-15 | 8,263 |
| 2026-10-16 | 15,425 |
| 2026-10-17 | 9,923 |
| 2026-10-18 | 8,632 |
| 2026-10-19 | 5,130 |
| 2026-10-20 | 9,544 |
| 2026-10-21 | 9,500 |
| 2026-10-22 | 10,369 |
| 2026-10-23 | 12,366 |
| 2026-10-24 | 15,040 |
| 2026-10-25 | 11,085 |
| 2026-10-26 | 9,438 |
| 2026-10-27 | 35,232 |
| 2026-10-28 | 11,272 |
| 2026-10-29 | 9,835 |
| 2026-10-30 | 20,113 |
| 2026-10-31 | 17,052 |
| 2026-11-01 | 15,362 |
| 2026-11-02 | 11,941 |
| 2026-11-03 | 16,642 |
| 2026-11-04 | 10,084 |
| 2026-11-05 | 7,285 |
| 2026-11-06 | 12,166 |
| 2026-11-07 | 13,622 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,629,587** IPs. Brutto faellig in den naechsten 30 Tagen: **355,849**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **2,923,436**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-08 | 7,239 | 2,000 |
| 2026-10-09 | 10,103 | 2,000 |
| 2026-10-10 | 7,513 | 2,000 |
| 2026-10-11 | 6,215 | 2,000 |
| 2026-10-12 | 3,846 | 2,000 |
| 2026-10-13 | 8,216 | 2,000 |
| 2026-10-14 | 7,396 | 2,000 |
| 2026-10-15 | 8,263 | 2,000 |
| 2026-10-16 | 15,425 | 2,000 |
| 2026-10-17 | 9,923 | 2,000 |
| 2026-10-18 | 8,632 | 2,000 |
| 2026-10-19 | 5,130 | 2,000 |
| 2026-10-20 | 9,544 | 2,000 |
| 2026-10-21 | 9,500 | 2,000 |
| 2026-10-22 | 10,369 | 2,000 |
| 2026-10-23 | 12,366 | 2,000 |
| 2026-10-24 | 15,040 | 2,000 |
| 2026-10-25 | 11,085 | 2,000 |
| 2026-10-26 | 9,438 | 2,000 |
| 2026-10-27 | 35,232 | 2,000 |
| 2026-10-28 | 11,272 | 2,000 |
| 2026-10-29 | 9,835 | 2,000 |
| 2026-10-30 | 20,113 | 2,000 |
| 2026-10-31 | 17,052 | 2,000 |
| 2026-11-01 | 15,362 | 2,000 |
| 2026-11-02 | 11,941 | 2,000 |
| 2026-11-03 | 16,642 | 2,000 |
| 2026-11-04 | 10,084 | 2,000 |
| 2026-11-05 | 7,285 | 2,000 |
| 2026-11-06 | 12,166 | 2,000 |
| 2026-11-07 | 13,622 | 2,000 |

> Hinweis: Der Rueckstau von 2,923,436 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-08 | 60,917 |
| 2026-10-09 | 220,775 |
| 2026-10-10 | 53,254 |
| 2026-10-11 | 15,993 |
| 2026-10-12 | 66,503 |
| 2026-10-13 | 1,580,468 |
| 2026-10-14 | 32,904 |
| 2026-10-15 | 41,284 |
| 2026-10-16 | 51,164 |
| 2026-10-17 | 24,177 |
| 2026-10-18 | 14,188 |
| 2026-10-19 | 22,085 |
| 2026-10-20 | 11,083 |
| 2026-10-21 | 11,042 |
| 2026-10-22 | 30,521 |
| 2026-10-23 | 50,268 |
| 2026-10-24 | 41,612 |
| 2026-10-25 | 21,518 |
| 2026-10-26 | 20,239 |
| 2026-10-27 | 20,554 |
| 2026-10-28 | 15,700 |
| 2026-10-29 | 9,602 |
| 2026-10-30 | 61,684 |
| 2026-10-31 | 88,094 |
| 2026-11-01 | 27,769 |
| 2026-11-02 | 28,719 |
| 2026-11-03 | 29,675 |
| 2026-11-04 | 29,538 |
| 2026-11-05 | 25,200 |
| 2026-11-06 | 36,264 |
| 2026-11-07 | 24,393 |
| 2026-11-08 | 26,058 |
| 2026-11-09 | 25,487 |
| 2026-11-10 | 32,649 |
| 2026-11-11 | 22,319 |
| 2026-11-12 | 20,471 |
| 2026-11-13 | 19,621 |
| 2026-11-14 | 22,925 |
| 2026-11-15 | 17,434 |
| 2026-11-16 | 17,935 |
| 2026-11-17 | 15,218 |
| 2026-11-18 | 19,474 |
| 2026-11-19 | 173,600 |
| 2026-11-20 | 26,112 |
| 2026-11-21 | 61,314 |
| 2026-11-22 | 30,387 |
| 2026-11-23 | 25,637 |
| 2026-11-24 | 26,442 |
| 2026-11-25 | 27,503 |
| 2026-11-26 | 28,637 |
| 2026-11-27 | 27,818 |
| 2026-11-28 | 109,177 |
| 2026-11-29 | 28,164 |
| 2026-11-30 | 25,527 |
| 2026-12-01 | 26,541 |
| 2026-12-02 | 26,186 |
| 2026-12-03 | 26,011 |
| 2026-12-04 | 27,908 |
| 2026-12-05 | 25,949 |
| 2026-12-06 | 30,145 |
| 2026-12-07 | 23,749 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
