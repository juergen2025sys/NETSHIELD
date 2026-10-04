# Seen-DB Expiry Forecast

Lauf: 2026-10-04 10:20 CEST (Europe/Berlin)
Gesamt: 12,187,710 IPs in seen_db.json (9,233,191 aktiv/180-Tage-Pfad, 2,954,519 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 400,137 |
| 8-14 Tage | 1,812,335 |
| 15-30 Tage | 491,087 |
| 31-60 Tage | 1,025,442 |
| 61-90 Tage | 752,936 |
| 91-180 Tage | 4,751,254 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,613,395 |
| 0-3 Tage | 25,504 |
| 4-7 Tage | 31,146 |
| 8-14 Tage | 61,875 |
| 15-30 Tage | 222,599 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-04 | 6,820 |
| 2026-10-05 | 2,859 |
| 2026-10-06 | 7,932 |
| 2026-10-07 | 7,893 |
| 2026-10-08 | 7,253 |
| 2026-10-09 | 10,125 |
| 2026-10-10 | 7,530 |
| 2026-10-11 | 6,238 |
| 2026-10-12 | 3,861 |
| 2026-10-13 | 8,252 |
| 2026-10-14 | 7,414 |
| 2026-10-15 | 8,293 |
| 2026-10-16 | 15,464 |
| 2026-10-17 | 9,936 |
| 2026-10-18 | 8,655 |
| 2026-10-19 | 5,150 |
| 2026-10-20 | 9,583 |
| 2026-10-21 | 9,536 |
| 2026-10-22 | 10,392 |
| 2026-10-23 | 12,415 |
| 2026-10-24 | 15,092 |
| 2026-10-25 | 11,109 |
| 2026-10-26 | 9,476 |
| 2026-10-27 | 35,308 |
| 2026-10-28 | 11,302 |
| 2026-10-29 | 9,872 |
| 2026-10-30 | 20,189 |
| 2026-10-31 | 17,165 |
| 2026-11-01 | 15,425 |
| 2026-11-02 | 12,026 |
| 2026-11-03 | 16,810 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,613,395** IPs. Brutto faellig in den naechsten 30 Tagen: **339,375**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **2,890,770**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-04 | 6,820 | 2,000 |
| 2026-10-05 | 2,859 | 2,000 |
| 2026-10-06 | 7,932 | 2,000 |
| 2026-10-07 | 7,893 | 2,000 |
| 2026-10-08 | 7,253 | 2,000 |
| 2026-10-09 | 10,125 | 2,000 |
| 2026-10-10 | 7,530 | 2,000 |
| 2026-10-11 | 6,238 | 2,000 |
| 2026-10-12 | 3,861 | 2,000 |
| 2026-10-13 | 8,252 | 2,000 |
| 2026-10-14 | 7,414 | 2,000 |
| 2026-10-15 | 8,293 | 2,000 |
| 2026-10-16 | 15,464 | 2,000 |
| 2026-10-17 | 9,936 | 2,000 |
| 2026-10-18 | 8,655 | 2,000 |
| 2026-10-19 | 5,150 | 2,000 |
| 2026-10-20 | 9,583 | 2,000 |
| 2026-10-21 | 9,536 | 2,000 |
| 2026-10-22 | 10,392 | 2,000 |
| 2026-10-23 | 12,415 | 2,000 |
| 2026-10-24 | 15,092 | 2,000 |
| 2026-10-25 | 11,109 | 2,000 |
| 2026-10-26 | 9,476 | 2,000 |
| 2026-10-27 | 35,308 | 2,000 |
| 2026-10-28 | 11,302 | 2,000 |
| 2026-10-29 | 9,872 | 2,000 |
| 2026-10-30 | 20,189 | 2,000 |
| 2026-10-31 | 17,165 | 2,000 |
| 2026-11-01 | 15,425 | 2,000 |
| 2026-11-02 | 12,026 | 2,000 |
| 2026-11-03 | 16,810 | 2,000 |

> Hinweis: Der Rueckstau von 2,890,770 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-05 | 17,448 |
| 2026-10-06 | 16,031 |
| 2026-10-07 | 14,966 |
| 2026-10-08 | 61,070 |
| 2026-10-09 | 221,322 |
| 2026-10-10 | 53,289 |
| 2026-10-11 | 16,011 |
| 2026-10-12 | 66,522 |
| 2026-10-13 | 1,581,946 |
| 2026-10-14 | 32,912 |
| 2026-10-15 | 41,298 |
| 2026-10-16 | 51,220 |
| 2026-10-17 | 24,213 |
| 2026-10-18 | 14,224 |
| 2026-10-19 | 22,177 |
| 2026-10-20 | 11,110 |
| 2026-10-21 | 11,070 |
| 2026-10-22 | 30,666 |
| 2026-10-23 | 50,331 |
| 2026-10-24 | 41,648 |
| 2026-10-25 | 21,555 |
| 2026-10-26 | 20,278 |
| 2026-10-27 | 20,610 |
| 2026-10-28 | 15,748 |
| 2026-10-29 | 9,637 |
| 2026-10-30 | 61,797 |
| 2026-10-31 | 88,148 |
| 2026-11-01 | 27,808 |
| 2026-11-02 | 28,769 |
| 2026-11-03 | 29,735 |
| 2026-11-04 | 29,583 |
| 2026-11-05 | 25,240 |
| 2026-11-06 | 36,329 |
| 2026-11-07 | 24,438 |
| 2026-11-08 | 26,095 |
| 2026-11-09 | 25,540 |
| 2026-11-10 | 32,708 |
| 2026-11-11 | 22,354 |
| 2026-11-12 | 20,491 |
| 2026-11-13 | 19,647 |
| 2026-11-14 | 22,963 |
| 2026-11-15 | 17,450 |
| 2026-11-16 | 17,959 |
| 2026-11-17 | 15,252 |
| 2026-11-18 | 19,501 |
| 2026-11-19 | 173,774 |
| 2026-11-20 | 26,164 |
| 2026-11-21 | 61,395 |
| 2026-11-22 | 30,437 |
| 2026-11-23 | 25,687 |
| 2026-11-24 | 26,485 |
| 2026-11-25 | 27,565 |
| 2026-11-26 | 28,679 |
| 2026-11-27 | 27,850 |
| 2026-11-28 | 109,228 |
| 2026-11-29 | 28,200 |
| 2026-11-30 | 25,565 |
| 2026-12-01 | 26,581 |
| 2026-12-02 | 26,219 |
| 2026-12-03 | 26,063 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
