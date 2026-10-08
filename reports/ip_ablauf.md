# Seen-DB Expiry Forecast

Lauf: 2026-10-08 09:16 CEST (Europe/Berlin)
Gesamt: 12,354,282 IPs in seen_db.json (9,369,310 aktiv/180-Tage-Pfad, 2,984,972 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 2,011,077 |
| 8-14 Tage | 164,242 |
| 15-30 Tage | 530,784 |
| 31-60 Tage | 1,016,339 |
| 61-90 Tage | 745,281 |
| 91-180 Tage | 4,901,587 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,627,478 |
| 0-3 Tage | 31,065 |
| 4-7 Tage | 27,716 |
| 8-14 Tage | 68,507 |
| 15-30 Tage | 230,206 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-08 | 7,236 |
| 2026-10-09 | 10,103 |
| 2026-10-10 | 7,511 |
| 2026-10-11 | 6,215 |
| 2026-10-12 | 3,846 |
| 2026-10-13 | 8,215 |
| 2026-10-14 | 7,394 |
| 2026-10-15 | 8,261 |
| 2026-10-16 | 15,424 |
| 2026-10-17 | 9,921 |
| 2026-10-18 | 8,629 |
| 2026-10-19 | 5,130 |
| 2026-10-20 | 9,541 |
| 2026-10-21 | 9,499 |
| 2026-10-22 | 10,363 |
| 2026-10-23 | 12,363 |
| 2026-10-24 | 15,040 |
| 2026-10-25 | 11,084 |
| 2026-10-26 | 9,434 |
| 2026-10-27 | 35,224 |
| 2026-10-28 | 11,268 |
| 2026-10-29 | 9,834 |
| 2026-10-30 | 20,108 |
| 2026-10-31 | 17,048 |
| 2026-11-01 | 15,356 |
| 2026-11-02 | 11,931 |
| 2026-11-03 | 16,633 |
| 2026-11-04 | 10,080 |
| 2026-11-05 | 7,277 |
| 2026-11-06 | 12,147 |
| 2026-11-07 | 13,514 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,627,478** IPs. Brutto faellig in den naechsten 30 Tagen: **355,629**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **2,921,107**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-08 | 7,236 | 2,000 |
| 2026-10-09 | 10,103 | 2,000 |
| 2026-10-10 | 7,511 | 2,000 |
| 2026-10-11 | 6,215 | 2,000 |
| 2026-10-12 | 3,846 | 2,000 |
| 2026-10-13 | 8,215 | 2,000 |
| 2026-10-14 | 7,394 | 2,000 |
| 2026-10-15 | 8,261 | 2,000 |
| 2026-10-16 | 15,424 | 2,000 |
| 2026-10-17 | 9,921 | 2,000 |
| 2026-10-18 | 8,629 | 2,000 |
| 2026-10-19 | 5,130 | 2,000 |
| 2026-10-20 | 9,541 | 2,000 |
| 2026-10-21 | 9,499 | 2,000 |
| 2026-10-22 | 10,363 | 2,000 |
| 2026-10-23 | 12,363 | 2,000 |
| 2026-10-24 | 15,040 | 2,000 |
| 2026-10-25 | 11,084 | 2,000 |
| 2026-10-26 | 9,434 | 2,000 |
| 2026-10-27 | 35,224 | 2,000 |
| 2026-10-28 | 11,268 | 2,000 |
| 2026-10-29 | 9,834 | 2,000 |
| 2026-10-30 | 20,108 | 2,000 |
| 2026-10-31 | 17,048 | 2,000 |
| 2026-11-01 | 15,356 | 2,000 |
| 2026-11-02 | 11,931 | 2,000 |
| 2026-11-03 | 16,633 | 2,000 |
| 2026-11-04 | 10,080 | 2,000 |
| 2026-11-05 | 7,277 | 2,000 |
| 2026-11-06 | 12,147 | 2,000 |
| 2026-11-07 | 13,514 | 2,000 |

> Hinweis: Der Rueckstau von 2,921,107 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-09 | 220,737 |
| 2026-10-10 | 53,254 |
| 2026-10-11 | 15,992 |
| 2026-10-12 | 66,499 |
| 2026-10-13 | 1,580,409 |
| 2026-10-14 | 32,903 |
| 2026-10-15 | 41,283 |
| 2026-10-16 | 51,160 |
| 2026-10-17 | 24,173 |
| 2026-10-18 | 14,187 |
| 2026-10-19 | 22,081 |
| 2026-10-20 | 11,081 |
| 2026-10-21 | 11,040 |
| 2026-10-22 | 30,520 |
| 2026-10-23 | 50,268 |
| 2026-10-24 | 41,610 |
| 2026-10-25 | 21,517 |
| 2026-10-26 | 20,237 |
| 2026-10-27 | 20,547 |
| 2026-10-28 | 15,693 |
| 2026-10-29 | 9,599 |
| 2026-10-30 | 61,680 |
| 2026-10-31 | 88,092 |
| 2026-11-01 | 27,766 |
| 2026-11-02 | 28,718 |
| 2026-11-03 | 29,671 |
| 2026-11-04 | 29,537 |
| 2026-11-05 | 25,198 |
| 2026-11-06 | 36,264 |
| 2026-11-07 | 24,387 |
| 2026-11-08 | 26,058 |
| 2026-11-09 | 25,487 |
| 2026-11-10 | 32,647 |
| 2026-11-11 | 22,317 |
| 2026-11-12 | 20,469 |
| 2026-11-13 | 19,621 |
| 2026-11-14 | 22,924 |
| 2026-11-15 | 17,432 |
| 2026-11-16 | 17,935 |
| 2026-11-17 | 15,217 |
| 2026-11-18 | 19,471 |
| 2026-11-19 | 173,590 |
| 2026-11-20 | 26,111 |
| 2026-11-21 | 61,311 |
| 2026-11-22 | 30,384 |
| 2026-11-23 | 25,636 |
| 2026-11-24 | 26,441 |
| 2026-11-25 | 27,499 |
| 2026-11-26 | 28,636 |
| 2026-11-27 | 27,817 |
| 2026-11-28 | 109,177 |
| 2026-11-29 | 28,163 |
| 2026-11-30 | 25,525 |
| 2026-12-01 | 26,538 |
| 2026-12-02 | 26,183 |
| 2026-12-03 | 26,010 |
| 2026-12-04 | 27,907 |
| 2026-12-05 | 25,946 |
| 2026-12-06 | 30,141 |
| 2026-12-07 | 23,746 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
