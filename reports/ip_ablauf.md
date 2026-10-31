# Seen-DB Expiry Forecast

Lauf: 2026-10-31 17:18 CET (Europe/Berlin)
Gesamt: 11,171,846 IPs in seen_db.json (7,990,823 aktiv/180-Tage-Pfad, 3,181,023 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 200,848 |
| 8-14 Tage | 168,947 |
| 15-30 Tage | 658,839 |
| 31-60 Tage | 761,989 |
| 61-90 Tage | 870,236 |
| 91-180 Tage | 5,329,964 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,856,834 |
| 0-3 Tage | 60,561 |
| 4-7 Tage | 42,548 |
| 8-14 Tage | 73,968 |
| 15-30 Tage | 147,112 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-31 | 16,866 |
| 2026-11-01 | 15,293 |
| 2026-11-02 | 11,851 |
| 2026-11-03 | 16,551 |
| 2026-11-04 | 10,018 |
| 2026-11-05 | 7,201 |
| 2026-11-06 | 12,022 |
| 2026-11-07 | 13,307 |
| 2026-11-08 | 6,230 |
| 2026-11-09 | 11,424 |
| 2026-11-10 | 23,603 |
| 2026-11-11 | 9,851 |
| 2026-11-12 | 7,993 |
| 2026-11-13 | 3,309 |
| 2026-11-14 | 11,558 |
| 2026-11-15 | 14,282 |
| 2026-11-16 | 18,840 |
| 2026-11-17 | 9,303 |
| 2026-11-18 | 3,481 |
| 2026-11-19 | 8,797 |
| 2026-11-20 | 10,876 |
| 2026-11-21 | 9,981 |
| 2026-11-22 | 10,013 |
| 2026-11-23 | 10,057 |
| 2026-11-24 | 10,139 |
| 2026-11-25 | 7,638 |
| 2026-11-26 | 3,364 |
| 2026-11-27 | 3,895 |
| 2026-11-28 | 3,570 |
| 2026-11-29 | 8,176 |
| 2026-11-30 | 7,251 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,856,834** IPs. Brutto faellig in den naechsten 30 Tagen: **316,740**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,111,574**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-31 | 16,866 | 2,000 |
| 2026-11-01 | 15,293 | 2,000 |
| 2026-11-02 | 11,851 | 2,000 |
| 2026-11-03 | 16,551 | 2,000 |
| 2026-11-04 | 10,018 | 2,000 |
| 2026-11-05 | 7,201 | 2,000 |
| 2026-11-06 | 12,022 | 2,000 |
| 2026-11-07 | 13,307 | 2,000 |
| 2026-11-08 | 6,230 | 2,000 |
| 2026-11-09 | 11,424 | 2,000 |
| 2026-11-10 | 23,603 | 2,000 |
| 2026-11-11 | 9,851 | 2,000 |
| 2026-11-12 | 7,993 | 2,000 |
| 2026-11-13 | 3,309 | 2,000 |
| 2026-11-14 | 11,558 | 2,000 |
| 2026-11-15 | 14,282 | 2,000 |
| 2026-11-16 | 18,840 | 2,000 |
| 2026-11-17 | 9,303 | 2,000 |
| 2026-11-18 | 3,481 | 2,000 |
| 2026-11-19 | 8,797 | 2,000 |
| 2026-11-20 | 10,876 | 2,000 |
| 2026-11-21 | 9,981 | 2,000 |
| 2026-11-22 | 10,013 | 2,000 |
| 2026-11-23 | 10,057 | 2,000 |
| 2026-11-24 | 10,139 | 2,000 |
| 2026-11-25 | 7,638 | 2,000 |
| 2026-11-26 | 3,364 | 2,000 |
| 2026-11-27 | 3,895 | 2,000 |
| 2026-11-28 | 3,570 | 2,000 |
| 2026-11-29 | 8,176 | 2,000 |
| 2026-11-30 | 7,251 | 2,000 |

> Hinweis: Der Rueckstau von 3,111,574 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-01 | 27,681 |
| 2026-11-02 | 28,622 |
| 2026-11-03 | 29,563 |
| 2026-11-04 | 29,419 |
| 2026-11-05 | 25,113 |
| 2026-11-06 | 36,138 |
| 2026-11-07 | 24,312 |
| 2026-11-08 | 25,983 |
| 2026-11-09 | 25,395 |
| 2026-11-10 | 32,545 |
| 2026-11-11 | 22,224 |
| 2026-11-12 | 20,408 |
| 2026-11-13 | 19,547 |
| 2026-11-14 | 22,845 |
| 2026-11-15 | 17,384 |
| 2026-11-16 | 17,866 |
| 2026-11-17 | 15,166 |
| 2026-11-18 | 19,412 |
| 2026-11-19 | 173,309 |
| 2026-11-20 | 26,026 |
| 2026-11-21 | 61,177 |
| 2026-11-22 | 30,284 |
| 2026-11-23 | 25,543 |
| 2026-11-24 | 26,366 |
| 2026-11-25 | 27,400 |
| 2026-11-26 | 28,566 |
| 2026-11-27 | 27,749 |
| 2026-11-28 | 109,055 |
| 2026-11-29 | 28,091 |
| 2026-11-30 | 25,445 |
| 2026-12-01 | 26,462 |
| 2026-12-02 | 26,107 |
| 2026-12-03 | 25,924 |
| 2026-12-04 | 27,842 |
| 2026-12-05 | 25,876 |
| 2026-12-06 | 30,051 |
| 2026-12-07 | 23,676 |
| 2026-12-08 | 39,291 |
| 2026-12-09 | 54,885 |
| 2026-12-10 | 25,027 |
| 2026-12-11 | 27,702 |
| 2026-12-12 | 24,319 |
| 2026-12-13 | 23,789 |
| 2026-12-14 | 23,406 |
| 2026-12-15 | 26,179 |
| 2026-12-16 | 16,586 |
| 2026-12-17 | 24,961 |
| 2026-12-18 | 22,451 |
| 2026-12-19 | 25,550 |
| 2026-12-20 | 14,285 |
| 2026-12-21 | 27,291 |
| 2026-12-22 | 24,061 |
| 2026-12-23 | 21,090 |
| 2026-12-24 | 20,378 |
| 2026-12-25 | 21,589 |
| 2026-12-26 | 17,800 |
| 2026-12-27 | 24,632 |
| 2026-12-28 | 21,725 |
| 2026-12-29 | 22,548 |
| 2026-12-30 | 26,506 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
