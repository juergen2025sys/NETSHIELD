# Seen-DB Expiry Forecast

Lauf: 2026-10-31 21:15 CET (Europe/Berlin)
Gesamt: 11,175,258 IPs in seen_db.json (7,993,782 aktiv/180-Tage-Pfad, 3,181,476 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 200,845 |
| 8-14 Tage | 168,946 |
| 15-30 Tage | 658,835 |
| 31-60 Tage | 761,973 |
| 61-90 Tage | 870,228 |
| 91-180 Tage | 5,332,955 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,856,803 |
| 0-3 Tage | 60,561 |
| 4-7 Tage | 42,546 |
| 8-14 Tage | 73,963 |
| 15-30 Tage | 147,603 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-31 | 16,866 |
| 2026-11-01 | 15,293 |
| 2026-11-02 | 11,851 |
| 2026-11-03 | 16,551 |
| 2026-11-04 | 10,018 |
| 2026-11-05 | 7,200 |
| 2026-11-06 | 12,022 |
| 2026-11-07 | 13,306 |
| 2026-11-08 | 6,228 |
| 2026-11-09 | 11,422 |
| 2026-11-10 | 23,602 |
| 2026-11-11 | 9,851 |
| 2026-11-12 | 7,993 |
| 2026-11-13 | 3,309 |
| 2026-11-14 | 11,558 |
| 2026-11-15 | 14,281 |
| 2026-11-16 | 18,839 |
| 2026-11-17 | 9,302 |
| 2026-11-18 | 3,481 |
| 2026-11-19 | 8,796 |
| 2026-11-20 | 10,874 |
| 2026-11-21 | 9,980 |
| 2026-11-22 | 10,011 |
| 2026-11-23 | 10,055 |
| 2026-11-24 | 10,137 |
| 2026-11-25 | 7,638 |
| 2026-11-26 | 3,364 |
| 2026-11-27 | 3,891 |
| 2026-11-28 | 3,570 |
| 2026-11-29 | 8,173 |
| 2026-11-30 | 7,250 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,856,803** IPs. Brutto faellig in den naechsten 30 Tagen: **316,712**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,111,515**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-31 | 16,866 | 2,000 |
| 2026-11-01 | 15,293 | 2,000 |
| 2026-11-02 | 11,851 | 2,000 |
| 2026-11-03 | 16,551 | 2,000 |
| 2026-11-04 | 10,018 | 2,000 |
| 2026-11-05 | 7,200 | 2,000 |
| 2026-11-06 | 12,022 | 2,000 |
| 2026-11-07 | 13,306 | 2,000 |
| 2026-11-08 | 6,228 | 2,000 |
| 2026-11-09 | 11,422 | 2,000 |
| 2026-11-10 | 23,602 | 2,000 |
| 2026-11-11 | 9,851 | 2,000 |
| 2026-11-12 | 7,993 | 2,000 |
| 2026-11-13 | 3,309 | 2,000 |
| 2026-11-14 | 11,558 | 2,000 |
| 2026-11-15 | 14,281 | 2,000 |
| 2026-11-16 | 18,839 | 2,000 |
| 2026-11-17 | 9,302 | 2,000 |
| 2026-11-18 | 3,481 | 2,000 |
| 2026-11-19 | 8,796 | 2,000 |
| 2026-11-20 | 10,874 | 2,000 |
| 2026-11-21 | 9,980 | 2,000 |
| 2026-11-22 | 10,011 | 2,000 |
| 2026-11-23 | 10,055 | 2,000 |
| 2026-11-24 | 10,137 | 2,000 |
| 2026-11-25 | 7,638 | 2,000 |
| 2026-11-26 | 3,364 | 2,000 |
| 2026-11-27 | 3,891 | 2,000 |
| 2026-11-28 | 3,570 | 2,000 |
| 2026-11-29 | 8,173 | 2,000 |
| 2026-11-30 | 7,250 | 2,000 |

> Hinweis: Der Rueckstau von 3,111,515 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-11-01 | 27,681 |
| 2026-11-02 | 28,622 |
| 2026-11-03 | 29,563 |
| 2026-11-04 | 29,418 |
| 2026-11-05 | 25,111 |
| 2026-11-06 | 36,138 |
| 2026-11-07 | 24,312 |
| 2026-11-08 | 25,983 |
| 2026-11-09 | 25,395 |
| 2026-11-10 | 32,545 |
| 2026-11-11 | 22,224 |
| 2026-11-12 | 20,407 |
| 2026-11-13 | 19,547 |
| 2026-11-14 | 22,845 |
| 2026-11-15 | 17,384 |
| 2026-11-16 | 17,866 |
| 2026-11-17 | 15,165 |
| 2026-11-18 | 19,412 |
| 2026-11-19 | 173,309 |
| 2026-11-20 | 26,026 |
| 2026-11-21 | 61,177 |
| 2026-11-22 | 30,284 |
| 2026-11-23 | 25,543 |
| 2026-11-24 | 26,365 |
| 2026-11-25 | 27,399 |
| 2026-11-26 | 28,566 |
| 2026-11-27 | 27,749 |
| 2026-11-28 | 109,054 |
| 2026-11-29 | 28,091 |
| 2026-11-30 | 25,445 |
| 2026-12-01 | 26,462 |
| 2026-12-02 | 26,107 |
| 2026-12-03 | 25,923 |
| 2026-12-04 | 27,842 |
| 2026-12-05 | 25,876 |
| 2026-12-06 | 30,050 |
| 2026-12-07 | 23,675 |
| 2026-12-08 | 39,291 |
| 2026-12-09 | 54,883 |
| 2026-12-10 | 25,027 |
| 2026-12-11 | 27,702 |
| 2026-12-12 | 24,319 |
| 2026-12-13 | 23,789 |
| 2026-12-14 | 23,405 |
| 2026-12-15 | 26,178 |
| 2026-12-16 | 16,586 |
| 2026-12-17 | 24,960 |
| 2026-12-18 | 22,451 |
| 2026-12-19 | 25,549 |
| 2026-12-20 | 14,283 |
| 2026-12-21 | 27,290 |
| 2026-12-22 | 24,061 |
| 2026-12-23 | 21,090 |
| 2026-12-24 | 20,377 |
| 2026-12-25 | 21,589 |
| 2026-12-26 | 17,799 |
| 2026-12-27 | 24,631 |
| 2026-12-28 | 21,725 |
| 2026-12-29 | 22,548 |
| 2026-12-30 | 26,505 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
