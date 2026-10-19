# Seen-DB Expiry Forecast

Lauf: 2026-10-19 13:10 CEST (Europe/Berlin)
Gesamt: 10,945,607 IPs in seen_db.json (7,857,616 aktiv/180-Tage-Pfad, 3,087,991 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 185,913 |
| 8-14 Tage | 251,468 |
| 15-30 Tage | 383,940 |
| 31-60 Tage | 1,085,000 |
| 61-90 Tage | 693,509 |
| 91-180 Tage | 5,257,786 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,701,148 |
| 0-3 Tage | 34,411 |
| 4-7 Tage | 47,783 |
| 8-14 Tage | 120,278 |
| 15-30 Tage | 184,371 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-19 | 5,106 |
| 2026-10-20 | 9,502 |
| 2026-10-21 | 9,469 |
| 2026-10-22 | 10,334 |
| 2026-10-23 | 12,332 |
| 2026-10-24 | 15,000 |
| 2026-10-25 | 11,048 |
| 2026-10-26 | 9,403 |
| 2026-10-27 | 35,088 |
| 2026-10-28 | 11,244 |
| 2026-10-29 | 9,804 |
| 2026-10-30 | 20,048 |
| 2026-10-31 | 16,904 |
| 2026-11-01 | 15,312 |
| 2026-11-02 | 11,878 |
| 2026-11-03 | 16,583 |
| 2026-11-04 | 10,042 |
| 2026-11-05 | 7,224 |
| 2026-11-06 | 12,050 |
| 2026-11-07 | 13,339 |
| 2026-11-08 | 6,253 |
| 2026-11-09 | 11,468 |
| 2026-11-10 | 23,819 |
| 2026-11-11 | 9,887 |
| 2026-11-12 | 8,047 |
| 2026-11-13 | 3,343 |
| 2026-11-14 | 11,630 |
| 2026-11-15 | 14,356 |
| 2026-11-16 | 18,965 |
| 2026-11-17 | 9,372 |
| 2026-11-18 | 3,548 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,701,148** IPs. Brutto faellig in den naechsten 30 Tagen: **382,398**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,021,546**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-19 | 5,106 | 2,000 |
| 2026-10-20 | 9,502 | 2,000 |
| 2026-10-21 | 9,469 | 2,000 |
| 2026-10-22 | 10,334 | 2,000 |
| 2026-10-23 | 12,332 | 2,000 |
| 2026-10-24 | 15,000 | 2,000 |
| 2026-10-25 | 11,048 | 2,000 |
| 2026-10-26 | 9,403 | 2,000 |
| 2026-10-27 | 35,088 | 2,000 |
| 2026-10-28 | 11,244 | 2,000 |
| 2026-10-29 | 9,804 | 2,000 |
| 2026-10-30 | 20,048 | 2,000 |
| 2026-10-31 | 16,904 | 2,000 |
| 2026-11-01 | 15,312 | 2,000 |
| 2026-11-02 | 11,878 | 2,000 |
| 2026-11-03 | 16,583 | 2,000 |
| 2026-11-04 | 10,042 | 2,000 |
| 2026-11-05 | 7,224 | 2,000 |
| 2026-11-06 | 12,050 | 2,000 |
| 2026-11-07 | 13,339 | 2,000 |
| 2026-11-08 | 6,253 | 2,000 |
| 2026-11-09 | 11,468 | 2,000 |
| 2026-11-10 | 23,819 | 2,000 |
| 2026-11-11 | 9,887 | 2,000 |
| 2026-11-12 | 8,047 | 2,000 |
| 2026-11-13 | 3,343 | 2,000 |
| 2026-11-14 | 11,630 | 2,000 |
| 2026-11-15 | 14,356 | 2,000 |
| 2026-11-16 | 18,965 | 2,000 |
| 2026-11-17 | 9,372 | 2,000 |
| 2026-11-18 | 3,548 | 2,000 |

> Hinweis: Der Rueckstau von 3,021,546 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-20 | 11,054 |
| 2026-10-21 | 11,012 |
| 2026-10-22 | 30,448 |
| 2026-10-23 | 50,190 |
| 2026-10-24 | 41,559 |
| 2026-10-25 | 21,470 |
| 2026-10-26 | 20,180 |
| 2026-10-27 | 20,416 |
| 2026-10-28 | 15,548 |
| 2026-10-29 | 9,516 |
| 2026-10-30 | 61,572 |
| 2026-10-31 | 88,030 |
| 2026-11-01 | 27,716 |
| 2026-11-02 | 28,670 |
| 2026-11-03 | 29,614 |
| 2026-11-04 | 29,469 |
| 2026-11-05 | 25,151 |
| 2026-11-06 | 36,202 |
| 2026-11-07 | 24,353 |
| 2026-11-08 | 26,011 |
| 2026-11-09 | 25,437 |
| 2026-11-10 | 32,597 |
| 2026-11-11 | 22,265 |
| 2026-11-12 | 20,436 |
| 2026-11-13 | 19,584 |
| 2026-11-14 | 22,879 |
| 2026-11-15 | 17,404 |
| 2026-11-16 | 17,904 |
| 2026-11-17 | 15,189 |
| 2026-11-18 | 19,445 |
| 2026-11-19 | 173,432 |
| 2026-11-20 | 26,071 |
| 2026-11-21 | 61,232 |
| 2026-11-22 | 30,333 |
| 2026-11-23 | 25,591 |
| 2026-11-24 | 26,397 |
| 2026-11-25 | 27,454 |
| 2026-11-26 | 28,597 |
| 2026-11-27 | 27,783 |
| 2026-11-28 | 109,117 |
| 2026-11-29 | 28,121 |
| 2026-11-30 | 25,480 |
| 2026-12-01 | 26,491 |
| 2026-12-02 | 26,147 |
| 2026-12-03 | 25,965 |
| 2026-12-04 | 27,869 |
| 2026-12-05 | 25,914 |
| 2026-12-06 | 30,088 |
| 2026-12-07 | 23,704 |
| 2026-12-08 | 39,332 |
| 2026-12-09 | 55,054 |
| 2026-12-10 | 25,054 |
| 2026-12-11 | 27,736 |
| 2026-12-12 | 24,364 |
| 2026-12-13 | 23,833 |
| 2026-12-14 | 23,444 |
| 2026-12-15 | 26,230 |
| 2026-12-16 | 16,655 |
| 2026-12-17 | 25,004 |
| 2026-12-18 | 22,508 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
