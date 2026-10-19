# Seen-DB Expiry Forecast

Lauf: 2026-10-19 15:50 CEST (Europe/Berlin)
Gesamt: 10,946,734 IPs in seen_db.json (7,858,506 aktiv/180-Tage-Pfad, 3,088,228 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 185,909 |
| 8-14 Tage | 251,460 |
| 15-30 Tage | 383,935 |
| 31-60 Tage | 1,084,982 |
| 61-90 Tage | 693,494 |
| 91-180 Tage | 5,258,726 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,701,126 |
| 0-3 Tage | 34,411 |
| 4-7 Tage | 47,782 |
| 8-14 Tage | 120,278 |
| 15-30 Tage | 184,631 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-19 | 5,106 |
| 2026-10-20 | 9,502 |
| 2026-10-21 | 9,469 |
| 2026-10-22 | 10,334 |
| 2026-10-23 | 12,331 |
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
| 2026-11-04 | 10,041 |
| 2026-11-05 | 7,222 |
| 2026-11-06 | 12,048 |
| 2026-11-07 | 13,339 |
| 2026-11-08 | 6,253 |
| 2026-11-09 | 11,467 |
| 2026-11-10 | 23,818 |
| 2026-11-11 | 9,885 |
| 2026-11-12 | 8,047 |
| 2026-11-13 | 3,342 |
| 2026-11-14 | 11,626 |
| 2026-11-15 | 14,354 |
| 2026-11-16 | 18,963 |
| 2026-11-17 | 9,369 |
| 2026-11-18 | 3,544 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,701,126** IPs. Brutto faellig in den naechsten 30 Tagen: **382,372**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **3,021,498**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-19 | 5,106 | 2,000 |
| 2026-10-20 | 9,502 | 2,000 |
| 2026-10-21 | 9,469 | 2,000 |
| 2026-10-22 | 10,334 | 2,000 |
| 2026-10-23 | 12,331 | 2,000 |
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
| 2026-11-04 | 10,041 | 2,000 |
| 2026-11-05 | 7,222 | 2,000 |
| 2026-11-06 | 12,048 | 2,000 |
| 2026-11-07 | 13,339 | 2,000 |
| 2026-11-08 | 6,253 | 2,000 |
| 2026-11-09 | 11,467 | 2,000 |
| 2026-11-10 | 23,818 | 2,000 |
| 2026-11-11 | 9,885 | 2,000 |
| 2026-11-12 | 8,047 | 2,000 |
| 2026-11-13 | 3,342 | 2,000 |
| 2026-11-14 | 11,626 | 2,000 |
| 2026-11-15 | 14,354 | 2,000 |
| 2026-11-16 | 18,963 | 2,000 |
| 2026-11-17 | 9,369 | 2,000 |
| 2026-11-18 | 3,544 | 2,000 |

> Hinweis: Der Rueckstau von 3,021,498 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-20 | 11,053 |
| 2026-10-21 | 11,012 |
| 2026-10-22 | 30,447 |
| 2026-10-23 | 50,189 |
| 2026-10-24 | 41,558 |
| 2026-10-25 | 21,470 |
| 2026-10-26 | 20,180 |
| 2026-10-27 | 20,415 |
| 2026-10-28 | 15,545 |
| 2026-10-29 | 9,516 |
| 2026-10-30 | 61,571 |
| 2026-10-31 | 88,029 |
| 2026-11-01 | 27,716 |
| 2026-11-02 | 28,668 |
| 2026-11-03 | 29,613 |
| 2026-11-04 | 29,469 |
| 2026-11-05 | 25,151 |
| 2026-11-06 | 36,201 |
| 2026-11-07 | 24,353 |
| 2026-11-08 | 26,011 |
| 2026-11-09 | 25,437 |
| 2026-11-10 | 32,596 |
| 2026-11-11 | 22,265 |
| 2026-11-12 | 20,436 |
| 2026-11-13 | 19,584 |
| 2026-11-14 | 22,879 |
| 2026-11-15 | 17,404 |
| 2026-11-16 | 17,904 |
| 2026-11-17 | 15,188 |
| 2026-11-18 | 19,444 |
| 2026-11-19 | 173,431 |
| 2026-11-20 | 26,071 |
| 2026-11-21 | 61,231 |
| 2026-11-22 | 30,332 |
| 2026-11-23 | 25,591 |
| 2026-11-24 | 26,397 |
| 2026-11-25 | 27,454 |
| 2026-11-26 | 28,597 |
| 2026-11-27 | 27,782 |
| 2026-11-28 | 109,117 |
| 2026-11-29 | 28,121 |
| 2026-11-30 | 25,478 |
| 2026-12-01 | 26,490 |
| 2026-12-02 | 26,146 |
| 2026-12-03 | 25,965 |
| 2026-12-04 | 27,869 |
| 2026-12-05 | 25,914 |
| 2026-12-06 | 30,088 |
| 2026-12-07 | 23,704 |
| 2026-12-08 | 39,331 |
| 2026-12-09 | 55,052 |
| 2026-12-10 | 25,054 |
| 2026-12-11 | 27,736 |
| 2026-12-12 | 24,363 |
| 2026-12-13 | 23,832 |
| 2026-12-14 | 23,444 |
| 2026-12-15 | 26,229 |
| 2026-12-16 | 16,654 |
| 2026-12-17 | 25,002 |
| 2026-12-18 | 22,507 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
