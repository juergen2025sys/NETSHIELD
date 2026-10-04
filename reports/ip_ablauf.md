# Seen-DB Expiry Forecast

Lauf: 2026-10-04 03:57 CEST (Europe/Berlin)
Gesamt: 12,167,966 IPs in seen_db.json (9,214,793 aktiv/180-Tage-Pfad, 2,953,173 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 400,181 |
| 8-14 Tage | 1,812,404 |
| 15-30 Tage | 491,109 |
| 31-60 Tage | 1,025,492 |
| 61-90 Tage | 753,001 |
| 91-180 Tage | 4,732,606 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 2,613,505 |
| 0-3 Tage | 25,511 |
| 4-7 Tage | 31,147 |
| 8-14 Tage | 61,885 |
| 15-30 Tage | 221,125 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-10-04 | 6,823 |
| 2026-10-05 | 2,859 |
| 2026-10-06 | 7,934 |
| 2026-10-07 | 7,895 |
| 2026-10-08 | 7,253 |
| 2026-10-09 | 10,126 |
| 2026-10-10 | 7,530 |
| 2026-10-11 | 6,238 |
| 2026-10-12 | 3,862 |
| 2026-10-13 | 8,253 |
| 2026-10-14 | 7,416 |
| 2026-10-15 | 8,293 |
| 2026-10-16 | 15,468 |
| 2026-10-17 | 9,938 |
| 2026-10-18 | 8,655 |
| 2026-10-19 | 5,150 |
| 2026-10-20 | 9,588 |
| 2026-10-21 | 9,540 |
| 2026-10-22 | 10,396 |
| 2026-10-23 | 12,416 |
| 2026-10-24 | 15,093 |
| 2026-10-25 | 11,112 |
| 2026-10-26 | 9,478 |
| 2026-10-27 | 35,311 |
| 2026-10-28 | 11,302 |
| 2026-10-29 | 9,876 |
| 2026-10-30 | 20,191 |
| 2026-10-31 | 17,168 |
| 2026-11-01 | 15,431 |
| 2026-11-02 | 12,045 |
| 2026-11-03 | 16,899 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **2,613,505** IPs. Brutto faellig in den naechsten 30 Tagen: **339,539**, davon im selben Fenster tatsaechlich entfernbar: **62,000**. Verbleibender Rueckstau am Fensterende: **2,891,044**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-10-04 | 6,823 | 2,000 |
| 2026-10-05 | 2,859 | 2,000 |
| 2026-10-06 | 7,934 | 2,000 |
| 2026-10-07 | 7,895 | 2,000 |
| 2026-10-08 | 7,253 | 2,000 |
| 2026-10-09 | 10,126 | 2,000 |
| 2026-10-10 | 7,530 | 2,000 |
| 2026-10-11 | 6,238 | 2,000 |
| 2026-10-12 | 3,862 | 2,000 |
| 2026-10-13 | 8,253 | 2,000 |
| 2026-10-14 | 7,416 | 2,000 |
| 2026-10-15 | 8,293 | 2,000 |
| 2026-10-16 | 15,468 | 2,000 |
| 2026-10-17 | 9,938 | 2,000 |
| 2026-10-18 | 8,655 | 2,000 |
| 2026-10-19 | 5,150 | 2,000 |
| 2026-10-20 | 9,588 | 2,000 |
| 2026-10-21 | 9,540 | 2,000 |
| 2026-10-22 | 10,396 | 2,000 |
| 2026-10-23 | 12,416 | 2,000 |
| 2026-10-24 | 15,093 | 2,000 |
| 2026-10-25 | 11,112 | 2,000 |
| 2026-10-26 | 9,478 | 2,000 |
| 2026-10-27 | 35,311 | 2,000 |
| 2026-10-28 | 11,302 | 2,000 |
| 2026-10-29 | 9,876 | 2,000 |
| 2026-10-30 | 20,191 | 2,000 |
| 2026-10-31 | 17,168 | 2,000 |
| 2026-11-01 | 15,431 | 2,000 |
| 2026-11-02 | 12,045 | 2,000 |
| 2026-11-03 | 16,899 | 2,000 |

> Hinweis: Der Rueckstau von 2,891,044 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-10-05 | 17,451 |
| 2026-10-06 | 16,032 |
| 2026-10-07 | 14,970 |
| 2026-10-08 | 61,073 |
| 2026-10-09 | 221,354 |
| 2026-10-10 | 53,289 |
| 2026-10-11 | 16,012 |
| 2026-10-12 | 66,523 |
| 2026-10-13 | 1,582,012 |
| 2026-10-14 | 32,912 |
| 2026-10-15 | 41,298 |
| 2026-10-16 | 51,220 |
| 2026-10-17 | 24,214 |
| 2026-10-18 | 14,225 |
| 2026-10-19 | 22,177 |
| 2026-10-20 | 11,111 |
| 2026-10-21 | 11,071 |
| 2026-10-22 | 30,668 |
| 2026-10-23 | 50,332 |
| 2026-10-24 | 41,652 |
| 2026-10-25 | 21,555 |
| 2026-10-26 | 20,280 |
| 2026-10-27 | 20,610 |
| 2026-10-28 | 15,749 |
| 2026-10-29 | 9,638 |
| 2026-10-30 | 61,803 |
| 2026-10-31 | 88,149 |
| 2026-11-01 | 27,809 |
| 2026-11-02 | 28,769 |
| 2026-11-03 | 29,736 |
| 2026-11-04 | 29,583 |
| 2026-11-05 | 25,240 |
| 2026-11-06 | 36,335 |
| 2026-11-07 | 24,439 |
| 2026-11-08 | 26,095 |
| 2026-11-09 | 25,540 |
| 2026-11-10 | 32,709 |
| 2026-11-11 | 22,355 |
| 2026-11-12 | 20,492 |
| 2026-11-13 | 19,648 |
| 2026-11-14 | 22,964 |
| 2026-11-15 | 17,450 |
| 2026-11-16 | 17,959 |
| 2026-11-17 | 15,252 |
| 2026-11-18 | 19,501 |
| 2026-11-19 | 173,788 |
| 2026-11-20 | 26,166 |
| 2026-11-21 | 61,399 |
| 2026-11-22 | 30,438 |
| 2026-11-23 | 25,687 |
| 2026-11-24 | 26,485 |
| 2026-11-25 | 27,566 |
| 2026-11-26 | 28,679 |
| 2026-11-27 | 27,853 |
| 2026-11-28 | 109,232 |
| 2026-11-29 | 28,203 |
| 2026-11-30 | 25,568 |
| 2026-12-01 | 26,582 |
| 2026-12-02 | 26,220 |
| 2026-12-03 | 26,064 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - eingefrorene Active-IP-Adressen bleiben komplett aus seen_db/COMB draussen, solange keine echte starke Neubestätigung (2+ HQ-Familien) den Ledger-Eintrag freigibt.

*Hinweis: Seit dem 21.09.2026 gilt fuer den Active/180T-Pfad ein harter Wiedereintrittsschutz: schwache Evidenz darf keine eingefrorene IP mehr in die COMB/Watchlist zurueckbringen. Erst 2+ unabhaengige HQ-Familien am selben Tag erlauben einen echten Wiedereintritt.*
