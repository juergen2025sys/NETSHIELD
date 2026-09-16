# Seen-DB Expiry Forecast

Lauf: 2026-09-16 16:47 CEST (Europe/Berlin)
Gesamt: 11,337,080 IPs in seen_db.json (8,405,700 aktiv/180-Tage-Pfad, 2,931,380 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 19,524 |
| 8-14 Tage | 101,470 |
| 15-30 Tage | 2,227,798 |
| 31-60 Tage | 837,352 |
| 61-90 Tage | 1,082,447 |
| 91-180 Tage | 4,137,109 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 549,920 |
| 0-3 Tage | 25,887 |
| 4-7 Tage | 26,383 |
| 8-14 Tage | 707,857 |
| 15-30 Tage | 1,621,333 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-16 | 6,230 |
| 2026-09-17 | 5,755 |
| 2026-09-18 | 8,770 |
| 2026-09-19 | 5,132 |
| 2026-09-20 | 5,053 |
| 2026-09-21 | 5,030 |
| 2026-09-22 | 11,168 |
| 2026-09-23 | 5,132 |
| 2026-09-24 | 11,415 |
| 2026-09-25 | 5,483 |
| 2026-09-26 | 624,087 |
| 2026-09-27 | 6,312 |
| 2026-09-28 | 779 |
| 2026-09-30 | 59,781 |
| 2026-10-01 | 7,681 |
| 2026-10-02 | 1,308,394 |
| 2026-10-03 | 2,984 |
| 2026-10-04 | 6,945 |
| 2026-10-05 | 2,918 |
| 2026-10-06 | 8,308 |
| 2026-10-07 | 8,043 |
| 2026-10-08 | 7,359 |
| 2026-10-09 | 152,230 |
| 2026-10-10 | 8,253 |
| 2026-10-11 | 23,275 |
| 2026-10-12 | 33,410 |
| 2026-10-13 | 9,118 |
| 2026-10-14 | 8,145 |
| 2026-10-15 | 8,959 |
| 2026-10-16 | 16,533 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **549,920** IPs. Brutto faellig in den naechsten 30 Tagen: **2,372,682**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,862,602**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-16 | 6,230 | 2,000 |
| 2026-09-17 | 5,755 | 2,000 |
| 2026-09-18 | 8,770 | 2,000 |
| 2026-09-19 | 5,132 | 2,000 |
| 2026-09-20 | 5,053 | 2,000 |
| 2026-09-21 | 5,030 | 2,000 |
| 2026-09-22 | 11,168 | 2,000 |
| 2026-09-23 | 5,132 | 2,000 |
| 2026-09-24 | 11,415 | 2,000 |
| 2026-09-25 | 5,483 | 2,000 |
| 2026-09-26 | 624,087 | 2,000 |
| 2026-09-27 | 6,312 | 2,000 |
| 2026-09-28 | 779 | 2,000 |
| 2026-09-30 | 59,781 | 2,000 |
| 2026-10-01 | 7,681 | 2,000 |
| 2026-10-02 | 1,308,394 | 2,000 |
| 2026-10-03 | 2,984 | 2,000 |
| 2026-10-04 | 6,945 | 2,000 |
| 2026-10-05 | 2,918 | 2,000 |
| 2026-10-06 | 8,308 | 2,000 |
| 2026-10-07 | 8,043 | 2,000 |
| 2026-10-08 | 7,359 | 2,000 |
| 2026-10-09 | 152,230 | 2,000 |
| 2026-10-10 | 8,253 | 2,000 |
| 2026-10-11 | 23,275 | 2,000 |
| 2026-10-12 | 33,410 | 2,000 |
| 2026-10-13 | 9,118 | 2,000 |
| 2026-10-14 | 8,145 | 2,000 |
| 2026-10-15 | 8,959 | 2,000 |
| 2026-10-16 | 16,533 | 2,000 |

> Hinweis: Der Rueckstau von 2,862,602 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,440 |
| 2026-09-23 | 13,084 |
| 2026-09-24 | 16,703 |
| 2026-09-25 | 20,977 |
| 2026-09-26 | 17,494 |
| 2026-09-27 | 15,077 |
| 2026-09-28 | 11,624 |
| 2026-09-29 | 9,380 |
| 2026-09-30 | 10,215 |
| 2026-10-01 | 16,633 |
| 2026-10-02 | 7,747 |
| 2026-10-03 | 7,353 |
| 2026-10-04 | 12,665 |
| 2026-10-05 | 17,595 |
| 2026-10-06 | 16,170 |
| 2026-10-07 | 15,110 |
| 2026-10-08 | 61,602 |
| 2026-10-09 | 223,925 |
| 2026-10-10 | 53,435 |
| 2026-10-11 | 16,076 |
| 2026-10-12 | 66,625 |
| 2026-10-13 | 1,587,127 |
| 2026-10-14 | 32,937 |
| 2026-10-15 | 41,381 |
| 2026-10-16 | 51,417 |
| 2026-10-17 | 24,377 |
| 2026-10-18 | 14,324 |
| 2026-10-19 | 22,484 |
| 2026-10-20 | 11,174 |
| 2026-10-21 | 11,151 |
| 2026-10-22 | 30,840 |
| 2026-10-23 | 50,514 |
| 2026-10-24 | 41,822 |
| 2026-10-25 | 21,682 |
| 2026-10-26 | 20,427 |
| 2026-10-27 | 20,778 |
| 2026-10-28 | 15,856 |
| 2026-10-29 | 9,747 |
| 2026-10-30 | 62,152 |
| 2026-10-31 | 88,318 |
| 2026-11-01 | 27,965 |
| 2026-11-02 | 28,944 |
| 2026-11-03 | 29,969 |
| 2026-11-04 | 29,774 |
| 2026-11-05 | 25,393 |
| 2026-11-06 | 36,821 |
| 2026-11-07 | 24,576 |
| 2026-11-08 | 26,246 |
| 2026-11-09 | 25,682 |
| 2026-11-10 | 32,880 |
| 2026-11-11 | 22,499 |
| 2026-11-12 | 20,587 |
| 2026-11-13 | 19,743 |
| 2026-11-14 | 23,081 |
| 2026-11-15 | 17,546 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 192245 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
