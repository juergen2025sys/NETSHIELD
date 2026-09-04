# Seen-DB Expiry Forecast

Lauf: 2026-09-04 15:54 CEST (Europe/Berlin)
Gesamt: 11,181,320 IPs in seen_db.json (8,532,770 aktiv/180-Tage-Pfad, 2,648,550 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 836,781 |
| 8-14 Tage | 0 |
| 15-30 Tage | 166,868 |
| 31-60 Tage | 2,728,055 |
| 61-90 Tage | 1,036,023 |
| 91-180 Tage | 3,765,043 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 196,691 |
| 0-3 Tage | 254,231 |
| 4-7 Tage | 50,349 |
| 8-14 Tage | 73,842 |
| 15-30 Tage | 2,073,437 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-04 | 148,100 |
| 2026-09-05 | 69,337 |
| 2026-09-06 | 20,511 |
| 2026-09-07 | 16,283 |
| 2026-09-08 | 13,101 |
| 2026-09-09 | 17,029 |
| 2026-09-10 | 8,820 |
| 2026-09-11 | 11,399 |
| 2026-09-12 | 11,986 |
| 2026-09-13 | 12,129 |
| 2026-09-14 | 12,963 |
| 2026-09-15 | 15,729 |
| 2026-09-16 | 6,300 |
| 2026-09-17 | 5,849 |
| 2026-09-18 | 8,886 |
| 2026-09-19 | 5,201 |
| 2026-09-20 | 5,115 |
| 2026-09-21 | 5,106 |
| 2026-09-22 | 11,289 |
| 2026-09-23 | 5,207 |
| 2026-09-24 | 11,491 |
| 2026-09-25 | 5,575 |
| 2026-09-26 | 624,777 |
| 2026-09-27 | 6,419 |
| 2026-09-28 | 791 |
| 2026-09-30 | 60,159 |
| 2026-10-01 | 7,795 |
| 2026-10-02 | 1,311,416 |
| 2026-10-03 | 3,060 |
| 2026-10-04 | 7,510 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **196,691** IPs. Brutto faellig in den naechsten 30 Tagen: **2,449,333**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,586,024**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-04 | 148,100 | 2,000 |
| 2026-09-05 | 69,337 | 2,000 |
| 2026-09-06 | 20,511 | 2,000 |
| 2026-09-07 | 16,283 | 2,000 |
| 2026-09-08 | 13,101 | 2,000 |
| 2026-09-09 | 17,029 | 2,000 |
| 2026-09-10 | 8,820 | 2,000 |
| 2026-09-11 | 11,399 | 2,000 |
| 2026-09-12 | 11,986 | 2,000 |
| 2026-09-13 | 12,129 | 2,000 |
| 2026-09-14 | 12,963 | 2,000 |
| 2026-09-15 | 15,729 | 2,000 |
| 2026-09-16 | 6,300 | 2,000 |
| 2026-09-17 | 5,849 | 2,000 |
| 2026-09-18 | 8,886 | 2,000 |
| 2026-09-19 | 5,201 | 2,000 |
| 2026-09-20 | 5,115 | 2,000 |
| 2026-09-21 | 5,106 | 2,000 |
| 2026-09-22 | 11,289 | 2,000 |
| 2026-09-23 | 5,207 | 2,000 |
| 2026-09-24 | 11,491 | 2,000 |
| 2026-09-25 | 5,575 | 2,000 |
| 2026-09-26 | 624,777 | 2,000 |
| 2026-09-27 | 6,419 | 2,000 |
| 2026-09-28 | 791 | 2,000 |
| 2026-09-30 | 60,159 | 2,000 |
| 2026-10-01 | 7,795 | 2,000 |
| 2026-10-02 | 1,311,416 | 2,000 |
| 2026-10-03 | 3,060 | 2,000 |
| 2026-10-04 | 7,510 | 2,000 |

> Hinweis: Der Rueckstau von 2,586,024 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-05 | 173,668 |
| 2026-09-08 | 663,113 |
| 2026-09-22 | 6,491 |
| 2026-09-23 | 13,193 |
| 2026-09-24 | 16,881 |
| 2026-09-25 | 21,165 |
| 2026-09-26 | 17,668 |
| 2026-09-27 | 15,247 |
| 2026-09-28 | 11,688 |
| 2026-09-29 | 9,449 |
| 2026-09-30 | 10,311 |
| 2026-10-01 | 16,742 |
| 2026-10-02 | 7,818 |
| 2026-10-03 | 7,412 |
| 2026-10-04 | 12,803 |
| 2026-10-05 | 17,725 |
| 2026-10-06 | 16,294 |
| 2026-10-07 | 15,211 |
| 2026-10-08 | 62,242 |
| 2026-10-09 | 226,526 |
| 2026-10-10 | 53,552 |
| 2026-10-11 | 16,124 |
| 2026-10-12 | 66,722 |
| 2026-10-13 | 1,592,246 |
| 2026-10-14 | 32,971 |
| 2026-10-15 | 41,464 |
| 2026-10-16 | 51,540 |
| 2026-10-17 | 24,507 |
| 2026-10-18 | 14,410 |
| 2026-10-19 | 22,773 |
| 2026-10-20 | 11,248 |
| 2026-10-21 | 11,228 |
| 2026-10-22 | 31,027 |
| 2026-10-23 | 50,664 |
| 2026-10-24 | 41,969 |
| 2026-10-25 | 21,822 |
| 2026-10-26 | 20,574 |
| 2026-10-27 | 20,928 |
| 2026-10-28 | 15,968 |
| 2026-10-29 | 9,841 |
| 2026-10-30 | 62,521 |
| 2026-10-31 | 88,513 |
| 2026-11-01 | 28,101 |
| 2026-11-02 | 29,128 |
| 2026-11-03 | 30,216 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
