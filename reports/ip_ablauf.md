# Seen-DB Expiry Forecast

Lauf: 2026-09-03 01:14 CEST (Europe/Berlin)
Gesamt: 11,148,706 IPs in seen_db.json (8,483,808 aktiv/180-Tage-Pfad, 2,664,898 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 837,111 |
| 8-14 Tage | 0 |
| 15-30 Tage | 146,769 |
| 31-60 Tage | 2,689,796 |
| 61-90 Tage | 1,042,815 |
| 91-180 Tage | 3,767,317 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 176,683 |
| 0-3 Tage | 237,783 |
| 4-7 Tage | 66,979 |
| 8-14 Tage | 79,439 |
| 15-30 Tage | 2,104,014 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-02 | 9,317 |
| 2026-09-03 | 10,959 |
| 2026-09-04 | 148,121 |
| 2026-09-05 | 69,386 |
| 2026-09-06 | 20,522 |
| 2026-09-07 | 16,309 |
| 2026-09-08 | 13,110 |
| 2026-09-09 | 17,038 |
| 2026-09-10 | 8,836 |
| 2026-09-11 | 11,416 |
| 2026-09-12 | 12,001 |
| 2026-09-13 | 12,150 |
| 2026-09-14 | 12,983 |
| 2026-09-15 | 15,747 |
| 2026-09-16 | 6,306 |
| 2026-09-17 | 5,853 |
| 2026-09-18 | 8,893 |
| 2026-09-19 | 5,209 |
| 2026-09-20 | 5,119 |
| 2026-09-21 | 5,115 |
| 2026-09-22 | 11,301 |
| 2026-09-23 | 5,221 |
| 2026-09-24 | 11,503 |
| 2026-09-25 | 5,581 |
| 2026-09-26 | 624,847 |
| 2026-09-27 | 6,439 |
| 2026-09-28 | 795 |
| 2026-09-30 | 60,226 |
| 2026-10-01 | 7,821 |
| 2026-10-02 | 1,311,869 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **176,683** IPs. Brutto faellig in den naechsten 30 Tagen: **2,459,993**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,576,676**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-02 | 9,317 | 2,000 |
| 2026-09-03 | 10,959 | 2,000 |
| 2026-09-04 | 148,121 | 2,000 |
| 2026-09-05 | 69,386 | 2,000 |
| 2026-09-06 | 20,522 | 2,000 |
| 2026-09-07 | 16,309 | 2,000 |
| 2026-09-08 | 13,110 | 2,000 |
| 2026-09-09 | 17,038 | 2,000 |
| 2026-09-10 | 8,836 | 2,000 |
| 2026-09-11 | 11,416 | 2,000 |
| 2026-09-12 | 12,001 | 2,000 |
| 2026-09-13 | 12,150 | 2,000 |
| 2026-09-14 | 12,983 | 2,000 |
| 2026-09-15 | 15,747 | 2,000 |
| 2026-09-16 | 6,306 | 2,000 |
| 2026-09-17 | 5,853 | 2,000 |
| 2026-09-18 | 8,893 | 2,000 |
| 2026-09-19 | 5,209 | 2,000 |
| 2026-09-20 | 5,119 | 2,000 |
| 2026-09-21 | 5,115 | 2,000 |
| 2026-09-22 | 11,301 | 2,000 |
| 2026-09-23 | 5,221 | 2,000 |
| 2026-09-24 | 11,503 | 2,000 |
| 2026-09-25 | 5,581 | 2,000 |
| 2026-09-26 | 624,847 | 2,000 |
| 2026-09-27 | 6,439 | 2,000 |
| 2026-09-28 | 795 | 2,000 |
| 2026-09-30 | 60,226 | 2,000 |
| 2026-10-01 | 7,821 | 2,000 |
| 2026-10-02 | 1,311,869 | 2,000 |

> Hinweis: Der Rueckstau von 2,576,676 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-05 | 173,679 |
| 2026-09-08 | 663,432 |
| 2026-09-22 | 6,499 |
| 2026-09-23 | 13,206 |
| 2026-09-24 | 16,890 |
| 2026-09-25 | 21,179 |
| 2026-09-26 | 17,683 |
| 2026-09-27 | 15,263 |
| 2026-09-28 | 11,696 |
| 2026-09-29 | 9,453 |
| 2026-09-30 | 10,321 |
| 2026-10-01 | 16,752 |
| 2026-10-02 | 7,827 |
| 2026-10-03 | 7,421 |
| 2026-10-04 | 12,820 |
| 2026-10-05 | 17,738 |
| 2026-10-06 | 16,309 |
| 2026-10-07 | 15,226 |
| 2026-10-08 | 62,324 |
| 2026-10-09 | 226,675 |
| 2026-10-10 | 53,563 |
| 2026-10-11 | 16,126 |
| 2026-10-12 | 66,731 |
| 2026-10-13 | 1,592,497 |
| 2026-10-14 | 32,976 |
| 2026-10-15 | 41,474 |
| 2026-10-16 | 51,552 |
| 2026-10-17 | 24,516 |
| 2026-10-18 | 14,415 |
| 2026-10-19 | 22,801 |
| 2026-10-20 | 11,252 |
| 2026-10-21 | 11,238 |
| 2026-10-22 | 31,045 |
| 2026-10-23 | 50,689 |
| 2026-10-24 | 41,984 |
| 2026-10-25 | 21,850 |
| 2026-10-26 | 20,596 |
| 2026-10-27 | 20,940 |
| 2026-10-28 | 15,977 |
| 2026-10-29 | 9,850 |
| 2026-10-30 | 62,552 |
| 2026-10-31 | 88,529 |
| 2026-11-01 | 28,130 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
