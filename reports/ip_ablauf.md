# Seen-DB Expiry Forecast

Lauf: 2026-09-05 05:43 CEST (Europe/Berlin)
Gesamt: 11,028,327 IPs in seen_db.json (8,378,532 aktiv/180-Tage-Pfad, 2,649,795 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 662,975 |
| 8-14 Tage | 0 |
| 15-30 Tage | 184,543 |
| 31-60 Tage | 2,739,941 |
| 61-90 Tage | 1,034,088 |
| 91-180 Tage | 3,756,985 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 344,731 |
| 0-3 Tage | 119,181 |
| 4-7 Tage | 49,219 |
| 8-14 Tage | 67,011 |
| 15-30 Tage | 2,069,653 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-05 | 69,312 |
| 2026-09-06 | 20,507 |
| 2026-09-07 | 16,267 |
| 2026-09-08 | 13,095 |
| 2026-09-09 | 17,027 |
| 2026-09-10 | 8,817 |
| 2026-09-11 | 11,395 |
| 2026-09-12 | 11,980 |
| 2026-09-13 | 12,121 |
| 2026-09-14 | 12,956 |
| 2026-09-15 | 15,722 |
| 2026-09-16 | 6,299 |
| 2026-09-17 | 5,843 |
| 2026-09-18 | 8,875 |
| 2026-09-19 | 5,195 |
| 2026-09-20 | 5,108 |
| 2026-09-21 | 5,100 |
| 2026-09-22 | 11,283 |
| 2026-09-23 | 5,203 |
| 2026-09-24 | 11,488 |
| 2026-09-25 | 5,568 |
| 2026-09-26 | 624,754 |
| 2026-09-27 | 6,411 |
| 2026-09-28 | 790 |
| 2026-09-30 | 60,139 |
| 2026-10-01 | 7,789 |
| 2026-10-02 | 1,311,258 |
| 2026-10-03 | 3,047 |
| 2026-10-04 | 7,093 |
| 2026-10-05 | 3,577 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **344,731** IPs. Brutto faellig in den naechsten 30 Tagen: **2,304,019**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,588,750**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-05 | 69,312 | 2,000 |
| 2026-09-06 | 20,507 | 2,000 |
| 2026-09-07 | 16,267 | 2,000 |
| 2026-09-08 | 13,095 | 2,000 |
| 2026-09-09 | 17,027 | 2,000 |
| 2026-09-10 | 8,817 | 2,000 |
| 2026-09-11 | 11,395 | 2,000 |
| 2026-09-12 | 11,980 | 2,000 |
| 2026-09-13 | 12,121 | 2,000 |
| 2026-09-14 | 12,956 | 2,000 |
| 2026-09-15 | 15,722 | 2,000 |
| 2026-09-16 | 6,299 | 2,000 |
| 2026-09-17 | 5,843 | 2,000 |
| 2026-09-18 | 8,875 | 2,000 |
| 2026-09-19 | 5,195 | 2,000 |
| 2026-09-20 | 5,108 | 2,000 |
| 2026-09-21 | 5,100 | 2,000 |
| 2026-09-22 | 11,283 | 2,000 |
| 2026-09-23 | 5,203 | 2,000 |
| 2026-09-24 | 11,488 | 2,000 |
| 2026-09-25 | 5,568 | 2,000 |
| 2026-09-26 | 624,754 | 2,000 |
| 2026-09-27 | 6,411 | 2,000 |
| 2026-09-28 | 790 | 2,000 |
| 2026-09-30 | 60,139 | 2,000 |
| 2026-10-01 | 7,789 | 2,000 |
| 2026-10-02 | 1,311,258 | 2,000 |
| 2026-10-03 | 3,047 | 2,000 |
| 2026-10-04 | 7,093 | 2,000 |
| 2026-10-05 | 3,577 | 2,000 |

> Hinweis: Der Rueckstau von 2,588,750 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-08 | 662,975 |
| 2026-09-22 | 6,490 |
| 2026-09-23 | 13,191 |
| 2026-09-24 | 16,876 |
| 2026-09-25 | 21,155 |
| 2026-09-26 | 17,660 |
| 2026-09-27 | 15,243 |
| 2026-09-28 | 11,686 |
| 2026-09-29 | 9,448 |
| 2026-09-30 | 10,305 |
| 2026-10-01 | 16,741 |
| 2026-10-02 | 7,816 |
| 2026-10-03 | 7,410 |
| 2026-10-04 | 12,800 |
| 2026-10-05 | 17,722 |
| 2026-10-06 | 16,291 |
| 2026-10-07 | 15,211 |
| 2026-10-08 | 62,213 |
| 2026-10-09 | 226,454 |
| 2026-10-10 | 53,545 |
| 2026-10-11 | 16,122 |
| 2026-10-12 | 66,719 |
| 2026-10-13 | 1,592,125 |
| 2026-10-14 | 32,969 |
| 2026-10-15 | 41,461 |
| 2026-10-16 | 51,535 |
| 2026-10-17 | 24,505 |
| 2026-10-18 | 14,408 |
| 2026-10-19 | 22,757 |
| 2026-10-20 | 11,244 |
| 2026-10-21 | 11,226 |
| 2026-10-22 | 31,021 |
| 2026-10-23 | 50,656 |
| 2026-10-24 | 41,959 |
| 2026-10-25 | 21,814 |
| 2026-10-26 | 20,568 |
| 2026-10-27 | 20,921 |
| 2026-10-28 | 15,962 |
| 2026-10-29 | 9,839 |
| 2026-10-30 | 62,499 |
| 2026-10-31 | 88,506 |
| 2026-11-01 | 28,095 |
| 2026-11-02 | 29,121 |
| 2026-11-03 | 30,206 |
| 2026-11-04 | 29,989 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Fuer den Active-Pfad kann eine legitime Zweitbestaetigung (2+ HQ-Feed-Familien) nicht von einem Bug unterschieden werden, daher wird dort nur der eindeutig unplausible Fall (Rueckfall auf den Watchlist-Pfad) geprueft.*
