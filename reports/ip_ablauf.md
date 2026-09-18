# Seen-DB Expiry Forecast

Lauf: 2026-09-18 03:26 CEST (Europe/Berlin)
Gesamt: 11,419,446 IPs in seen_db.json (8,479,408 aktiv/180-Tage-Pfad, 2,940,038 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 57,167 |
| 8-14 Tage | 88,097 |
| 15-30 Tage | 2,241,409 |
| 31-60 Tage | 831,556 |
| 61-90 Tage | 1,090,688 |
| 91-180 Tage | 4,170,491 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 559,577 |
| 0-3 Tage | 23,956 |
| 4-7 Tage | 33,169 |
| 8-14 Tage | 2,006,520 |
| 15-30 Tage | 316,816 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-18 | 8,759 |
| 2026-09-19 | 5,130 |
| 2026-09-20 | 5,043 |
| 2026-09-21 | 5,024 |
| 2026-09-22 | 11,156 |
| 2026-09-23 | 5,125 |
| 2026-09-24 | 11,410 |
| 2026-09-25 | 5,478 |
| 2026-09-26 | 624,015 |
| 2026-09-27 | 6,299 |
| 2026-09-28 | 778 |
| 2026-09-30 | 59,754 |
| 2026-10-01 | 7,676 |
| 2026-10-02 | 1,307,998 |
| 2026-10-03 | 2,982 |
| 2026-10-04 | 6,935 |
| 2026-10-05 | 2,916 |
| 2026-10-06 | 8,299 |
| 2026-10-07 | 8,028 |
| 2026-10-08 | 7,347 |
| 2026-10-09 | 152,105 |
| 2026-10-10 | 8,231 |
| 2026-10-11 | 23,236 |
| 2026-10-12 | 33,366 |
| 2026-10-13 | 9,082 |
| 2026-10-14 | 8,122 |
| 2026-10-15 | 8,930 |
| 2026-10-16 | 16,312 |
| 2026-10-17 | 10,706 |
| 2026-10-18 | 10,211 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **559,577** IPs. Brutto faellig in den naechsten 30 Tagen: **2,380,453**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,880,030**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-18 | 8,759 | 2,000 |
| 2026-09-19 | 5,130 | 2,000 |
| 2026-09-20 | 5,043 | 2,000 |
| 2026-09-21 | 5,024 | 2,000 |
| 2026-09-22 | 11,156 | 2,000 |
| 2026-09-23 | 5,125 | 2,000 |
| 2026-09-24 | 11,410 | 2,000 |
| 2026-09-25 | 5,478 | 2,000 |
| 2026-09-26 | 624,015 | 2,000 |
| 2026-09-27 | 6,299 | 2,000 |
| 2026-09-28 | 778 | 2,000 |
| 2026-09-30 | 59,754 | 2,000 |
| 2026-10-01 | 7,676 | 2,000 |
| 2026-10-02 | 1,307,998 | 2,000 |
| 2026-10-03 | 2,982 | 2,000 |
| 2026-10-04 | 6,935 | 2,000 |
| 2026-10-05 | 2,916 | 2,000 |
| 2026-10-06 | 8,299 | 2,000 |
| 2026-10-07 | 8,028 | 2,000 |
| 2026-10-08 | 7,347 | 2,000 |
| 2026-10-09 | 152,105 | 2,000 |
| 2026-10-10 | 8,231 | 2,000 |
| 2026-10-11 | 23,236 | 2,000 |
| 2026-10-12 | 33,366 | 2,000 |
| 2026-10-13 | 9,082 | 2,000 |
| 2026-10-14 | 8,122 | 2,000 |
| 2026-10-15 | 8,930 | 2,000 |
| 2026-10-16 | 16,312 | 2,000 |
| 2026-10-17 | 10,706 | 2,000 |
| 2026-10-18 | 10,211 | 2,000 |

> Hinweis: Der Rueckstau von 2,880,030 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,437 |
| 2026-09-23 | 13,076 |
| 2026-09-24 | 16,692 |
| 2026-09-25 | 20,962 |
| 2026-09-26 | 17,483 |
| 2026-09-27 | 15,062 |
| 2026-09-28 | 11,620 |
| 2026-09-29 | 9,370 |
| 2026-09-30 | 10,201 |
| 2026-10-01 | 16,623 |
| 2026-10-02 | 7,738 |
| 2026-10-03 | 7,346 |
| 2026-10-04 | 12,647 |
| 2026-10-05 | 17,579 |
| 2026-10-06 | 16,154 |
| 2026-10-07 | 15,098 |
| 2026-10-08 | 61,536 |
| 2026-10-09 | 223,747 |
| 2026-10-10 | 53,422 |
| 2026-10-11 | 16,071 |
| 2026-10-12 | 66,613 |
| 2026-10-13 | 1,586,811 |
| 2026-10-14 | 32,930 |
| 2026-10-15 | 41,372 |
| 2026-10-16 | 51,407 |
| 2026-10-17 | 24,367 |
| 2026-10-18 | 14,309 |
| 2026-10-19 | 22,452 |
| 2026-10-20 | 11,168 |
| 2026-10-21 | 11,142 |
| 2026-10-22 | 30,821 |
| 2026-10-23 | 50,494 |
| 2026-10-24 | 41,805 |
| 2026-10-25 | 21,679 |
| 2026-10-26 | 20,408 |
| 2026-10-27 | 20,766 |
| 2026-10-28 | 15,847 |
| 2026-10-29 | 9,729 |
| 2026-10-30 | 62,122 |
| 2026-10-31 | 88,299 |
| 2026-11-01 | 27,950 |
| 2026-11-02 | 28,926 |
| 2026-11-03 | 29,954 |
| 2026-11-04 | 29,762 |
| 2026-11-05 | 25,373 |
| 2026-11-06 | 36,803 |
| 2026-11-07 | 24,564 |
| 2026-11-08 | 26,227 |
| 2026-11-09 | 25,663 |
| 2026-11-10 | 32,854 |
| 2026-11-11 | 22,478 |
| 2026-11-12 | 20,580 |
| 2026-11-13 | 19,731 |
| 2026-11-14 | 23,065 |
| 2026-11-15 | 17,537 |
| 2026-11-16 | 18,050 |
| 2026-11-17 | 15,307 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 192788 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
