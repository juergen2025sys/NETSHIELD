# Seen-DB Expiry Forecast

Lauf: 2026-09-06 16:05 CEST (Europe/Berlin)
Gesamt: 11,124,841 IPs in seen_db.json (8,462,926 aktiv/180-Tage-Pfad, 2,661,915 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 662,632 |
| 8-14 Tage | 0 |
| 15-30 Tage | 200,660 |
| 31-60 Tage | 2,748,049 |
| 61-90 Tage | 1,034,322 |
| 91-180 Tage | 3,817,263 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 414,030 |
| 0-3 Tage | 66,832 |
| 4-7 Tage | 44,261 |
| 8-14 Tage | 59,923 |
| 15-30 Tage | 2,076,869 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-06 | 20,493 |
| 2026-09-07 | 16,242 |
| 2026-09-08 | 13,083 |
| 2026-09-09 | 17,014 |
| 2026-09-10 | 8,806 |
| 2026-09-11 | 11,376 |
| 2026-09-12 | 11,970 |
| 2026-09-13 | 12,109 |
| 2026-09-14 | 12,936 |
| 2026-09-15 | 15,708 |
| 2026-09-16 | 6,290 |
| 2026-09-17 | 5,833 |
| 2026-09-18 | 8,866 |
| 2026-09-19 | 5,189 |
| 2026-09-20 | 5,101 |
| 2026-09-21 | 5,088 |
| 2026-09-22 | 11,267 |
| 2026-09-23 | 5,196 |
| 2026-09-24 | 11,476 |
| 2026-09-25 | 5,554 |
| 2026-09-26 | 624,695 |
| 2026-09-27 | 6,393 |
| 2026-09-28 | 789 |
| 2026-09-30 | 60,088 |
| 2026-10-01 | 7,779 |
| 2026-10-02 | 1,310,921 |
| 2026-10-03 | 3,027 |
| 2026-10-04 | 7,048 |
| 2026-10-05 | 3,025 |
| 2026-10-06 | 8,600 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **414,030** IPs. Brutto faellig in den naechsten 30 Tagen: **2,241,962**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,595,992**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-06 | 20,493 | 2,000 |
| 2026-09-07 | 16,242 | 2,000 |
| 2026-09-08 | 13,083 | 2,000 |
| 2026-09-09 | 17,014 | 2,000 |
| 2026-09-10 | 8,806 | 2,000 |
| 2026-09-11 | 11,376 | 2,000 |
| 2026-09-12 | 11,970 | 2,000 |
| 2026-09-13 | 12,109 | 2,000 |
| 2026-09-14 | 12,936 | 2,000 |
| 2026-09-15 | 15,708 | 2,000 |
| 2026-09-16 | 6,290 | 2,000 |
| 2026-09-17 | 5,833 | 2,000 |
| 2026-09-18 | 8,866 | 2,000 |
| 2026-09-19 | 5,189 | 2,000 |
| 2026-09-20 | 5,101 | 2,000 |
| 2026-09-21 | 5,088 | 2,000 |
| 2026-09-22 | 11,267 | 2,000 |
| 2026-09-23 | 5,196 | 2,000 |
| 2026-09-24 | 11,476 | 2,000 |
| 2026-09-25 | 5,554 | 2,000 |
| 2026-09-26 | 624,695 | 2,000 |
| 2026-09-27 | 6,393 | 2,000 |
| 2026-09-28 | 789 | 2,000 |
| 2026-09-30 | 60,088 | 2,000 |
| 2026-10-01 | 7,779 | 2,000 |
| 2026-10-02 | 1,310,921 | 2,000 |
| 2026-10-03 | 3,027 | 2,000 |
| 2026-10-04 | 7,048 | 2,000 |
| 2026-10-05 | 3,025 | 2,000 |
| 2026-10-06 | 8,600 | 2,000 |

> Hinweis: Der Rueckstau von 2,595,992 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-08 | 662,632 |
| 2026-09-22 | 6,484 |
| 2026-09-23 | 13,181 |
| 2026-09-24 | 16,862 |
| 2026-09-25 | 21,130 |
| 2026-09-26 | 17,642 |
| 2026-09-27 | 15,229 |
| 2026-09-28 | 11,682 |
| 2026-09-29 | 9,439 |
| 2026-09-30 | 10,296 |
| 2026-10-01 | 16,728 |
| 2026-10-02 | 7,808 |
| 2026-10-03 | 7,406 |
| 2026-10-04 | 12,788 |
| 2026-10-05 | 17,706 |
| 2026-10-06 | 16,279 |
| 2026-10-07 | 15,202 |
| 2026-10-08 | 62,145 |
| 2026-10-09 | 226,230 |
| 2026-10-10 | 53,535 |
| 2026-10-11 | 16,120 |
| 2026-10-12 | 66,711 |
| 2026-10-13 | 1,591,679 |
| 2026-10-14 | 32,964 |
| 2026-10-15 | 41,453 |
| 2026-10-16 | 51,520 |
| 2026-10-17 | 24,496 |
| 2026-10-18 | 14,398 |
| 2026-10-19 | 22,728 |
| 2026-10-20 | 11,237 |
| 2026-10-21 | 11,215 |
| 2026-10-22 | 31,001 |
| 2026-10-23 | 50,634 |
| 2026-10-24 | 41,947 |
| 2026-10-25 | 21,794 |
| 2026-10-26 | 20,552 |
| 2026-10-27 | 20,904 |
| 2026-10-28 | 15,951 |
| 2026-10-29 | 9,830 |
| 2026-10-30 | 62,463 |
| 2026-10-31 | 88,486 |
| 2026-11-01 | 28,089 |
| 2026-11-02 | 29,098 |
| 2026-11-03 | 30,175 |
| 2026-11-04 | 29,968 |
| 2026-11-05 | 25,524 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 246 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
