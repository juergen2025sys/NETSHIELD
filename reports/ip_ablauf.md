# Seen-DB Expiry Forecast

Lauf: 2026-09-06 00:46 CEST (Europe/Berlin)
Gesamt: 11,101,732 IPs in seen_db.json (8,444,954 aktiv/180-Tage-Pfad, 2,656,778 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 662,760 |
| 8-14 Tage | 0 |
| 15-30 Tage | 184,443 |
| 31-60 Tage | 2,739,185 |
| 61-90 Tage | 1,033,784 |
| 91-180 Tage | 3,824,782 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 344,798 |
| 0-3 Tage | 119,120 |
| 4-7 Tage | 49,190 |
| 8-14 Tage | 66,967 |
| 15-30 Tage | 2,076,703 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-05 | 69,281 |
| 2026-09-06 | 20,499 |
| 2026-09-07 | 16,253 |
| 2026-09-08 | 13,087 |
| 2026-09-09 | 17,021 |
| 2026-09-10 | 8,811 |
| 2026-09-11 | 11,384 |
| 2026-09-12 | 11,974 |
| 2026-09-13 | 12,110 |
| 2026-09-14 | 12,945 |
| 2026-09-15 | 15,716 |
| 2026-09-16 | 6,293 |
| 2026-09-17 | 5,840 |
| 2026-09-18 | 8,869 |
| 2026-09-19 | 5,194 |
| 2026-09-20 | 5,103 |
| 2026-09-21 | 5,093 |
| 2026-09-22 | 11,269 |
| 2026-09-23 | 5,200 |
| 2026-09-24 | 11,481 |
| 2026-09-25 | 5,561 |
| 2026-09-26 | 624,726 |
| 2026-09-27 | 6,401 |
| 2026-09-28 | 790 |
| 2026-09-30 | 60,110 |
| 2026-10-01 | 7,783 |
| 2026-10-02 | 1,311,068 |
| 2026-10-03 | 3,033 |
| 2026-10-04 | 7,064 |
| 2026-10-05 | 3,075 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **344,798** IPs. Brutto faellig in den naechsten 30 Tagen: **2,303,034**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,587,832**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-05 | 69,281 | 2,000 |
| 2026-09-06 | 20,499 | 2,000 |
| 2026-09-07 | 16,253 | 2,000 |
| 2026-09-08 | 13,087 | 2,000 |
| 2026-09-09 | 17,021 | 2,000 |
| 2026-09-10 | 8,811 | 2,000 |
| 2026-09-11 | 11,384 | 2,000 |
| 2026-09-12 | 11,974 | 2,000 |
| 2026-09-13 | 12,110 | 2,000 |
| 2026-09-14 | 12,945 | 2,000 |
| 2026-09-15 | 15,716 | 2,000 |
| 2026-09-16 | 6,293 | 2,000 |
| 2026-09-17 | 5,840 | 2,000 |
| 2026-09-18 | 8,869 | 2,000 |
| 2026-09-19 | 5,194 | 2,000 |
| 2026-09-20 | 5,103 | 2,000 |
| 2026-09-21 | 5,093 | 2,000 |
| 2026-09-22 | 11,269 | 2,000 |
| 2026-09-23 | 5,200 | 2,000 |
| 2026-09-24 | 11,481 | 2,000 |
| 2026-09-25 | 5,561 | 2,000 |
| 2026-09-26 | 624,726 | 2,000 |
| 2026-09-27 | 6,401 | 2,000 |
| 2026-09-28 | 790 | 2,000 |
| 2026-09-30 | 60,110 | 2,000 |
| 2026-10-01 | 7,783 | 2,000 |
| 2026-10-02 | 1,311,068 | 2,000 |
| 2026-10-03 | 3,033 | 2,000 |
| 2026-10-04 | 7,064 | 2,000 |
| 2026-10-05 | 3,075 | 2,000 |

> Hinweis: Der Rueckstau von 2,587,832 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-08 | 662,760 |
| 2026-09-22 | 6,486 |
| 2026-09-23 | 13,184 |
| 2026-09-24 | 16,866 |
| 2026-09-25 | 21,140 |
| 2026-09-26 | 17,648 |
| 2026-09-27 | 15,234 |
| 2026-09-28 | 11,683 |
| 2026-09-29 | 9,444 |
| 2026-09-30 | 10,300 |
| 2026-10-01 | 16,734 |
| 2026-10-02 | 7,812 |
| 2026-10-03 | 7,408 |
| 2026-10-04 | 12,792 |
| 2026-10-05 | 17,712 |
| 2026-10-06 | 16,285 |
| 2026-10-07 | 15,205 |
| 2026-10-08 | 62,175 |
| 2026-10-09 | 226,294 |
| 2026-10-10 | 53,544 |
| 2026-10-11 | 16,121 |
| 2026-10-12 | 66,712 |
| 2026-10-13 | 1,591,804 |
| 2026-10-14 | 32,966 |
| 2026-10-15 | 41,458 |
| 2026-10-16 | 51,528 |
| 2026-10-17 | 24,499 |
| 2026-10-18 | 14,404 |
| 2026-10-19 | 22,736 |
| 2026-10-20 | 11,237 |
| 2026-10-21 | 11,221 |
| 2026-10-22 | 31,010 |
| 2026-10-23 | 50,640 |
| 2026-10-24 | 41,953 |
| 2026-10-25 | 21,804 |
| 2026-10-26 | 20,556 |
| 2026-10-27 | 20,914 |
| 2026-10-28 | 15,958 |
| 2026-10-29 | 9,832 |
| 2026-10-30 | 62,476 |
| 2026-10-31 | 88,494 |
| 2026-11-01 | 28,092 |
| 2026-11-02 | 29,109 |
| 2026-11-03 | 30,183 |
| 2026-11-04 | 29,975 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 221 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
