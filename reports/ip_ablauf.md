# Seen-DB Expiry Forecast

Lauf: 2026-09-08 21:34 CEST (Europe/Berlin)
Gesamt: 10,777,942 IPs in seen_db.json (7,957,211 aktiv/180-Tage-Pfad, 2,820,731 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 0 |
| 8-14 Tage | 6,471 |
| 15-30 Tage | 271,102 |
| 31-60 Tage | 2,730,248 |
| 61-90 Tage | 1,026,145 |
| 91-180 Tage | 3,923,245 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 450,621 |
| 0-3 Tage | 50,180 |
| 4-7 Tage | 52,614 |
| 8-14 Tage | 47,516 |
| 15-30 Tage | 2,219,800 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-08 | 13,060 |
| 2026-09-09 | 16,992 |
| 2026-09-10 | 8,773 |
| 2026-09-11 | 11,355 |
| 2026-09-12 | 11,945 |
| 2026-09-13 | 12,091 |
| 2026-09-14 | 12,909 |
| 2026-09-15 | 15,669 |
| 2026-09-16 | 6,274 |
| 2026-09-17 | 5,816 |
| 2026-09-18 | 8,841 |
| 2026-09-19 | 5,177 |
| 2026-09-20 | 5,093 |
| 2026-09-21 | 5,075 |
| 2026-09-22 | 11,240 |
| 2026-09-23 | 5,189 |
| 2026-09-24 | 11,462 |
| 2026-09-25 | 5,532 |
| 2026-09-26 | 624,566 |
| 2026-09-27 | 6,375 |
| 2026-09-28 | 786 |
| 2026-09-30 | 60,029 |
| 2026-10-01 | 7,753 |
| 2026-10-02 | 1,310,364 |
| 2026-10-03 | 3,014 |
| 2026-10-04 | 7,017 |
| 2026-10-05 | 2,976 |
| 2026-10-06 | 8,485 |
| 2026-10-07 | 8,197 |
| 2026-10-08 | 7,510 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **450,621** IPs. Brutto faellig in den naechsten 30 Tagen: **2,219,565**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,610,186**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-08 | 13,060 | 2,000 |
| 2026-09-09 | 16,992 | 2,000 |
| 2026-09-10 | 8,773 | 2,000 |
| 2026-09-11 | 11,355 | 2,000 |
| 2026-09-12 | 11,945 | 2,000 |
| 2026-09-13 | 12,091 | 2,000 |
| 2026-09-14 | 12,909 | 2,000 |
| 2026-09-15 | 15,669 | 2,000 |
| 2026-09-16 | 6,274 | 2,000 |
| 2026-09-17 | 5,816 | 2,000 |
| 2026-09-18 | 8,841 | 2,000 |
| 2026-09-19 | 5,177 | 2,000 |
| 2026-09-20 | 5,093 | 2,000 |
| 2026-09-21 | 5,075 | 2,000 |
| 2026-09-22 | 11,240 | 2,000 |
| 2026-09-23 | 5,189 | 2,000 |
| 2026-09-24 | 11,462 | 2,000 |
| 2026-09-25 | 5,532 | 2,000 |
| 2026-09-26 | 624,566 | 2,000 |
| 2026-09-27 | 6,375 | 2,000 |
| 2026-09-28 | 786 | 2,000 |
| 2026-09-30 | 60,029 | 2,000 |
| 2026-10-01 | 7,753 | 2,000 |
| 2026-10-02 | 1,310,364 | 2,000 |
| 2026-10-03 | 3,014 | 2,000 |
| 2026-10-04 | 7,017 | 2,000 |
| 2026-10-05 | 2,976 | 2,000 |
| 2026-10-06 | 8,485 | 2,000 |
| 2026-10-07 | 8,197 | 2,000 |
| 2026-10-08 | 7,510 | 2,000 |

> Hinweis: Der Rueckstau von 2,610,186 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,471 |
| 2026-09-23 | 13,157 |
| 2026-09-24 | 16,829 |
| 2026-09-25 | 21,107 |
| 2026-09-26 | 17,606 |
| 2026-09-27 | 15,205 |
| 2026-09-28 | 11,670 |
| 2026-09-29 | 9,424 |
| 2026-09-30 | 10,283 |
| 2026-10-01 | 16,707 |
| 2026-10-02 | 7,797 |
| 2026-10-03 | 7,392 |
| 2026-10-04 | 12,772 |
| 2026-10-05 | 17,685 |
| 2026-10-06 | 16,254 |
| 2026-10-07 | 15,176 |
| 2026-10-08 | 62,038 |
| 2026-10-09 | 225,826 |
| 2026-10-10 | 53,519 |
| 2026-10-11 | 16,109 |
| 2026-10-12 | 66,696 |
| 2026-10-13 | 1,590,719 |
| 2026-10-14 | 32,961 |
| 2026-10-15 | 41,445 |
| 2026-10-16 | 51,501 |
| 2026-10-17 | 24,465 |
| 2026-10-18 | 14,381 |
| 2026-10-19 | 22,668 |
| 2026-10-20 | 11,216 |
| 2026-10-21 | 11,196 |
| 2026-10-22 | 30,968 |
| 2026-10-23 | 50,604 |
| 2026-10-24 | 41,915 |
| 2026-10-25 | 21,763 |
| 2026-10-26 | 20,525 |
| 2026-10-27 | 20,884 |
| 2026-10-28 | 15,939 |
| 2026-10-29 | 9,810 |
| 2026-10-30 | 62,396 |
| 2026-10-31 | 88,444 |
| 2026-11-01 | 28,058 |
| 2026-11-02 | 29,064 |
| 2026-11-03 | 30,138 |
| 2026-11-04 | 29,927 |
| 2026-11-05 | 25,496 |
| 2026-11-06 | 36,947 |
| 2026-11-07 | 24,668 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 142618 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
