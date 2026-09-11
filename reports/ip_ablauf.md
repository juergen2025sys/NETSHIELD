# Seen-DB Expiry Forecast

Lauf: 2026-09-12 01:10 CEST (Europe/Berlin)
Gesamt: 11,009,397 IPs in seen_db.json (8,123,946 aktiv/180-Tage-Pfad, 2,885,451 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 0 |
| 8-14 Tage | 57,400 |
| 15-30 Tage | 513,928 |
| 31-60 Tage | 2,517,038 |
| 61-90 Tage | 1,060,968 |
| 91-180 Tage | 3,974,612 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 488,370 |
| 0-3 Tage | 48,159 |
| 4-7 Tage | 36,477 |
| 8-14 Tage | 48,627 |
| 15-30 Tage | 2,263,818 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-11 | 11,313 |
| 2026-09-12 | 11,917 |
| 2026-09-13 | 12,060 |
| 2026-09-14 | 12,869 |
| 2026-09-15 | 15,626 |
| 2026-09-16 | 6,252 |
| 2026-09-17 | 5,790 |
| 2026-09-18 | 8,809 |
| 2026-09-19 | 5,162 |
| 2026-09-20 | 5,073 |
| 2026-09-21 | 5,060 |
| 2026-09-22 | 11,209 |
| 2026-09-23 | 5,169 |
| 2026-09-24 | 11,442 |
| 2026-09-25 | 5,512 |
| 2026-09-26 | 624,356 |
| 2026-09-27 | 6,351 |
| 2026-09-28 | 784 |
| 2026-09-30 | 59,920 |
| 2026-10-01 | 7,725 |
| 2026-10-02 | 1,309,541 |
| 2026-10-03 | 3,000 |
| 2026-10-04 | 6,990 |
| 2026-10-05 | 2,939 |
| 2026-10-06 | 8,353 |
| 2026-10-07 | 8,111 |
| 2026-10-08 | 7,391 |
| 2026-10-09 | 152,577 |
| 2026-10-10 | 8,321 |
| 2026-10-11 | 23,505 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **488,370** IPs. Brutto faellig in den naechsten 30 Tagen: **2,363,127**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,791,497**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-11 | 11,313 | 2,000 |
| 2026-09-12 | 11,917 | 2,000 |
| 2026-09-13 | 12,060 | 2,000 |
| 2026-09-14 | 12,869 | 2,000 |
| 2026-09-15 | 15,626 | 2,000 |
| 2026-09-16 | 6,252 | 2,000 |
| 2026-09-17 | 5,790 | 2,000 |
| 2026-09-18 | 8,809 | 2,000 |
| 2026-09-19 | 5,162 | 2,000 |
| 2026-09-20 | 5,073 | 2,000 |
| 2026-09-21 | 5,060 | 2,000 |
| 2026-09-22 | 11,209 | 2,000 |
| 2026-09-23 | 5,169 | 2,000 |
| 2026-09-24 | 11,442 | 2,000 |
| 2026-09-25 | 5,512 | 2,000 |
| 2026-09-26 | 624,356 | 2,000 |
| 2026-09-27 | 6,351 | 2,000 |
| 2026-09-28 | 784 | 2,000 |
| 2026-09-30 | 59,920 | 2,000 |
| 2026-10-01 | 7,725 | 2,000 |
| 2026-10-02 | 1,309,541 | 2,000 |
| 2026-10-03 | 3,000 | 2,000 |
| 2026-10-04 | 6,990 | 2,000 |
| 2026-10-05 | 2,939 | 2,000 |
| 2026-10-06 | 8,353 | 2,000 |
| 2026-10-07 | 8,111 | 2,000 |
| 2026-10-08 | 7,391 | 2,000 |
| 2026-10-09 | 152,577 | 2,000 |
| 2026-10-10 | 8,321 | 2,000 |
| 2026-10-11 | 23,505 | 2,000 |

> Hinweis: Der Rueckstau von 2,791,497 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,459 |
| 2026-09-23 | 13,118 |
| 2026-09-24 | 16,775 |
| 2026-09-25 | 21,048 |
| 2026-09-26 | 17,562 |
| 2026-09-27 | 15,159 |
| 2026-09-28 | 11,642 |
| 2026-09-29 | 9,404 |
| 2026-09-30 | 10,258 |
| 2026-10-01 | 16,677 |
| 2026-10-02 | 7,774 |
| 2026-10-03 | 7,381 |
| 2026-10-04 | 12,727 |
| 2026-10-05 | 17,650 |
| 2026-10-06 | 16,225 |
| 2026-10-07 | 15,150 |
| 2026-10-08 | 61,870 |
| 2026-10-09 | 224,874 |
| 2026-10-10 | 53,483 |
| 2026-10-11 | 16,092 |
| 2026-10-12 | 66,661 |
| 2026-10-13 | 1,589,020 |
| 2026-10-14 | 32,949 |
| 2026-10-15 | 41,436 |
| 2026-10-16 | 51,473 |
| 2026-10-17 | 24,433 |
| 2026-10-18 | 14,356 |
| 2026-10-19 | 22,584 |
| 2026-10-20 | 11,199 |
| 2026-10-21 | 11,178 |
| 2026-10-22 | 30,912 |
| 2026-10-23 | 50,576 |
| 2026-10-24 | 41,878 |
| 2026-10-25 | 21,743 |
| 2026-10-26 | 20,489 |
| 2026-10-27 | 20,843 |
| 2026-10-28 | 15,905 |
| 2026-10-29 | 9,782 |
| 2026-10-30 | 62,281 |
| 2026-10-31 | 88,394 |
| 2026-11-01 | 28,023 |
| 2026-11-02 | 29,017 |
| 2026-11-03 | 30,072 |
| 2026-11-04 | 29,858 |
| 2026-11-05 | 25,449 |
| 2026-11-06 | 36,890 |
| 2026-11-07 | 24,625 |
| 2026-11-08 | 26,303 |
| 2026-11-09 | 25,753 |
| 2026-11-10 | 32,956 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 189770 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
