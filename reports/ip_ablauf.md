# Seen-DB Expiry Forecast

Lauf: 2026-09-16 06:34 CEST (Europe/Berlin)
Gesamt: 11,301,716 IPs in seen_db.json (8,380,142 aktiv/180-Tage-Pfad, 2,921,574 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 19,528 |
| 8-14 Tage | 101,517 |
| 15-30 Tage | 2,228,069 |
| 31-60 Tage | 837,487 |
| 61-90 Tage | 1,082,619 |
| 91-180 Tage | 4,110,922 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 548,059 |
| 0-3 Tage | 25,899 |
| 4-7 Tage | 26,388 |
| 8-14 Tage | 707,899 |
| 15-30 Tage | 1,613,329 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-16 | 6,231 |
| 2026-09-17 | 5,758 |
| 2026-09-18 | 8,776 |
| 2026-09-19 | 5,134 |
| 2026-09-20 | 5,055 |
| 2026-09-21 | 5,030 |
| 2026-09-22 | 11,170 |
| 2026-09-23 | 5,133 |
| 2026-09-24 | 11,417 |
| 2026-09-25 | 5,486 |
| 2026-09-26 | 624,108 |
| 2026-09-27 | 6,319 |
| 2026-09-28 | 779 |
| 2026-09-30 | 59,790 |
| 2026-10-01 | 7,687 |
| 2026-10-02 | 1,308,498 |
| 2026-10-03 | 2,985 |
| 2026-10-04 | 6,951 |
| 2026-10-05 | 2,919 |
| 2026-10-06 | 8,309 |
| 2026-10-07 | 8,046 |
| 2026-10-08 | 7,361 |
| 2026-10-09 | 152,271 |
| 2026-10-10 | 8,259 |
| 2026-10-11 | 23,301 |
| 2026-10-12 | 33,417 |
| 2026-10-13 | 9,129 |
| 2026-10-14 | 8,156 |
| 2026-10-15 | 9,001 |
| 2026-10-16 | 17,002 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **548,059** IPs. Brutto faellig in den naechsten 30 Tagen: **2,373,478**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,861,537**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-16 | 6,231 | 2,000 |
| 2026-09-17 | 5,758 | 2,000 |
| 2026-09-18 | 8,776 | 2,000 |
| 2026-09-19 | 5,134 | 2,000 |
| 2026-09-20 | 5,055 | 2,000 |
| 2026-09-21 | 5,030 | 2,000 |
| 2026-09-22 | 11,170 | 2,000 |
| 2026-09-23 | 5,133 | 2,000 |
| 2026-09-24 | 11,417 | 2,000 |
| 2026-09-25 | 5,486 | 2,000 |
| 2026-09-26 | 624,108 | 2,000 |
| 2026-09-27 | 6,319 | 2,000 |
| 2026-09-28 | 779 | 2,000 |
| 2026-09-30 | 59,790 | 2,000 |
| 2026-10-01 | 7,687 | 2,000 |
| 2026-10-02 | 1,308,498 | 2,000 |
| 2026-10-03 | 2,985 | 2,000 |
| 2026-10-04 | 6,951 | 2,000 |
| 2026-10-05 | 2,919 | 2,000 |
| 2026-10-06 | 8,309 | 2,000 |
| 2026-10-07 | 8,046 | 2,000 |
| 2026-10-08 | 7,361 | 2,000 |
| 2026-10-09 | 152,271 | 2,000 |
| 2026-10-10 | 8,259 | 2,000 |
| 2026-10-11 | 23,301 | 2,000 |
| 2026-10-12 | 33,417 | 2,000 |
| 2026-10-13 | 9,129 | 2,000 |
| 2026-10-14 | 8,156 | 2,000 |
| 2026-10-15 | 9,001 | 2,000 |
| 2026-10-16 | 17,002 | 2,000 |

> Hinweis: Der Rueckstau von 2,861,537 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,441 |
| 2026-09-23 | 13,087 |
| 2026-09-24 | 16,711 |
| 2026-09-25 | 20,987 |
| 2026-09-26 | 17,501 |
| 2026-09-27 | 15,086 |
| 2026-09-28 | 11,625 |
| 2026-09-29 | 9,387 |
| 2026-09-30 | 10,220 |
| 2026-10-01 | 16,637 |
| 2026-10-02 | 7,750 |
| 2026-10-03 | 7,354 |
| 2026-10-04 | 12,671 |
| 2026-10-05 | 17,599 |
| 2026-10-06 | 16,173 |
| 2026-10-07 | 15,111 |
| 2026-10-08 | 61,620 |
| 2026-10-09 | 223,991 |
| 2026-10-10 | 53,441 |
| 2026-10-11 | 16,079 |
| 2026-10-12 | 66,627 |
| 2026-10-13 | 1,587,274 |
| 2026-10-14 | 32,938 |
| 2026-10-15 | 41,386 |
| 2026-10-16 | 51,418 |
| 2026-10-17 | 24,384 |
| 2026-10-18 | 14,327 |
| 2026-10-19 | 22,492 |
| 2026-10-20 | 11,178 |
| 2026-10-21 | 11,154 |
| 2026-10-22 | 30,848 |
| 2026-10-23 | 50,519 |
| 2026-10-24 | 41,827 |
| 2026-10-25 | 21,689 |
| 2026-10-26 | 20,429 |
| 2026-10-27 | 20,782 |
| 2026-10-28 | 15,864 |
| 2026-10-29 | 9,747 |
| 2026-10-30 | 62,158 |
| 2026-10-31 | 88,324 |
| 2026-11-01 | 27,967 |
| 2026-11-02 | 28,951 |
| 2026-11-03 | 29,973 |
| 2026-11-04 | 29,781 |
| 2026-11-05 | 25,396 |
| 2026-11-06 | 36,828 |
| 2026-11-07 | 24,582 |
| 2026-11-08 | 26,250 |
| 2026-11-09 | 25,691 |
| 2026-11-10 | 32,883 |
| 2026-11-11 | 22,500 |
| 2026-11-12 | 20,588 |
| 2026-11-13 | 19,744 |
| 2026-11-14 | 23,085 |
| 2026-11-15 | 17,546 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 191770 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
