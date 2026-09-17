# Seen-DB Expiry Forecast

Lauf: 2026-09-17 13:33 CEST (Europe/Berlin)
Gesamt: 11,382,961 IPs in seen_db.json (8,442,978 aktiv/180-Tage-Pfad, 2,939,983 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 36,219 |
| 8-14 Tage | 101,362 |
| 15-30 Tage | 2,235,187 |
| 31-60 Tage | 830,782 |
| 61-90 Tage | 1,081,021 |
| 91-180 Tage | 4,158,407 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 555,998 |
| 0-3 Tage | 24,694 |
| 4-7 Tage | 32,732 |
| 8-14 Tage | 704,058 |
| 15-30 Tage | 1,622,501 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-17 | 5,752 |
| 2026-09-18 | 8,765 |
| 2026-09-19 | 5,131 |
| 2026-09-20 | 5,046 |
| 2026-09-21 | 5,026 |
| 2026-09-22 | 11,163 |
| 2026-09-23 | 5,129 |
| 2026-09-24 | 11,414 |
| 2026-09-25 | 5,480 |
| 2026-09-26 | 624,051 |
| 2026-09-27 | 6,303 |
| 2026-09-28 | 778 |
| 2026-09-30 | 59,767 |
| 2026-10-01 | 7,679 |
| 2026-10-02 | 1,308,210 |
| 2026-10-03 | 2,984 |
| 2026-10-04 | 6,938 |
| 2026-10-05 | 2,917 |
| 2026-10-06 | 8,304 |
| 2026-10-07 | 8,031 |
| 2026-10-08 | 7,356 |
| 2026-10-09 | 152,171 |
| 2026-10-10 | 8,240 |
| 2026-10-11 | 23,256 |
| 2026-10-12 | 33,386 |
| 2026-10-13 | 9,098 |
| 2026-10-14 | 8,134 |
| 2026-10-15 | 8,939 |
| 2026-10-16 | 16,381 |
| 2026-10-17 | 11,249 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **555,998** IPs. Brutto faellig in den naechsten 30 Tagen: **2,377,078**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,873,076**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-17 | 5,752 | 2,000 |
| 2026-09-18 | 8,765 | 2,000 |
| 2026-09-19 | 5,131 | 2,000 |
| 2026-09-20 | 5,046 | 2,000 |
| 2026-09-21 | 5,026 | 2,000 |
| 2026-09-22 | 11,163 | 2,000 |
| 2026-09-23 | 5,129 | 2,000 |
| 2026-09-24 | 11,414 | 2,000 |
| 2026-09-25 | 5,480 | 2,000 |
| 2026-09-26 | 624,051 | 2,000 |
| 2026-09-27 | 6,303 | 2,000 |
| 2026-09-28 | 778 | 2,000 |
| 2026-09-30 | 59,767 | 2,000 |
| 2026-10-01 | 7,679 | 2,000 |
| 2026-10-02 | 1,308,210 | 2,000 |
| 2026-10-03 | 2,984 | 2,000 |
| 2026-10-04 | 6,938 | 2,000 |
| 2026-10-05 | 2,917 | 2,000 |
| 2026-10-06 | 8,304 | 2,000 |
| 2026-10-07 | 8,031 | 2,000 |
| 2026-10-08 | 7,356 | 2,000 |
| 2026-10-09 | 152,171 | 2,000 |
| 2026-10-10 | 8,240 | 2,000 |
| 2026-10-11 | 23,256 | 2,000 |
| 2026-10-12 | 33,386 | 2,000 |
| 2026-10-13 | 9,098 | 2,000 |
| 2026-10-14 | 8,134 | 2,000 |
| 2026-10-15 | 8,939 | 2,000 |
| 2026-10-16 | 16,381 | 2,000 |
| 2026-10-17 | 11,249 | 2,000 |

> Hinweis: Der Rueckstau von 2,873,076 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,438 |
| 2026-09-23 | 13,082 |
| 2026-09-24 | 16,699 |
| 2026-09-25 | 20,971 |
| 2026-09-26 | 17,490 |
| 2026-09-27 | 15,070 |
| 2026-09-28 | 11,621 |
| 2026-09-29 | 9,375 |
| 2026-09-30 | 10,207 |
| 2026-10-01 | 16,628 |
| 2026-10-02 | 7,744 |
| 2026-10-03 | 7,350 |
| 2026-10-04 | 12,652 |
| 2026-10-05 | 17,583 |
| 2026-10-06 | 16,164 |
| 2026-10-07 | 15,101 |
| 2026-10-08 | 61,575 |
| 2026-10-09 | 223,840 |
| 2026-10-10 | 53,427 |
| 2026-10-11 | 16,074 |
| 2026-10-12 | 66,619 |
| 2026-10-13 | 1,586,961 |
| 2026-10-14 | 32,935 |
| 2026-10-15 | 41,377 |
| 2026-10-16 | 51,412 |
| 2026-10-17 | 24,373 |
| 2026-10-18 | 14,314 |
| 2026-10-19 | 22,472 |
| 2026-10-20 | 11,173 |
| 2026-10-21 | 11,146 |
| 2026-10-22 | 30,830 |
| 2026-10-23 | 50,506 |
| 2026-10-24 | 41,817 |
| 2026-10-25 | 21,680 |
| 2026-10-26 | 20,416 |
| 2026-10-27 | 20,773 |
| 2026-10-28 | 15,851 |
| 2026-10-29 | 9,736 |
| 2026-10-30 | 62,132 |
| 2026-10-31 | 88,307 |
| 2026-11-01 | 27,958 |
| 2026-11-02 | 28,932 |
| 2026-11-03 | 29,959 |
| 2026-11-04 | 29,766 |
| 2026-11-05 | 25,382 |
| 2026-11-06 | 36,812 |
| 2026-11-07 | 24,568 |
| 2026-11-08 | 26,240 |
| 2026-11-09 | 25,671 |
| 2026-11-10 | 32,866 |
| 2026-11-11 | 22,486 |
| 2026-11-12 | 20,584 |
| 2026-11-13 | 19,738 |
| 2026-11-14 | 23,071 |
| 2026-11-15 | 17,540 |
| 2026-11-16 | 18,056 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 192802 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
