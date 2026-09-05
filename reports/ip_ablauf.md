# Seen-DB Expiry Forecast

Lauf: 2026-09-05 22:40 CEST (Europe/Berlin)
Gesamt: 11,053,966 IPs in seen_db.json (8,396,868 aktiv/180-Tage-Pfad, 2,657,098 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 662,855 |
| 8-14 Tage | 0 |
| 15-30 Tage | 184,481 |
| 31-60 Tage | 2,739,556 |
| 61-90 Tage | 1,033,908 |
| 91-180 Tage | 3,776,068 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 344,754 |
| 0-3 Tage | 119,132 |
| 4-7 Tage | 49,196 |
| 8-14 Tage | 66,978 |
| 15-30 Tage | 2,077,038 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-05 | 69,285 |
| 2026-09-06 | 20,502 |
| 2026-09-07 | 16,256 |
| 2026-09-08 | 13,089 |
| 2026-09-09 | 17,022 |
| 2026-09-10 | 8,811 |
| 2026-09-11 | 11,389 |
| 2026-09-12 | 11,974 |
| 2026-09-13 | 12,114 |
| 2026-09-14 | 12,948 |
| 2026-09-15 | 15,718 |
| 2026-09-16 | 6,293 |
| 2026-09-17 | 5,840 |
| 2026-09-18 | 8,871 |
| 2026-09-19 | 5,194 |
| 2026-09-20 | 5,106 |
| 2026-09-21 | 5,095 |
| 2026-09-22 | 11,274 |
| 2026-09-23 | 5,201 |
| 2026-09-24 | 11,484 |
| 2026-09-25 | 5,564 |
| 2026-09-26 | 624,732 |
| 2026-09-27 | 6,405 |
| 2026-09-28 | 790 |
| 2026-09-30 | 60,114 |
| 2026-10-01 | 7,783 |
| 2026-10-02 | 1,311,089 |
| 2026-10-03 | 3,033 |
| 2026-10-04 | 7,066 |
| 2026-10-05 | 3,080 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **344,754** IPs. Brutto faellig in den naechsten 30 Tagen: **2,303,122**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,587,876**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-05 | 69,285 | 2,000 |
| 2026-09-06 | 20,502 | 2,000 |
| 2026-09-07 | 16,256 | 2,000 |
| 2026-09-08 | 13,089 | 2,000 |
| 2026-09-09 | 17,022 | 2,000 |
| 2026-09-10 | 8,811 | 2,000 |
| 2026-09-11 | 11,389 | 2,000 |
| 2026-09-12 | 11,974 | 2,000 |
| 2026-09-13 | 12,114 | 2,000 |
| 2026-09-14 | 12,948 | 2,000 |
| 2026-09-15 | 15,718 | 2,000 |
| 2026-09-16 | 6,293 | 2,000 |
| 2026-09-17 | 5,840 | 2,000 |
| 2026-09-18 | 8,871 | 2,000 |
| 2026-09-19 | 5,194 | 2,000 |
| 2026-09-20 | 5,106 | 2,000 |
| 2026-09-21 | 5,095 | 2,000 |
| 2026-09-22 | 11,274 | 2,000 |
| 2026-09-23 | 5,201 | 2,000 |
| 2026-09-24 | 11,484 | 2,000 |
| 2026-09-25 | 5,564 | 2,000 |
| 2026-09-26 | 624,732 | 2,000 |
| 2026-09-27 | 6,405 | 2,000 |
| 2026-09-28 | 790 | 2,000 |
| 2026-09-30 | 60,114 | 2,000 |
| 2026-10-01 | 7,783 | 2,000 |
| 2026-10-02 | 1,311,089 | 2,000 |
| 2026-10-03 | 3,033 | 2,000 |
| 2026-10-04 | 7,066 | 2,000 |
| 2026-10-05 | 3,080 | 2,000 |

> Hinweis: Der Rueckstau von 2,587,876 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-08 | 662,855 |
| 2026-09-22 | 6,486 |
| 2026-09-23 | 13,186 |
| 2026-09-24 | 16,870 |
| 2026-09-25 | 21,149 |
| 2026-09-26 | 17,655 |
| 2026-09-27 | 15,235 |
| 2026-09-28 | 11,683 |
| 2026-09-29 | 9,446 |
| 2026-09-30 | 10,302 |
| 2026-10-01 | 16,739 |
| 2026-10-02 | 7,813 |
| 2026-10-03 | 7,408 |
| 2026-10-04 | 12,794 |
| 2026-10-05 | 17,715 |
| 2026-10-06 | 16,287 |
| 2026-10-07 | 15,205 |
| 2026-10-08 | 62,182 |
| 2026-10-09 | 226,378 |
| 2026-10-10 | 53,545 |
| 2026-10-11 | 16,121 |
| 2026-10-12 | 66,713 |
| 2026-10-13 | 1,592,019 |
| 2026-10-14 | 32,967 |
| 2026-10-15 | 41,459 |
| 2026-10-16 | 51,532 |
| 2026-10-17 | 24,500 |
| 2026-10-18 | 14,405 |
| 2026-10-19 | 22,740 |
| 2026-10-20 | 11,239 |
| 2026-10-21 | 11,222 |
| 2026-10-22 | 31,012 |
| 2026-10-23 | 50,645 |
| 2026-10-24 | 41,956 |
| 2026-10-25 | 21,809 |
| 2026-10-26 | 20,559 |
| 2026-10-27 | 20,914 |
| 2026-10-28 | 15,960 |
| 2026-10-29 | 9,833 |
| 2026-10-30 | 62,481 |
| 2026-10-31 | 88,495 |
| 2026-11-01 | 28,093 |
| 2026-11-02 | 29,109 |
| 2026-11-03 | 30,199 |
| 2026-11-04 | 29,977 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 221 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
