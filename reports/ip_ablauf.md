# Seen-DB Expiry Forecast

Lauf: 2026-09-13 16:54 CEST (Europe/Berlin)
Gesamt: 11,095,437 IPs in seen_db.json (8,195,410 aktiv/180-Tage-Pfad, 2,900,027 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 0 |
| 8-14 Tage | 89,995 |
| 15-30 Tage | 2,135,645 |
| 31-60 Tage | 903,902 |
| 61-90 Tage | 1,069,973 |
| 91-180 Tage | 3,995,895 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 510,651 |
| 0-3 Tage | 46,742 |
| 4-7 Tage | 24,798 |
| 8-14 Tage | 668,960 |
| 15-30 Tage | 1,648,876 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-13 | 12,039 |
| 2026-09-14 | 12,849 |
| 2026-09-15 | 15,609 |
| 2026-09-16 | 6,245 |
| 2026-09-17 | 5,779 |
| 2026-09-18 | 8,800 |
| 2026-09-19 | 5,154 |
| 2026-09-20 | 5,065 |
| 2026-09-21 | 5,052 |
| 2026-09-22 | 11,192 |
| 2026-09-23 | 5,161 |
| 2026-09-24 | 11,436 |
| 2026-09-25 | 5,507 |
| 2026-09-26 | 624,270 |
| 2026-09-27 | 6,342 |
| 2026-09-28 | 783 |
| 2026-09-30 | 59,887 |
| 2026-10-01 | 7,719 |
| 2026-10-02 | 1,309,196 |
| 2026-10-03 | 2,997 |
| 2026-10-04 | 6,978 |
| 2026-10-05 | 2,933 |
| 2026-10-06 | 8,338 |
| 2026-10-07 | 8,094 |
| 2026-10-08 | 7,381 |
| 2026-10-09 | 152,468 |
| 2026-10-10 | 8,295 |
| 2026-10-11 | 23,386 |
| 2026-10-12 | 33,487 |
| 2026-10-13 | 9,428 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **510,651** IPs. Brutto faellig in den naechsten 30 Tagen: **2,381,870**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,832,521**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-13 | 12,039 | 2,000 |
| 2026-09-14 | 12,849 | 2,000 |
| 2026-09-15 | 15,609 | 2,000 |
| 2026-09-16 | 6,245 | 2,000 |
| 2026-09-17 | 5,779 | 2,000 |
| 2026-09-18 | 8,800 | 2,000 |
| 2026-09-19 | 5,154 | 2,000 |
| 2026-09-20 | 5,065 | 2,000 |
| 2026-09-21 | 5,052 | 2,000 |
| 2026-09-22 | 11,192 | 2,000 |
| 2026-09-23 | 5,161 | 2,000 |
| 2026-09-24 | 11,436 | 2,000 |
| 2026-09-25 | 5,507 | 2,000 |
| 2026-09-26 | 624,270 | 2,000 |
| 2026-09-27 | 6,342 | 2,000 |
| 2026-09-28 | 783 | 2,000 |
| 2026-09-30 | 59,887 | 2,000 |
| 2026-10-01 | 7,719 | 2,000 |
| 2026-10-02 | 1,309,196 | 2,000 |
| 2026-10-03 | 2,997 | 2,000 |
| 2026-10-04 | 6,978 | 2,000 |
| 2026-10-05 | 2,933 | 2,000 |
| 2026-10-06 | 8,338 | 2,000 |
| 2026-10-07 | 8,094 | 2,000 |
| 2026-10-08 | 7,381 | 2,000 |
| 2026-10-09 | 152,468 | 2,000 |
| 2026-10-10 | 8,295 | 2,000 |
| 2026-10-11 | 23,386 | 2,000 |
| 2026-10-12 | 33,487 | 2,000 |
| 2026-10-13 | 9,428 | 2,000 |

> Hinweis: Der Rueckstau von 2,832,521 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,452 |
| 2026-09-23 | 13,105 |
| 2026-09-24 | 16,750 |
| 2026-09-25 | 21,023 |
| 2026-09-26 | 17,533 |
| 2026-09-27 | 15,132 |
| 2026-09-28 | 11,635 |
| 2026-09-29 | 9,396 |
| 2026-09-30 | 10,246 |
| 2026-10-01 | 16,661 |
| 2026-10-02 | 7,765 |
| 2026-10-03 | 7,372 |
| 2026-10-04 | 12,709 |
| 2026-10-05 | 17,631 |
| 2026-10-06 | 16,208 |
| 2026-10-07 | 15,136 |
| 2026-10-08 | 61,799 |
| 2026-10-09 | 224,489 |
| 2026-10-10 | 53,469 |
| 2026-10-11 | 16,084 |
| 2026-10-12 | 66,648 |
| 2026-10-13 | 1,588,397 |
| 2026-10-14 | 32,945 |
| 2026-10-15 | 41,423 |
| 2026-10-16 | 51,455 |
| 2026-10-17 | 24,416 |
| 2026-10-18 | 14,341 |
| 2026-10-19 | 22,555 |
| 2026-10-20 | 11,190 |
| 2026-10-21 | 11,163 |
| 2026-10-22 | 30,887 |
| 2026-10-23 | 50,558 |
| 2026-10-24 | 41,858 |
| 2026-10-25 | 21,717 |
| 2026-10-26 | 20,469 |
| 2026-10-27 | 20,819 |
| 2026-10-28 | 15,882 |
| 2026-10-29 | 9,769 |
| 2026-10-30 | 62,237 |
| 2026-10-31 | 88,363 |
| 2026-11-01 | 28,008 |
| 2026-11-02 | 28,991 |
| 2026-11-03 | 30,036 |
| 2026-11-04 | 29,835 |
| 2026-11-05 | 25,433 |
| 2026-11-06 | 36,866 |
| 2026-11-07 | 24,612 |
| 2026-11-08 | 26,282 |
| 2026-11-09 | 25,729 |
| 2026-11-10 | 32,930 |
| 2026-11-11 | 22,526 |
| 2026-11-12 | 20,607 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 190868 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
