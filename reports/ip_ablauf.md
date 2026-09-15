# Seen-DB Expiry Forecast

Lauf: 2026-09-15 23:11 CEST (Europe/Berlin)
Gesamt: 11,278,810 IPs in seen_db.json (8,356,076 aktiv/180-Tage-Pfad, 2,922,734 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 6,441 |
| 8-14 Tage | 104,412 |
| 15-30 Tage | 2,187,095 |
| 31-60 Tage | 871,492 |
| 61-90 Tage | 1,073,746 |
| 91-180 Tage | 4,112,890 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 534,567 |
| 0-3 Tage | 36,339 |
| 4-7 Tage | 26,394 |
| 8-14 Tage | 653,268 |
| 15-30 Tage | 1,672,166 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-15 | 15,569 |
| 2026-09-16 | 6,235 |
| 2026-09-17 | 5,759 |
| 2026-09-18 | 8,776 |
| 2026-09-19 | 5,135 |
| 2026-09-20 | 5,056 |
| 2026-09-21 | 5,031 |
| 2026-09-22 | 11,172 |
| 2026-09-23 | 5,135 |
| 2026-09-24 | 11,418 |
| 2026-09-25 | 5,488 |
| 2026-09-26 | 624,129 |
| 2026-09-27 | 6,319 |
| 2026-09-28 | 779 |
| 2026-09-30 | 59,800 |
| 2026-10-01 | 7,690 |
| 2026-10-02 | 1,308,594 |
| 2026-10-03 | 2,985 |
| 2026-10-04 | 6,955 |
| 2026-10-05 | 2,919 |
| 2026-10-06 | 8,311 |
| 2026-10-07 | 8,052 |
| 2026-10-08 | 7,364 |
| 2026-10-09 | 152,297 |
| 2026-10-10 | 8,263 |
| 2026-10-11 | 23,307 |
| 2026-10-12 | 33,425 |
| 2026-10-13 | 9,136 |
| 2026-10-14 | 8,166 |
| 2026-10-15 | 9,313 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **534,567** IPs. Brutto faellig in den naechsten 30 Tagen: **2,372,578**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,847,145**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-15 | 15,569 | 2,000 |
| 2026-09-16 | 6,235 | 2,000 |
| 2026-09-17 | 5,759 | 2,000 |
| 2026-09-18 | 8,776 | 2,000 |
| 2026-09-19 | 5,135 | 2,000 |
| 2026-09-20 | 5,056 | 2,000 |
| 2026-09-21 | 5,031 | 2,000 |
| 2026-09-22 | 11,172 | 2,000 |
| 2026-09-23 | 5,135 | 2,000 |
| 2026-09-24 | 11,418 | 2,000 |
| 2026-09-25 | 5,488 | 2,000 |
| 2026-09-26 | 624,129 | 2,000 |
| 2026-09-27 | 6,319 | 2,000 |
| 2026-09-28 | 779 | 2,000 |
| 2026-09-30 | 59,800 | 2,000 |
| 2026-10-01 | 7,690 | 2,000 |
| 2026-10-02 | 1,308,594 | 2,000 |
| 2026-10-03 | 2,985 | 2,000 |
| 2026-10-04 | 6,955 | 2,000 |
| 2026-10-05 | 2,919 | 2,000 |
| 2026-10-06 | 8,311 | 2,000 |
| 2026-10-07 | 8,052 | 2,000 |
| 2026-10-08 | 7,364 | 2,000 |
| 2026-10-09 | 152,297 | 2,000 |
| 2026-10-10 | 8,263 | 2,000 |
| 2026-10-11 | 23,307 | 2,000 |
| 2026-10-12 | 33,425 | 2,000 |
| 2026-10-13 | 9,136 | 2,000 |
| 2026-10-14 | 8,166 | 2,000 |
| 2026-10-15 | 9,313 | 2,000 |

> Hinweis: Der Rueckstau von 2,847,145 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,441 |
| 2026-09-23 | 13,089 |
| 2026-09-24 | 16,724 |
| 2026-09-25 | 20,992 |
| 2026-09-26 | 17,505 |
| 2026-09-27 | 15,090 |
| 2026-09-28 | 11,625 |
| 2026-09-29 | 9,387 |
| 2026-09-30 | 10,223 |
| 2026-10-01 | 16,639 |
| 2026-10-02 | 7,751 |
| 2026-10-03 | 7,354 |
| 2026-10-04 | 12,675 |
| 2026-10-05 | 17,601 |
| 2026-10-06 | 16,177 |
| 2026-10-07 | 15,112 |
| 2026-10-08 | 61,663 |
| 2026-10-09 | 224,032 |
| 2026-10-10 | 53,444 |
| 2026-10-11 | 16,080 |
| 2026-10-12 | 66,631 |
| 2026-10-13 | 1,587,386 |
| 2026-10-14 | 32,938 |
| 2026-10-15 | 41,389 |
| 2026-10-16 | 51,422 |
| 2026-10-17 | 24,389 |
| 2026-10-18 | 14,327 |
| 2026-10-19 | 22,503 |
| 2026-10-20 | 11,182 |
| 2026-10-21 | 11,157 |
| 2026-10-22 | 30,852 |
| 2026-10-23 | 50,519 |
| 2026-10-24 | 41,830 |
| 2026-10-25 | 21,695 |
| 2026-10-26 | 20,434 |
| 2026-10-27 | 20,787 |
| 2026-10-28 | 15,868 |
| 2026-10-29 | 9,752 |
| 2026-10-30 | 62,171 |
| 2026-10-31 | 88,327 |
| 2026-11-01 | 27,973 |
| 2026-11-02 | 28,955 |
| 2026-11-03 | 29,977 |
| 2026-11-04 | 29,784 |
| 2026-11-05 | 25,397 |
| 2026-11-06 | 36,834 |
| 2026-11-07 | 24,587 |
| 2026-11-08 | 26,255 |
| 2026-11-09 | 25,699 |
| 2026-11-10 | 32,890 |
| 2026-11-11 | 22,502 |
| 2026-11-12 | 20,590 |
| 2026-11-13 | 19,745 |
| 2026-11-14 | 23,089 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 191742 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
